//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// Native primary fixtures deliberately start after password/TOTP completion.
// The public service must authenticate these actual bearer/CSRF credentials
// against the current owners; this is not proof of the login ceremony itself.
func TestImpersonationServiceTwoAdminApprovalPostgres(t *testing.T) {
	for _, scenario := range []string{"approve-and-recover", "requester-authority-withdrawn"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			service, cfg, requester, approver := newM24ServiceFixture(t, ctx, pool)
			scope := m24Must(impersonation.NewScope([]string{"profile.read", "address.read"}))
			reason := m24Must(impersonation.NewReason("private support case request"))
			requestID := m24Must(identity.NewCommandID())
			requestInput := RequestInput{Authentication: requester, CommandID: requestID, Target: "target-user", Scope: scope, Reason: reason, Duration: 10 * time.Minute, Network: "192.0.2.11"}
			request := m24Must(service.PrepareRequest(ctx, requestInput))
			requestBinding := m24Must(request.Binding())
			cfg.Authorization.(*m24Authorization).recovery[string(requestID)] = requestBinding
			pending := m24Must(service.Execute(ctx, request))
			if pending.Outcome != identity.CommitOutcomeCommitted || pending.Binding != requestBinding || pending.Feature == nil || pending.Feature.BeforeVersion != 0 || pending.Feature.AfterVersion != 1 {
				t.Fatal("request did not return its original committed binding", pending.Outcome)
			}
			assertM24Grant(t, ctx, pool, requestID, "pending_approval", 1, 0)
			assertM24CommandEffects(t, ctx, pool, requestID, 1)
			if replay := m24Must(service.Execute(ctx, request)); !reflect.DeepEqual(replay, pending) {
				t.Fatal("request replay did not return its exact original result")
			}

			approvalInput := ApproveInput{Authentication: approver, CommandID: m24Must(identity.NewCommandID()), GrantID: impersonation.GrantID(requestID), ExpectedVersion: 1, Reason: m24Must(impersonation.NewReason("private distinct administrator approval")), Network: "192.0.2.12"}
			self := approvalInput
			self.Authentication = requester
			if _, err := service.PrepareApproval(ctx, self); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("requesting administrator approved its own request", err)
			}
			wrongCSRF := approvalInput
			wrongCSRF.Authentication.CSRF = requester.CSRF
			if _, err := service.PrepareApproval(ctx, wrongCSRF); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("approver authenticated with another administrator's CSRF", err)
			}
			wrongRequestCSRF := requestInput
			wrongRequestCSRF.CommandID = m24Must(identity.NewCommandID())
			wrongRequestCSRF.Authentication.CSRF = approver.CSRF
			if _, err := service.PrepareRequest(ctx, wrongRequestCSRF); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("request authenticated with another administrator's CSRF", err)
			}
			assertM24Grant(t, ctx, pool, requestID, "pending_approval", 1, 0)
			assertM24CommandEffects(t, ctx, pool, approvalInput.CommandID, 0)
			assertM24CommandEffects(t, ctx, pool, wrongRequestCSRF.CommandID, 0)

			approval := m24Must(service.PrepareApproval(ctx, approvalInput))
			approvalBinding := m24Must(approval.Binding())
			cfg.Authorization.(*m24Authorization).recovery[string(approvalInput.CommandID)] = approvalBinding
			if scenario == "requester-authority-withdrawn" {
				m24Exec(t, ctx, pool, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id='m24-tenant' AND subject_id='request-admin'`)
				result, err := service.Execute(ctx, approval)
				if !errors.Is(err, identity.ForbiddenError{}) || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("approval did not settle as denied after requester authority changed", result.Outcome, err)
				}
				assertM24Grant(t, ctx, pool, requestID, "pending_approval", 1, 0)
				assertM24DeniedEffects(t, ctx, pool, approvalInput.CommandID)
				replayed, err := service.Execute(ctx, approval)
				if err != nil || !reflect.DeepEqual(replayed, result) {
					t.Fatal("denied approval did not retain its original result", replayed.Outcome, err)
				}
				restarted := m24Must(NewService(pool, cfg))
				recovered, err := restarted.Recover(ctx, approver, approvalBinding)
				if !errors.Is(err, identity.ForbiddenError{}) || !reflect.DeepEqual(recovered, result) {
					t.Fatal("recovery lost the original denial classification", recovered.Outcome, err)
				}
				assertM24DeniedEffects(t, ctx, pool, approvalInput.CommandID)
				assertM24NoSessionIssuance(t, ctx, pool)
				return
			}

			approved := m24Must(service.Execute(ctx, approval))
			if approved.Outcome != identity.CommitOutcomeCommitted || approved.Binding != approvalBinding || approved.Feature == nil || approved.Feature.BeforeVersion != 1 || approved.Feature.AfterVersion != 2 {
				t.Fatal("distinct approval did not return its original committed binding", approved.Outcome)
			}
			assertM24Grant(t, ctx, pool, requestID, "approved", 2, 1)
			assertM24CommandEffects(t, ctx, pool, approvalInput.CommandID, 1)
			savedGrant := m24Must(observeGrant(ctx, pool, approver.Tenant, approvalInput.GrantID))
			var decision approvalRecord
			var decisionID, decisionActor string
			if err := pool.Raw().QueryRow(ctx, `SELECT command_id,approver_id,encrypted_payload,decided_at
				FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`,
				string(approver.Tenant), string(approvalInput.GrantID)).
				Scan(&decisionID, &decisionActor, &decision.payload, &decision.decidedAt); err != nil {
				t.Fatal("cannot read durable decision evidence", err)
			}
			decision.commandID, decision.approver = identity.CommandID(decisionID), identity.UserID(decisionActor)
			savedReason, epoch, err := openActivationApproval(ctx, cfg.Envelopes, savedGrant, decision)
			if err != nil || decision.commandID != approvalInput.CommandID || savedReason != approvalInput.Reason ||
				epoch != (approvalEpoch{userVersion: 1, authorizationVersion: 1, namespace: cfg.Session.Profile.PolicyNamespace}) {
				t.Fatal("approval did not seal the exact retained authority and intent", err)
			}
			if replay := m24Must(service.Execute(ctx, approval)); !reflect.DeepEqual(replay, approved) {
				t.Fatal("approval replay did not return its exact original result")
			}
			// Recovery reconstructs the public service, not the prepared command
			// or its private contributor, and retains the exact keyed outcome.
			restarted := m24Must(NewService(pool, cfg))
			if recovered := m24Must(restarted.Recover(ctx, approver, approvalBinding)); !reflect.DeepEqual(recovered, approved) {
				t.Fatal("restart recovery lost the exact approval outcome")
			}
			if recovered := m24Must(restarted.Recover(ctx, requester, requestBinding)); !reflect.DeepEqual(recovered, pending) {
				t.Fatal("request recovery changed after the distinct approval")
			}
			if _, err := restarted.Recover(ctx, requester, approvalBinding); err == nil {
				t.Fatal("requester recovered another administrator's approval")
			}
			assertM24Grant(t, ctx, pool, requestID, "approved", 2, 1)
			assertM24CommandEffects(t, ctx, pool, requestID, 1)
			assertM24CommandEffects(t, ctx, pool, approvalInput.CommandID, 1)
			assertM24NoSessionIssuance(t, ctx, pool)
		})
	}
}

type m24Authorization struct {
	recovery map[string]identity.CommandBinding
	revision authorization.Revision
}

func (p *m24Authorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	decision := authorization.Decision{Outcome: authorization.Deny, Revision: p.revision}
	if err := ctx.Err(); err != nil {
		return decision, err
	}
	r := caller.Request
	if recovering, _ := r.Resource.Attributes["identity.command.recovery"].Bool(); recovering {
		id, _ := r.Resource.Attributes["identity.command.id"].String()
		recordID, _ := r.Resource.Attributes["identity.command.record-id"].String()
		binding, known := p.recovery[id]
		if known && recordID == binding.RecordID && caller.PolicyRevision == p.revision && r.Tenant == authorization.TenantID(binding.TenantID) && r.Subject.Kind == binding.ActorKind && r.Subject.ID == authorization.SubjectID(binding.ActorID) && r.Action == authorization.Action(binding.OperationID) && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(binding.UserID) {
			decision.Outcome = authorization.Allow
		}
		return decision, nil
	}
	permissions, ok := r.Attributes[scopeAttribute].StringSet()
	actorAllowed := r.Subject.ID == "request-admin" && r.Action == requestAction || r.Subject.ID == "approve-admin" && r.Action == approveAction
	if caller.PolicyRevision == p.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && actorAllowed && r.Resource.Type == "identity.user" && r.Resource.ID == "target-user" && ok && slices.Equal(permissions, []string{"address.read", "profile.read"}) {
		decision.Outcome = authorization.Allow
	}
	return decision, nil
}

func newM24ServiceFixture(t *testing.T, ctx context.Context, pool *database.Pool) (*Service, Config, Authentication, Authentication) {
	t.Helper()
	directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12, GlobalAuthorityID: "m24-deployment", TenantIDs: []identity.TenantID{"m24-tenant"}}
	for _, source := range []migrations.Source{
		directory,
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "session_store", Version: 20}, Version: 21}, Version: 22},
		sessionpg.CSRFMigrationSource{Schema: "session_store", Version: 23},
		sessionpg.OTPMigrationSource{Schema: "session_store", Version: 24},
		sessionpg.CredentialContinuationMigrationSource{Schema: "session_store", Version: 25},
		sessionpg.MagicLinkMigrationSource{Schema: "session_store", Version: 26},
		sessionpg.MFAMigrationSource{Schema: "session_store", Version: 27},
		sessionpg.PasswordMFAMigrationSource{Schema: "session_store", Version: 28},
		mfapg.TOTPFactorMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2},
		riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "m24_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5},
		MigrationSource{},
	} {
		for _, migration := range m24Must(source.Load(ctx)) {
			m24Exec(t, ctx, pool, migration.UpSQL())
		}
	}
	policyMigration := m24Must(authoritypg.AuthoritySchemaMigration(30))
	m24Exec(t, ctx, pool, policyMigration.Up)
	for _, files := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations()} {
		for _, path := range m24Must(fs.Glob(files, "*.sql")) {
			contents := m24Must(fs.ReadFile(files, path))
			m24Exec(t, ctx, pool, strings.Split(string(contents), "-- +migrations Down")[0])
		}
	}
	m24Exec(t, ctx, pool, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('m24-tenant','request-admin','active',1),('m24-tenant','approve-admin','active',1),('m24-tenant','target-user','active',1)`)
	lookupKey := m24Must(session.NewDigestKey(1, bytes.Repeat([]byte{31}, 32)))
	csrfKey := m24Must(session.NewCSRFKey(1, bytes.Repeat([]byte{32}, 32)))
	requester := seedM24PasswordTOTPSession(t, ctx, pool, "request-admin", lookupKey, csrfKey)
	approver := seedM24PasswordTOTPSession(t, ctx, pool, "approve-admin", lookupKey, csrfKey)
	envelopes, _ := newCustodyTestService(t)
	cfg := Config{
		Policy:        m24Must(impersonation.NewPolicy("m24-distinct-admin", 1)),
		Authorization: &m24Authorization{recovery: make(map[string]identity.CommandBinding), revision: 1},
		Session: sessionpg.SessionServiceConfig{
			Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second},
			Profile:    sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "m24-deployment", PolicyNamespace: "m24-admins", Audience: "m24-console", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"},
			Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "m24-console", Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookupKey}},
		},
		CSRFKey:     csrfKey,
		Risk:        newM24RiskRepository(t),
		Audit:       m24Must(auditpg.NewIdentityContributor(auditpg.Config{})),
		Lifecycle:   m24Must(lifecyclepg.NewContributor()),
		Envelopes:   envelopes,
		EnvelopeKey: "custody-v1",
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {21}}},
	}
	return m24Must(NewService(pool, cfg)), cfg, requester, approver
}

func newM24RiskRepository(t *testing.T) *riskpg.Repository {
	t.Helper()
	policy := m24Must(risk.NewPolicy(risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}}))
	key := m24Must(risk.NewCounterDigestKey(1, bytes.Repeat([]byte{41}, 32)))
	evidence := m24Must(risk.NewEvidenceKey(1, bytes.Repeat([]byte{42}, 32), bytes.Repeat([]byte{43}, 32)))
	return m24Must(riskpg.NewRepository(riskpg.Config{Schema: "m24_risk", PolicyVersion: 1, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"m24-wrap": bytes.Repeat([]byte{44}, 32)}, CurrentEnvelopeKey: "m24-wrap", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}}, EnforceLockouts: true}))
}

func seedM24PasswordTOTPSession(t *testing.T, ctx context.Context, pool *database.Pool, user identity.UserID, lookupKey session.DigestKey, csrfKey session.CSRFKey) Authentication {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	newID := func() identity.CommandID { return m24Must(identity.NewCommandID()) }
	signup, enrollment, factorID, primary, completion, continuation := newID(), newID(), newID(), newID(), newID(), newID()
	seedCommand := func(id identity.CommandID, purpose string) {
		raw := m24Must(base64.RawURLEncoding.DecodeString(string(id)))
		m24Exec(t, ctx, pool, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'m24-tenant',$2,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, raw, purpose)
		m24Exec(t, ctx, pool, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'m24-tenant',$2)`, raw, purpose)
	}
	seedCommand(signup, "identity.password.signup")
	seedCommand(enrollment, "identity.mfa.enable")
	m24Exec(t, ctx, pool, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('m24-tenant',$1,'password',1,'identity/password',1,true)`, string(user))
	m24Exec(t, ctx, pool, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES('m24-tenant',$1,1,1,$2,'identity.password.signup')`, string(user), m24Must(base64.RawURLEncoding.DecodeString(string(signup))))
	m24Exec(t, ctx, pool, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('m24-tenant',$1,$2,2,1,1,'SHA1',6,30,1,'M24 fixture',decode('01','hex'),$3,'identity.mfa.enable',$4,$5,$4)`, string(user), string(factorID), m24Must(base64.RawURLEncoding.DecodeString(string(enrollment))), now.Add(-time.Minute), now.Add(time.Minute))
	policyScope := authoritypg.AuthorityScope{TenantID: "m24-tenant", PolicyNamespace: "m24-admins", SubjectID: authorization.SubjectID(user)}
	_ = m24Must(authoritypg.InitializeAuthority(ctx, pool.Raw(), policyScope, time.Second))
	remember := m24Must(session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}))
	spec := session.SessionSpec{TenantID: "m24-tenant", UserID: user, SessionID: "session-" + string(user), FamilyID: "family-" + string(user), Audience: "m24-console", Version: 1, FamilyVersion: 1, Remember: remember, IssuedAt: now, LastActivityAt: now}
	token := m24Must(session.NewToken(32))
	spec.Lookup = m24Must(token.Digest(lookupKey, "m24-tenant"))
	directoryKeys := m24Must(kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "m24-deployment", TenantID: "m24-tenant"}, user))
	sessionKeys := m24Must(sessionpg.SessionAuthorityKeys(spec.TenantID, user, spec.FamilyID, spec.SessionID))
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	spec.Authority = m24Must(session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(directoryKeys.Global), Tenant: bind(directoryKeys.Tenant), User: bind(directoryKeys.User), Identifier: bind(directoryKeys.Identifier), Credential: bind(directoryKeys.Credential), SessionFamily: bind(sessionKeys.Family), Session: bind(sessionKeys.Session), Authorization: bind(m24Must(policyScope.Key())), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind(m24Must(mfapg.FactorAuthorityKey(spec.TenantID, user)))}}))
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1, Proof: authentication.Proof{ID: authentication.ProofID(primary), Tenant: "m24-tenant", Subject: string(user), Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: session.PasswordMFAPrimaryPurpose, Audience: spec.Audience, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(4 * time.Minute)}}
	rememberSpec := m24Must(remember.Bindings())
	mfaSpec := session.MFAAuthenticationSpec{CommandID: completion, PrimaryCommandID: primary, ContinuationID: continuation, ContinuationScopeDigest: [32]byte{51}, Method: "totp", FactorID: string(factorID), EnrollmentVersion: 1, FactorAuthorityVersion: 1, ContinuationVersion: 1, Remember: rememberSpec, VerifiedAt: now, ValidUntil: now.Add(4 * time.Minute)}
	factor := m24Must(session.NewMFAAuthentication(mfaSpec))
	csrfToken := m24Must(session.NewCSRFToken())
	csrfState := m24Must(csrfToken.Digest(csrfKey, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: 1}))
	record := m24Must(session.NewSessionWithPasswordMFAAndCSRF(spec, factor, csrfState))
	// session/postgres deliberately keeps its encoder private. Seed its closed
	// schema-12 projection from validated native bindings, then read it through
	// the real service instead of adding a test-only production export.
	payload := m24Must(json.Marshal(map[string]any{"Schema": 12, "SessionID": spec.SessionID, "FamilyID": spec.FamilyID, "TenantID": spec.TenantID, "UserID": spec.UserID, "Audience": spec.Audience, "Version": spec.Version, "FamilyVersion": spec.FamilyVersion, "Remember": rememberSpec, "Authority": m24Must(spec.Authority.Bindings()), "Lookup": spec.Lookup, "Authentication": spec.Authentication, "IssuedAt": spec.IssuedAt, "LastActivityAt": spec.LastActivityAt, "MFA": mfaSpec, "CSRF": m24Must(csrfState.Bindings())}))
	lifetime := m24Must(record.Lifetime(now))
	const instant = "2006-01-02T15:04:05.000000000Z"
	m24Exec(t, ctx, pool, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES('m24-tenant',$1,$2,1,'active',$3)`, spec.FamilyID, string(user), now.Format(instant))
	m24Exec(t, ctx, pool, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('m24-tenant',$1,$2,$3,1,1,'active',1,$4,$5,$6)`, spec.SessionID, string(user), spec.FamilyID, spec.Lookup.Sum[:], lifetime.ExpiresAt.UTC().Format(instant), payload)
	return Authentication{Tenant: spec.TenantID, Bearer: authentication.NewBearerCredential(m24Must(token.Reveal())), CSRF: csrfToken}
}

func assertM24Grant(t *testing.T, ctx context.Context, pool *database.Pool, id identity.CommandID, state string, version uint64, approvals int) {
	t.Helper()
	var gotState, gotVersion, requester, target string
	var grants, decisions, events, audits int
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT g.state,g.version::text,g.requester_id,g.target_id,g.encrypted_payload,(SELECT count(*) FROM identity_impersonation.grants),(SELECT count(*) FROM identity_impersonation.approvals WHERE tenant_id=g.tenant_id AND grant_id=g.grant_id),(SELECT count(*) FROM public.outbox_messages),(SELECT count(*) FROM audit.records WHERE (convert_from(canonical_record,'UTF8')::jsonb #>> '{changes,no_change}')::boolean IS NOT TRUE) FROM identity_impersonation.grants g WHERE g.tenant_id='m24-tenant' AND g.grant_id=$1`, string(id)).Scan(&gotState, &gotVersion, &requester, &target, &ciphertext, &grants, &decisions, &events, &audits); err != nil {
		t.Fatal("read authoritative grant", err)
	}
	if gotState != state || gotVersion != strconv.FormatUint(version, 10) || requester != "request-admin" || target != "target-user" || grants != 1 || decisions != approvals || events != int(version) || audits != int(version) {
		t.Fatal("grant, distinct approval or single native effect diverged", gotState, gotVersion, grants, decisions, events, audits)
	}
	if bytes.Contains(ciphertext, []byte("private support case request")) {
		t.Fatal("original request reason was stored in clear text")
	}
	if approvals == 1 {
		var actor string
		if err := pool.Raw().QueryRow(ctx, `SELECT approver_id FROM identity_impersonation.approvals WHERE tenant_id='m24-tenant' AND grant_id=$1`, string(id)).Scan(&actor); err != nil || actor != "approve-admin" {
			t.Fatal("decision was not attributed to the distinct authenticated administrator", err)
		}
	}
}

func assertM24DeniedEffects(t *testing.T, ctx context.Context, pool *database.Pool, id identity.CommandID) {
	t.Helper()
	raw := m24Must(base64.RawURLEncoding.DecodeString(string(id)))
	var auditCount, outboxCount, chargeCount, snapshotCount int
	var noChange bool
	if err := pool.Raw().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
		(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
		(SELECT count(*) FROM m24_risk.counter_charges WHERE command_id=$1),
		(SELECT count(*) FROM m24_risk.counter_snapshots WHERE command_id=$1),
		(SELECT (convert_from(canonical_record,'UTF8')::jsonb #>> '{changes,no_change}')::boolean FROM audit.records WHERE correlation_id=$2)`,
		raw, string(id)).Scan(&auditCount, &outboxCount, &chargeCount, &snapshotCount, &noChange); err != nil {
		t.Fatal("read denial audit and risk custody", err)
	}
	if auditCount != 1 || outboxCount != 0 || chargeCount != 1 || snapshotCount != 4 || !noChange {
		t.Fatal("denial did not retain just its no-change audit and charged attempt", auditCount, outboxCount, chargeCount, snapshotCount, noChange)
	}
}

func assertM24CommandEffects(t *testing.T, ctx context.Context, pool *database.Pool, id identity.CommandID, want int) {
	t.Helper()
	var auditBindings, auditRecords, outboxBindings, charges, snapshots int
	raw := m24Must(base64.RawURLEncoding.DecodeString(string(id)))
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM audit.records WHERE correlation_id=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM m24_risk.counter_charges WHERE command_id=$1),(SELECT count(*) FROM m24_risk.counter_snapshots WHERE command_id=$1)`, raw, string(id)).Scan(&auditBindings, &auditRecords, &outboxBindings, &charges, &snapshots); err != nil {
		t.Fatal("read atomic command effects", err)
	}
	if auditBindings != want || auditRecords != want || outboxBindings != want || charges != want || snapshots != 4*want {
		t.Fatal("grant outcome split from audit, lifecycle or risk", auditBindings, auditRecords, outboxBindings, charges, snapshots)
	}
	var unredacted int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND (position(convert_to('private support case request','UTF8') in canonical_record)>0 OR position(convert_to('private distinct administrator approval','UTF8') in canonical_record)>0)`, string(id)).Scan(&unredacted); err != nil || unredacted != 0 {
		t.Fatal("private request or decision reason entered the audit projection", err)
	}
}

func assertM24NoSessionIssuance(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	var sessions, families, issuances int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM session_store.families),(SELECT count(*) FROM session_store.session_issuances)`).Scan(&sessions, &families, &issuances); err != nil || sessions != 2 || families != 2 || issuances != 0 {
		t.Fatal("approval issued a session or changed the original administrator sessions", sessions, families, issuances, err)
	}
}

func m24Exec(t *testing.T, ctx context.Context, pool *database.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, query, args...); err != nil {
		t.Fatal("native fixture statement failed", err)
	}
}

func m24Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
