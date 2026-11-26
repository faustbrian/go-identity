//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Google verification, risk admission and encrypted preparation output are
// bounded fixtures, not authentication or the production OAuth owner. The
// coordinator, one-use participant, selected account, MFA, provider-bound browser
// storage and session effects below are real. No HTTP or live Google is used.
type oneTapSessionInvocation struct {
	effect                          *OneTapCallbackEffect
	original                        identity.Command
	declaration                     kernel.CommandPlan
	flow                            session.PreAuthTransaction
	mode, lateSQL                   string
	retained                        kernel.Work
	consumption                     kernel.CapabilityReservationBinding
	applyCalls                      int
	applied, finalEntered, admitted bool
}

func (*oneTapSessionInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-completion", Version: 1}
}

func (*oneTapSessionInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.OneTapCallbackOperation()}
}

func (p *oneTapSessionInvocation) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.original || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != kernel.OneTapCallbackOperation() || plan.Capability == nil || p.declaration.Capability == nil || *plan.Capability != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	if _, err := kernel.OneTapCallbackAccount(command); err != nil {
		return err
	}
	_, err := OneTapCallbackSession(command)
	return err
}

func (p *oneTapSessionInvocation) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}

func (p *oneTapSessionInvocation) ValidateOneTapCallbackConsumption(command identity.Command, plan kernel.CapabilityPlan) error {
	if command != p.original || p.declaration.Capability == nil || plan != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapSessionInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	f, ok := command.Feature()
	b, registration, _, err := w.FeatureScope(p)
	if err != nil || !ok || command != p.original || b != f.Binding || registration.Operation != kernel.OneTapCallbackOperation() {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *oneTapSessionInvocation) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return (ssoOIDCSessionPreparation{}).Generate(ctx, generation)
}

func (p *oneTapSessionInvocation) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if command != p.original || generation == 0 || len(wire) != 8 || binary.BigEndian.Uint64(wire) != generation {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	return command, p.declaration, ctx.Err()
}

func (p *oneTapSessionInvocation) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, p.declaration); err != nil {
		return nil, err
	}
	return ssoOIDCSessionPreparation{}, ctx.Err()
}

func (p *oneTapSessionInvocation) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	return ssoOIDCSessionPreparation{}, nil
}

func (p *oneTapSessionInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	p.retained = w
	consumed, err := w.OneTapCallbackConsumption(p)
	f, ok := command.Feature()
	if err != nil || !ok || command != p.original || consumed.Command != f.Binding || consumed.Plan != *p.declaration.Capability || consumed.Generation == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.consumption = consumed
	if p.mode == "reconstructed-command" {
		cookie, _ := command.PreAuthCookie()
		command, err = identity.NewFeaturePreAuthCommand(f, cookie)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	receipt, err := p.effect.Apply(ctx, w, p, command, p.flow)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	if p.lateSQL != "" {
		if _, err := w.Exec(ctx, p.lateSQL); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return receipt, nil
}

func (p *oneTapSessionInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.finalEntered = true
	if w != p.retained || command != p.original {
		return identity.ForbiddenError{}
	}
	if err := p.effect.CheckCurrent(ctx, w, p, command); err != nil {
		return err
	}
	p.admitted = true
	return nil
}

func (p *oneTapSessionInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func TestOneTapCallbackSessionPreparedPostgres(t *testing.T) {
	ctx, pool, repository := anonymousSessionDatabase(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 30}
	prepared := kernel.CounterPreparationMigrationSource{Base: kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 31}, Version: 32}, Version: 33}
	history, err := (kernel.OneTapCallbackPreparationErasureMigrationSource{Base: prepared, Version: 34}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() >= 30 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("native account and One Tap preparation history", err)
			}
		}
	}
	for _, source := range []migrations.Source{
		mfapg.MigrationSource{Version: 35},
		PreAuthMigrationSource{Schema: "session_store", Version: 36},
		CSRFMigrationSource{Schema: "session_store", Version: 37},
		OneTapCallbackSessionMigrationSource{Schema: "session_store", Version: 38, ValidationVersion: 39, PreviousConstraint: "session_issuances_purpose_anonymous_v1"},
	} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("native browser, factor and session history", err)
			}
		}
	}
	capabilityHistory := capabilitypg.Migrations()
	entries, err := fs.ReadDir(capabilityHistory, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(capabilityHistory, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal("real one-use capability history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('guest-tenant','onetap-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'guest-tenant','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'guest-tenant','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('guest-tenant','onetap-user',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('guest-tenant','onetap-user','google-credential',3,'identity/oauth',1,true);
WITH a AS (SELECT 'google'::text AS provider,'https://accounts.google.com'::text AS issuer,'opaque-google-subject'::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT 'guest-tenant','onetap-user','google-account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a;
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('guest-tenant','onetap-user','google-credential','google-account')`); err != nil {
		t.Fatal("existing linked Google account and known-empty factor fixture", err)
	}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "oauth", CredentialKind: identity.CredentialProvider, CredentialOwner: "identity/oauth"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policy.AuthorityScope{TenantID: "guest-tenant", PolicyNamespace: profile.PolicyNamespace, SubjectID: "onetap-user"}, time.Second); err != nil {
		t.Fatal(err)
	}
	provider := session.PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "synthetic-onetap-client", Mode: session.PreAuthProviderCallback}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	native, err := NewRepository(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, lateSQL string }{
		{"commit", ""},
		{"reconstructed-command", ""},
		{"wrong-selected-provider", ""},
		{"existing-family", ""},
		{"late-global-epoch", `UPDATE identity.global_authorities SET version=2 WHERE authority_id='guest-deployment'`},
		{"late-tenant-disabled", `UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id='guest-tenant'`},
		{"late-user-suspended", `UPDATE identity.users SET status='suspended' WHERE tenant_id='guest-tenant' AND user_id='onetap-user'`},
		{"late-identifier-epoch", `UPDATE identity.users SET identifier_version=2 WHERE tenant_id='guest-tenant' AND user_id='onetap-user'`},
		{"late-credential-epoch", `UPDATE identity.users SET credential_version=2 WHERE tenant_id='guest-tenant' AND user_id='onetap-user'`},
		{"late-credential-disabled", `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='guest-tenant' AND credential_id='google-credential'`},
		{"late-account-unlinked", `UPDATE identity.accounts SET linked=false WHERE tenant_id='guest-tenant' AND account_id='google-account'`},
		{"late-account-version", `UPDATE identity.accounts SET version=2 WHERE tenant_id='guest-tenant' AND account_id='google-account'`},
		{"late-social-link-version", `UPDATE identity.accounts SET social_link_version=2 WHERE tenant_id='guest-tenant' AND account_id='google-account'`},
		{"late-policy-epoch", `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id='guest-tenant' AND subject_id='onetap-user'`},
		{"late-factor-enrolled", `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id='guest-tenant' AND user_id='onetap-user'`},
		{"late-factor-generation", `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id='guest-tenant' AND user_id='onetap-user'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, record, flow, proof := oneTapSessionPreparedFixture(t, ctx, pool, repository, profile, provider, test.name)
			selected := provider
			if test.name == "wrong-selected-provider" {
				selected.ProviderVersion++
			}
			effect, err := NewOneTapCallbackEffect(config, profile, selected)
			if err != nil {
				t.Fatal(err)
			}
			owner := &oneTapSessionInvocation{effect: effect, original: command, flow: flow, mode: test.name, lateSQL: test.lateSQL}
			f, _ := command.Feature()
			b := f.Binding
			spec, _ := record.Bindings()
			flowSpec, _ := flow.ProviderBindings()
			if test.name == "existing-family" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(spec.TenantID), spec.FamilyID, string(spec.UserID), spec.IssuedAt.Add(-time.Minute).Format(storedTimeLayout)); err != nil {
					t.Fatal(err)
				}
			}
			before := oneTapSessionAuthoritySnapshot(t, ctx, pool)
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &revokeAudit{}, &revokeOutbox{}, owner, capabilitypg.NewParticipant()})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := builder.Build(audit.RecordInput{OccurredAt: spec.IssuedAt, Action: "identity.oauth.verify_one_tap", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, "authentication_attempt", seed)
			if err != nil {
				t.Fatal(err)
			}
			transition := kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}
			owner.declaration = kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: f.Operation}, Capability: &proof, Lifecycle: &transition, Audits: []kernel.AuditPlan{{EventType: "identity.oauth.verify_one_tap", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			plan, err := coordinator.PrepareFeaturePreparationPlan(command, owner.declaration)
			if err != nil {
				t.Fatal("prepare original One Tap callback", err)
			}
			result, executionErr := coordinator.ExecutePreparedFeature(ctx, command, plan)
			success := test.name == "commit"
			if owner.applyCalls != 1 || owner.retained == (kernel.Work{}) || owner.consumption.Generation == 0 {
				t.Fatal("original callback did not reach real consumed Work", executionErr)
			}
			if success {
				if executionErr != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.admitted || result.Feature == nil || *result.Feature != (identity.FeatureReceipt{Operation: f.Operation, BeforeVersion: 1, AfterVersion: 2}) {
					t.Fatal("original Google callback did not commit its exact session", result.Outcome, executionErr)
				}
			} else if executionErr == nil || result.Outcome != identity.CommitOutcomeNotCommitted || owner.admitted {
				t.Fatal("denied callback was not rolled back", result.Outcome, executionErr)
			}
			if test.lateSQL != "" && (!owner.applied || !owner.finalEntered) {
				t.Fatal("late authority denial did not test the final fence", executionErr)
			}
			if test.lateSQL == "" && !success && (owner.applied || owner.finalEntered) {
				t.Fatal("invalid original callback escaped Apply admission")
			}
			if err := effect.CheckCurrent(ctx, owner.retained, owner, command); err == nil {
				t.Fatal("returned Work retained session authority")
			}
			if got := oneTapSessionAuthoritySnapshot(t, ctx, pool); got != before {
				t.Fatal("account, credential, directory, policy or factor mutation escaped rollback")
			}
			want, wantState, wantFlow, wantVersion := 0, "released", "issued", "1"
			if success {
				want, wantState, wantFlow, wantVersion = 1, "finalized", "consumed", "3"
			}
			var sessions, families, issuances, uses int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT state,uses,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$2 AND session_id=$3),(SELECT count(*) FROM session_store.families WHERE tenant_id=$2 AND family_id=$4),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$2 AND session_id=$3) FROM public.capability_identity_one_use WHERE capability_id=$1`, proof.CapabilityID, string(spec.TenantID), spec.SessionID, spec.FamilyID).Scan(&state, &uses, &sessions, &families, &issuances); err != nil {
				t.Fatal(err)
			}
			wantFamilies := want
			if test.name == "existing-family" {
				wantFamilies = 1
			}
			if sessions != want || families != wantFamilies || issuances != want || uses != want || state != wantState {
				t.Fatal("session, new family, issuance and one-use effects were not atomic", sessions, families, issuances, uses, state)
			}
			var flowState, version, generation string
			var wire, flowCommand, fingerprint []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT state,version::text,record,command_id,fingerprint,COALESCE(generation::text,'') FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), string(flowSpec.Transaction.Binding.ID)).Scan(&flowState, &version, &wire, &flowCommand, &fingerprint, &generation); err != nil {
				t.Fatal(err)
			}
			originalWire, _ := encodePreAuth(flow)
			if flowState != wantFlow || version != wantVersion || !bytes.Equal(wire, originalWire) {
				t.Fatal("original provider-bound browser changed or escaped rollback", flowState, version)
			}
			if success {
				if !bytes.Equal(flowCommand, mustCommandBytes(t, b.CommandID)) || !bytes.Equal(fingerprint, owner.consumption.Fingerprint[:]) || generation != strconv.FormatUint(owner.consumption.Generation, 10) {
					t.Fatal("browser finalization changed original capability custody")
				}
			} else if len(flowCommand) != 0 || len(fingerprint) != 0 || generation != "" {
				t.Fatal("rolled-back callback retained browser custody")
			}
			var audits, successfulAudits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE outcome=$2),(SELECT count(*) FROM public.revoke_outbox WHERE command_id=$1) FROM public.revoke_audit WHERE command_id=$1`, string(b.CommandID), int64(audit.OutcomeSucceeded)).Scan(&audits, &successfulAudits, &events); err != nil || audits != 1 || successfulAudits != want || events != want {
				t.Fatal("success audit or lifecycle escaped rollback, or terminal failure audit was lost", audits, successfulAudits, events, err)
			}
			stored, readErr := native.Get(ctx, spec.TenantID, spec.SessionID)
			if !success {
				if !errors.Is(readErr, ErrRecordAbsent) || stored != (StoredSession{}) {
					t.Fatal("denied callback exposed a provisional session", readErr)
				}
				return
			}
			wantWire, _, _ := encodeRecord(record)
			gotWire, _, encodeErr := encodeRecord(stored.Session)
			if readErr != nil || encodeErr != nil || !bytes.Equal(wantWire, gotWire) || stored.CurrentFamilyVersion != 1 || stored.Revoked || stored.FamilyRevoked {
				t.Fatal("stored session changed original authority, proof, remember policy or CSRF", readErr, encodeErr)
			}
			retained, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, transition, oneTapCallbackIssuanceDigest)
			if err != nil || status != kernel.RecoveryCommitted || retained.UserID != spec.UserID || retained.SessionID != spec.SessionID || retained.FamilyID != spec.FamilyID {
				t.Fatal("retained One Tap issuance lost original identity", err)
			}
			if _, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, transition, oauthSigninIssuanceDigest); err != nil || status != kernel.RecoveryUnknown {
				t.Fatal("ordinary OAuth issuance domain borrowed One Tap evidence", err)
			}
			// Historical commitment survives live-session revocation. Replaying the
			// original command must not restore current access or consume again.
			if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(spec.TenantID), spec.SessionID); err != nil {
				t.Fatal(err)
			}
			replayed, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
			if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Binding != b || replayed.Feature == nil || *replayed.Feature != *result.Feature || owner.applyCalls != 1 {
				t.Fatal("original historical receipt was lost or reexecuted", err)
			}
			stored, err = native.Get(ctx, spec.TenantID, spec.SessionID)
			if err != nil || !stored.Revoked {
				t.Fatal("historical callback replay restored revoked access", err)
			}
			var ciphertext, ciphertextGeneration bool
			if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NOT NULL,preparation_ciphertext_generation IS NOT NULL FROM identity.commands WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&ciphertext, &ciphertextGeneration); err != nil || ciphertext || ciphertextGeneration {
				t.Fatal("committed callback retained temporary preparation custody", err)
			}
		})
	}
}

func oneTapSessionPreparedFixture(t *testing.T, ctx context.Context, pool *database.Pool, repository *kernel.Repository, profile IdentifierAdmissionConfig, provider session.PreAuthProviderBinding, name string) (identity.Command, session.Session, session.PreAuthTransaction, kernel.CapabilityPlan) {
	t.Helper()
	account, err := repository.GetProviderSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: "guest-tenant", Provider: "google", Issuer: "https://accounts.google.com", Subject: "opaque-google-subject"})
	if err != nil || account.Account.ID != "google-account" || account.Account.UserID != "onetap-user" {
		t.Fatal("real existing selected Google account", err)
	}
	directory, err := repository.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: account.Account.TenantID})
	if err != nil || !directory.Enabled {
		t.Fatal("real current directory", err)
	}
	factors, err := mfapg.ReadOAuthSigninFactors(ctx, pool, account.Account.TenantID, account.Account.UserID, time.Second)
	if err != nil || factors.Version() != 1 {
		t.Fatal("real current known-empty factor generation", err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	flowID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := kernel.OneTapCallbackOperation()
	binding := identity.CommandBinding{CommandID: id, TenantID: account.Account.TenantID, ActorID: "onetap-service", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: string(flowID), RecordID: string(flowID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "onetap-signin", PolicyVersion: 1, CorrelationID: string(id)}
	spec, _ := testSession(t).Bindings()
	spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID = "onetap-session-"+name, "onetap-family-"+name, binding.TenantID, account.Account.UserID
	spec.Version, spec.FamilyVersion, spec.IssuedAt, spec.LastActivityAt = 1, 1, now, now
	spec.Audience = profile.Audience
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(id), Tenant: string(spec.TenantID), Subject: string(spec.UserID), Method: "oauth", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: spec.Audience, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: string(account.Credential.Credential.ID), CredentialVersion: account.Credential.Credential.Version}
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.KernelAuthorityKeys(directory.Query, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sessionKeys, err := SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	policyKey, err := (policy.AuthorityScope{TenantID: authorization.TenantID(spec.TenantID), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(spec.UserID)}).Key()
	if err != nil {
		t.Fatal(err)
	}
	factorKey, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	a := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	spec.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global, directory.GlobalVersion), Tenant: a(keys.Tenant, directory.TenantVersion), User: a(keys.User, account.Credential.UserAuthorityVersion), Identifier: a(keys.Identifier, account.Credential.IdentifierAuthorityVersion), Credential: a(keys.Credential, account.Credential.CredentialAuthorityVersion), Session: a(sessionKeys.Session, 1), SessionFamily: a(sessionKeys.Family, 1), Authorization: a(policyKey, 1), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(factorKey, factors.Version())}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	record = withCSRFState(t, record, 1)
	flowSpec, _ := testPreAuth(t, now).Bindings()
	flowSpec.Binding.ID = flowID
	flowSpec.Binding.Intent.TenantID, flowSpec.Binding.Intent.Action = binding.TenantID, "identity.oauth.onetap-start"
	flowSpec.Binding.Intent.PolicyID, flowSpec.Binding.Intent.PolicyVersion, flowSpec.Binding.Intent.Remember = binding.PolicyID, binding.PolicyVersion, spec.Remember
	flowSpec.Binding.Intent.Origin, flowSpec.Binding.Intent.CallbackURL = "https://identity.test", ""
	flowSpec.Binding.Intent.IdentifierBinding = [32]byte{}
	flowSpec.Binding.Intent.Purpose = session.PreAuthSessionIssuance
	flowSpec.Binding.ExpiresAt = now.Add(5 * time.Minute)
	cookie, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	flowSpec.Cookie, err = cookie.ProviderPreAuthDigest(key, flowSpec.Binding, provider)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewProviderPreAuthTransaction(session.ProviderPreAuthTransactionSpec{Transaction: flowSpec, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	flowTx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer flowTx.Rollback(ctx)
	if err := insertSelectedPreAuth(ctx, preAuthTestTx{flowTx}, Config{Schema: "session_store", MaximumDuration: time.Second}, flow, provider); err != nil {
		t.Fatal("original provider-bound issued browser transaction", err)
	}
	if err := flowTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadProviderPreAuth(ctx, pool.Raw(), Config{Schema: "session_store", MaximumDuration: time.Second}, binding.TenantID, flowID, provider)
	if err != nil || loaded.CheckProvider(now, flowSpec.Binding, provider, flowSpec.Cookie) != nil {
		t.Fatal("read exact provider-bound original browser", err)
	}
	fields, err := OneTapCallbackSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	accountFields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	cookieWire, err := cookie.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: append(fields, accountFields...)}, auth.NewBearerCredential(cookieWire))
	if err != nil {
		t.Fatal(err)
	}
	proof := kernel.CapabilityPlan{CapabilityID: string(id), Purpose: capability.Purpose(op.OperationID), ReplayKeyVersion: 1, ReplayDigest: sha256.Sum256([]byte(id)), ProofFingerprint: [32]byte{79}, ExpiresAt: now.Add(2 * time.Minute).Truncate(time.Second), MaxUses: 1}
	// Only issuance metadata is synthetic: the real participant owns reserve,
	// consumption, finalization, rollback and release in the coordinator Work.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(binding.TenantID), string(proof.Purpose), proof.ReplayKeyVersion, proof.ReplayDigest[:], proof.CapabilityID, proof.ProofFingerprint[:], proof.ExpiresAt, proof.MaxUses); err != nil {
		t.Fatal(err)
	}
	return command, record, loaded, proof
}

func oneTapSessionAuthoritySnapshot(t *testing.T, ctx context.Context, pool *database.Pool) string {
	t.Helper()
	var snapshot string
	err := pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
(SELECT to_jsonb(a) FROM identity.global_authorities a WHERE authority_id='guest-deployment'),
(SELECT to_jsonb(a) FROM identity.tenant_authorities a WHERE tenant_id='guest-tenant'),
(SELECT to_jsonb(a) FROM identity.users a WHERE tenant_id='guest-tenant' AND user_id='onetap-user'),
(SELECT to_jsonb(a) FROM identity.credential_references a WHERE tenant_id='guest-tenant' AND credential_id='google-credential'),
(SELECT to_jsonb(a) FROM identity.accounts a WHERE tenant_id='guest-tenant' AND account_id='google-account'),
(SELECT to_jsonb(a) FROM authorization_subject_authorities a WHERE tenant_id='guest-tenant' AND subject_id='onetap-user'),
(SELECT to_jsonb(a) FROM identity_mfa.factor_authorities a WHERE tenant_id='guest-tenant' AND user_id='onetap-user'))::text`).Scan(&snapshot)
	if err != nil {
		t.Fatal("read exact real authority snapshot", err)
	}
	return snapshot
}
