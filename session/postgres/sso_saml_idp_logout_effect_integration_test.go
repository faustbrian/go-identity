//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type samlIDPLogoutEffectTestOwner struct {
	effect       *SSOSAMLIDPLogoutEffect
	command      identity.Command
	intent       kernel.SSOSAMLIDPLogoutIntent
	mode         string
	applyCalls   int
	applied      bool
	checkCalls   int
	recoverCalls int
	vote         kernel.RecoveryStatus
}

func (*samlIDPLogoutEffectTestOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOSAMLIDPLogoutDescriptor()
}

func (*samlIDPLogoutEffectTestOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOSAMLIDPLogoutOperation()}
}

func (p *samlIDPLogoutEffectTestOwner) ValidateFeatureCommand(command identity.Command, _ kernel.CommandPlan) error {
	if command != p.command {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func (p *samlIDPLogoutEffectTestOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	receipt, err := p.effect.Apply(ctx, w, p, command, p.intent)
	p.applied = err == nil
	return receipt, err
}

func (p *samlIDPLogoutEffectTestOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	p.checkCalls++
	if p.mode == "late-target-version" {
		target := p.intent.Targets[1]
		if n, err := w.Exec(ctx, `UPDATE session_store.sessions SET version=version+1 WHERE tenant_id='guest-tenant' AND session_id=$1`, target.SessionID); err != nil || n != 1 {
			return identity.UnavailableError{}
		}
	}
	if err := p.effect.Check(ctx, w, p, command, p.intent); err != nil {
		return err
	}
	if p.mode == "late-final-failure" {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPLogoutEffectTestOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	p.recoverCalls++
	vote, err := p.effect.Recover(ctx, w, p, p.intent)
	p.vote = vote
	return vote, err
}

func TestSSOSAMLIDPLogoutEffectAtomicallyRevokesExactTargetSet(t *testing.T) {
	for _, mode := range []string{"commit-and-retry", "mismatched-issuance", "mismatched-version", "expired-request", "late-target-version", "late-final-failure", "recover-absent", "recover-matching", "recover-conflicting"} {
		t.Run(mode, func(t *testing.T) {
			f := newSSOSessionAccessFixture(t, "sso-saml")
			installSAMLIDPLogoutEffectTestHistory(t, f)
			second, secondRequest := addSAMLIDPLogoutEffectTestSession(t, f, "enterprise-access-second", "enterprise-family-second")
			unrelated, unrelatedRequest := addSAMLIDPLogoutEffectTestSession(t, f, "unrelated-access", "unrelated-family")
			firstTarget := seedSAMLIDPLogoutEffectTestIssuance(t, f, f.record, "identity.sso.saml-acs")
			secondTarget := seedSAMLIDPLogoutEffectTestIssuance(t, f, second, "identity.sso.saml-idp-init")
			seedSAMLIDPLogoutEffectTestIssuance(t, f, unrelated, "identity.sso.saml-acs")
			requests := []session.GetRequest{f.request, secondRequest, unrelatedRequest}
			for _, request := range requests {
				observed, err := f.reader.Get(f.ctx, request)
				if err != nil || !observed.Authenticated {
					t.Fatal("fixture session is not usable before logout", err)
				}
			}
			intent := kernel.SSOSAMLIDPLogoutIntent{
				OrganizationID: "selected-org", ProviderID: "selected-provider", RequestDigest: sha256.Sum256([]byte("authenticated-original-idp-logout-request")),
				ValidUntil: time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond),
				Targets:    []kernel.SSOSAMLIDPLogoutTarget{firstTarget, secondTarget},
			}
			if mode == "mismatched-issuance" {
				intent.Targets[1].IssuanceCommandID = newSAMLIDPLogoutEffectTestCommandID(t)
			}
			if mode == "mismatched-version" {
				intent.Targets[1].Version++
			}
			if mode == "expired-request" {
				intent.ValidUntil = time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
			}
			binding, command := newSAMLIDPLogoutEffectTestCommand(t, intent)
			effect, err := NewSSOSAMLIDPLogoutEffect(f.repository)
			if err != nil {
				t.Fatal("construct session-owned IdP logout effect", err)
			}
			owner := &samlIDPLogoutEffectTestOwner{effect: effect, command: command, intent: intent, mode: mode}
			coordinator, plan := prepareSAMLIDPLogoutEffectTest(t, f, owner, binding)
			reservation, _, err := coordinator.ReserveCommand(f.ctx, binding, command, plan)
			if err != nil {
				t.Fatal("reserve exact service command", err)
			}
			before := snapshotSAMLIDPLogoutEffectTestSessions(t, f)
			if mode == "recover-absent" || mode == "recover-matching" || mode == "recover-conflicting" {
				id := mustCommandBytes(t, binding.CommandID)
				wantVote := kernel.RecoveryNotCommitted
				if mode != "recover-absent" {
					_, bindingDigest := revocationEvidence(binding, kernel.SSOSAMLIDPLogoutLifecycle())
					intentDigest, err := samlIDPLogoutIntentDigest(intent)
					if err != nil {
						t.Fatal(err)
					}
					wantVote = kernel.RecoveryCommitted
					if mode == "recover-conflicting" {
						intentDigest[0] ^= 1
						wantVote = kernel.RecoveryUnknown
					}
					if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.saml_idp_logout_revocations VALUES($1,$2,$3,$4,$5,$6,2)`, string(binding.TenantID), id, binding.OperationID, string(binding.UserID), bindingDigest[:], intentDigest[:]); err != nil {
						t.Fatal("fixture could not retain native evidence", err)
					}
				}
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				query, caller := revokeRecoveryInput(binding)
				result, err := coordinator.RecoverFeatureCommand(f.ctx, query, caller)
				if owner.recoverCalls != 1 || owner.vote != wantVote || owner.applyCalls != 0 || snapshotSAMLIDPLogoutEffectTestSessions(t, f) != before {
					t.Fatal("recovery vote changed the target set or did not match retained evidence", result.Outcome, owner.vote, owner.recoverCalls, err)
				}
				if mode != "recover-absent" {
					var retained string
					if err == nil || result.Outcome == identity.CommitOutcomeCommitted || result.Outcome == identity.CommitOutcomeNotCommitted {
						t.Fatal("partial native evidence incorrectly settled the whole command", result.Outcome, err)
					}
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, id).Scan(&retained); err != nil || retained != "pending" {
						t.Fatal("partial native evidence must preserve the pending journal", retained, err)
					}
					return
				}
				if result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("absent native evidence did not reconcile as not committed", result.Outcome, err)
				}
				assertSAMLIDPLogoutEffectTestState(t, f, binding, before, false)
				return
			}
			work, err := coordinator.Begin(f.ctx, reservation)
			if err != nil {
				t.Fatal("begin exact coordinator transaction", err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			candidate, applyErr := coordinator.ApplyFeature(f.ctx, work, command)
			var result identity.CommandResult
			if applyErr != nil {
				result, err = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, candidate)
			}
			committed := mode == "commit-and-retry"
			if committed {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.Operation != kernel.SSOSAMLIDPLogoutOperation() || result.Feature.BeforeVersion != 0 || result.Feature.AfterVersion != 1 {
					t.Fatal("exact two-session logout did not commit aggregate receipt", result.Outcome, applyErr, err)
				}
			} else if result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("mismatched or late-failed target set was not rolled back", result.Outcome, applyErr, err)
			}
			if owner.applyCalls != 1 || committed && (!owner.applied || owner.checkCalls != 1) || (mode == "late-target-version" || mode == "late-final-failure") && (!owner.applied || owner.checkCalls != 1) {
				t.Fatal("test did not reach the intended apply/final-check boundary", owner.applyCalls, owner.applied, owner.checkCalls)
			}
			assertSAMLIDPLogoutEffectTestState(t, f, binding, before, committed)
			for i, request := range requests {
				observed, readErr := f.reader.Get(f.ctx, request)
				wantAuthenticated := !committed || i == 2
				if readErr != nil || observed.Authenticated != wantAuthenticated {
					t.Fatal("cookie validity changed outside the exact committed target set", i, observed.Authenticated, readErr)
				}
			}
			if committed {
				after := snapshotSAMLIDPLogoutEffectTestSessions(t, f)
				_, replay, err := coordinator.ReserveCommand(f.ctx, binding, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || *replay.Feature != *result.Feature || owner.applyCalls != 1 {
					t.Fatal("same-command retry did not return the original receipt", replay.Outcome, owner.applyCalls, err)
				}
				if snapshotSAMLIDPLogoutEffectTestSessions(t, f) != after {
					t.Fatal("same-command retry changed a session or family again")
				}
				assertSAMLIDPLogoutEffectTestState(t, f, binding, before, true)
			}
		})
	}
}

func installSAMLIDPLogoutEffectTestHistory(t *testing.T, f ssoSessionAccessFixture) {
	t.Helper()
	for _, source := range []migrations.Source{
		SSOOIDCSigninMigrationSource{Schema: f.repository.Schema, Version: 80, ValidationVersion: 81, PreviousConstraint: "session_issuances_purpose_anonymous_v1"},
		SSOOAuth2SigninMigrationSource{Schema: f.repository.Schema, Version: 82, ValidationVersion: 83},
		SSOSAMLSigninMigrationSource{Schema: f.repository.Schema, Version: 84, ValidationVersion: 85},
		SSOSAMLIDPSigninMigrationSource{Schema: f.repository.Schema, Version: 86, ValidationVersion: 87},
		SSOSAMLIDPLogoutMigrationSource{Schema: f.repository.Schema, Version: 100},
	} {
		history, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load actual SAML issuance/logout history", err)
		}
		for _, step := range history {
			if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
				t.Fatal("install actual SAML issuance/logout history", err)
			}
		}
	}
}

func newSAMLIDPLogoutEffectTestCommandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func addSAMLIDPLogoutEffectTestSession(t *testing.T, f ssoSessionAccessFixture, sessionID, familyID string) (session.Session, session.GetRequest) {
	t.Helper()
	spec, err := f.record.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.SessionID, spec.FamilyID = sessionID, familyID
	spec.Authentication.Proof.ID = auth.ProofID(newSAMLIDPLogoutEffectTestCommandID(t))
	authority, err := spec.Authority.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := SessionAuthorityKeys(spec.TenantID, spec.UserID, familyID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	authority.Session.ScopeKey, authority.SessionFamily.ScopeKey = keys.Session, keys.Family
	spec.Authority, err = session.NewAuthoritySnapshot(authority)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(f.validation.LookupKeys[0], string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := f.csrf.Digest(f.csrfKey, session.CSRFBinding{TenantID: spec.TenantID, SessionID: sessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(spec, csrf)
	if err != nil {
		t.Fatal(err)
	}
	wire, expiry, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(spec.TenantID), familyID, string(spec.UserID), spec.IssuedAt.Format(storedTimeLayout)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8::jsonb)`, string(spec.TenantID), sessionID, string(spec.UserID), familyID, int64(spec.Lookup.KeyVersion), spec.Lookup.Sum[:], expiry, wire); err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return record, session.GetRequest{TenantID: spec.TenantID, Credential: credential}
}

func seedSAMLIDPLogoutEffectTestIssuance(t *testing.T, f ssoSessionAccessFixture, record session.Session, purpose string) kernel.SSOSAMLIDPLogoutTarget {
	t.Helper()
	spec, err := record.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.ParseCommandID(string(spec.Authentication.Proof.ID))
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	recordDigest := sha256.Sum256(wire)
	// These retained rows provide native issuance provenance, not a claim that
	// this component fixture authenticated an external SAML assertion.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, mustCommandBytes(t, id), string(spec.TenantID), purpose); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, mustCommandBytes(t, id), string(spec.TenantID), purpose); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.session_issuances(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('02',32),'hex'),$7)`, string(spec.TenantID), mustCommandBytes(t, id), purpose, string(spec.UserID), spec.SessionID, spec.FamilyID, recordDigest[:]); err != nil {
		t.Fatal("seed retained native SAML issuance", err)
	}
	return kernel.SSOSAMLIDPLogoutTarget{SessionID: spec.SessionID, FamilyID: spec.FamilyID, IssuanceCommandID: id, Version: spec.Version}
}

func newSAMLIDPLogoutEffectTestCommand(t *testing.T, intent kernel.SSOSAMLIDPLogoutIntent) (identity.CommandBinding, identity.Command) {
	t.Helper()
	op := kernel.SSOSAMLIDPLogoutOperation()
	binding := revokeBinding()
	binding.CommandID = newSAMLIDPLogoutEffectTestCommandID(t)
	binding.TenantID, binding.UserID, binding.ActorID, binding.ActorKind = "guest-tenant", "enterprise-user", "saml-service", authorization.SubjectServiceAccount
	binding.OperationID, binding.SchemaID, binding.SchemaVersion, binding.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(binding.CommandID)
	fields, err := kernel.SSOSAMLIDPLogoutFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	return binding, command
}

func prepareSAMLIDPLogoutEffectTest(t *testing.T, f ssoSessionAccessFixture, owner *samlIDPLogoutEffectTestOwner, binding identity.CommandBinding) (*kernel.Coordinator, kernel.CommandPlan) {
	t.Helper()
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, auditor, lifecycle, owner})
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: revokeQueryPolicy{}, Clock: clock.System{}, PolicyVersion: binding.PolicyVersion}
	coordinator, err := kernel.NewCoordinator(f.pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {73}}, QueryPolicy: &query})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	op := kernel.SSOSAMLIDPLogoutOperation()
	const subjectType = "sso_saml_logout"
	seed, err := builder.Build(audit.RecordInput{
		OccurredAt: time.Now().UTC(), Action: op.OperationID, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: subjectType, ID: binding.RecordID},
		Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: strconv.FormatUint(binding.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": subjectType, "aggregate.id": binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, op, subjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	transition := kernel.SSOSAMLIDPLogoutLifecycle()
	plan, err := coordinator.PrepareCommandPlan(binding, owner.command, kernel.CommandPlan{
		Contributors: registry.Descriptors(), SubjectType: subjectType, Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Lifecycle: &transition,
		Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}},
	})
	if err != nil {
		t.Fatal("prepare exact service actor, audit and aggregate lifecycle", err)
	}
	return coordinator, plan
}

type samlIDPLogoutEffectTestSnapshot struct {
	state, record, familyState, version, familyVersion string
}

func snapshotSAMLIDPLogoutEffectTestSessions(t *testing.T, f ssoSessionAccessFixture) [3]samlIDPLogoutEffectTestSnapshot {
	t.Helper()
	var snapshots [3]samlIDPLogoutEffectTestSnapshot
	for i, id := range []string{"enterprise-access", "enterprise-access-second", "unrelated-access"} {
		s := &snapshots[i]
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.state,s.version::text,s.record::text,f.state,f.version::text FROM session_store.sessions s JOIN session_store.families f USING(tenant_id,family_id) WHERE s.tenant_id='guest-tenant' AND s.session_id=$1`, id).Scan(&s.state, &s.version, &s.record, &s.familyState, &s.familyVersion); err != nil {
			t.Fatal("snapshot actual session and family", err)
		}
	}
	return snapshots
}

func assertSAMLIDPLogoutEffectTestState(t *testing.T, f ssoSessionAccessFixture, binding identity.CommandBinding, before [3]samlIDPLogoutEffectTestSnapshot, committed bool) {
	t.Helper()
	after := snapshotSAMLIDPLogoutEffectTestSessions(t, f)
	for i, actual := range after {
		if !committed || i == 2 {
			if actual != before[i] {
				t.Fatal("an aborted or unrelated session changed", i)
			}
			continue
		}
		if actual.state != "revoked" || actual.version != before[i].version || actual.record != before[i].record || actual.familyState != before[i].familyState || actual.familyVersion != before[i].familyVersion {
			t.Fatal("target revocation changed its immutable predecessor or family", i, actual.state, actual.version, actual.familyState, actual.familyVersion)
		}
	}
	var evidence, targets, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM session_store.saml_idp_logout_revocations WHERE tenant_id=$1 AND command_id=$2 AND purpose=$3 AND user_id=$4),
 (SELECT COALESCE(sum(target_count),0) FROM session_store.saml_idp_logout_revocations WHERE tenant_id=$1 AND command_id=$2),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.outcome=$5),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$2)`, string(binding.TenantID), mustCommandBytes(t, binding.CommandID), binding.OperationID, string(binding.UserID), int64(audit.OutcomeSucceeded)).Scan(&evidence, &targets, &audits, &events); err != nil {
		t.Fatal("read durable native/audit/lifecycle evidence", err)
	}
	want := 0
	if committed {
		want = 1
	}
	if evidence != want || targets != 2*want || audits != want || events != want {
		t.Fatal("native target-set evidence, audit and lifecycle were not atomic or were duplicated", evidence, targets, audits, events)
	}
}
