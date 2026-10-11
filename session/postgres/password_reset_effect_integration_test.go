//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This fixture isolates real kernel/session SQL. Capability/risk below are
// deliberate invocation-only doubles: this is not reset authorization, actual
// password material replacement or the public reset journey.
type resetSessionFeature struct {
	effect        *PasswordResetEffect
	intent        kernel.CredentialResetIntent
	command       identity.Command
	foreign, fail bool
}

func (*resetSessionFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*resetSessionFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordResetSessionOperation()}
}
func (p *resetSessionFeature) CredentialReset(c identity.Command) (kernel.CredentialResetIntent, error) {
	if c != p.command {
		return kernel.CredentialResetIntent{}, identity.ForbiddenError{}
	}
	return p.intent, nil
}
func (p *resetSessionFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	_, err := p.CredentialReset(c)
	return err
}
func (p *resetSessionFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	owner := p
	if p.foreign {
		clone := *p
		owner = &clone
	}
	return p.effect.Apply(ctx, w, owner, c)
}
func (p *resetSessionFeature) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.fail {
		return identity.UnavailableError{}
	}
	_, _, _, err := w.FeatureScope(p)
	return err
}
func (p *resetSessionFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

type resetSessionOutbox struct{ revokeOutbox }

func (p *resetSessionOutbox) PersistCredentialReset(ctx context.Context, w kernel.Work) error {
	if _, err := w.StagedCredentialReplacement(); err != nil {
		return err
	}
	return p.PersistLifecycle(ctx, w)
}

type resetSessionCounter struct{}

func (*resetSessionCounter) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}
func (*resetSessionCounter) ValidateCommandCounters(identity.Command, kernel.CommandCounterPlan) error {
	return nil
}
func (p *resetSessionCounter) ReserveCommandCounters(_ context.Context, w kernel.CommandCounterWork) (kernel.CommandCounterDisposition, error) {
	_, err := w.Binding(p)
	return kernel.CommandCounterAllowed, err
}
func (p *resetSessionCounter) CheckCommandCounters(_ context.Context, w kernel.CommandCounterAdmissionWork) error {
	_, err := w.Binding(p)
	return err
}
func (*resetSessionCounter) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryNotCommitted, nil
}

type resetSessionCapability struct{}

func (*resetSessionCapability) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
}
func (p *resetSessionCapability) ReserveCapability(_ context.Context, w kernel.CapabilityReservationWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *resetSessionCapability) RebindCapability(_ context.Context, w kernel.CapabilityReservationWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *resetSessionCapability) ReleaseCapability(_ context.Context, w kernel.CapabilityReleaseWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *resetSessionCapability) ApplyCapability(_ context.Context, w kernel.CapabilityApplyWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *resetSessionCapability) FinalizeCapability(_ context.Context, w kernel.CapabilityFinalizeWork) error {
	_, err := w.Binding(p)
	return err
}
func (*resetSessionCapability) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryNotCommitted, nil
}

func testNativeResetSessionEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	effect, err := NewPasswordResetEffect(Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "reset-session-effect"
	const foreignTenant = "reset-session-foreign"
	for _, mode := range []string{"all", "empty", "rollback", "audit-failure", "outbox-failure", "foreign-participant"} {
		t.Run(mode, func(t *testing.T) {
			user := identity.UserID(mode)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,credential_version) VALUES($1,$2,'active',101,3)`, tenant, string(user)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',7,false)`, tenant, string(user)); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			selected := 18
			if mode == "empty" {
				selected = 0
			}
			if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, foreignTenant, string(user)); e != nil {
				t.Fatal(e)
			}
			// Include one genuine other-tenant record with the same user ID,
			// including when the local set is empty. It must remain active.
			for i := 0; i <= selected; i++ {
				rowTenant := tenant
				if i == selected {
					rowTenant = foreignTenant
				}
				s, _ := testSession(t).Bindings()
				s.TenantID, s.UserID, s.SessionID, s.FamilyID = identity.TenantID(rowTenant), user, fmt.Sprintf("%s-session-%02d", mode, i), fmt.Sprintf("%s-family-%02d", mode, i)
				s.Version, s.FamilyVersion = 1, 1
				vector, _ := s.Authority.Bindings()
				vector.Session.Version, vector.SessionFamily.Version = 1, 1
				s.Authority, err = session.NewAuthoritySnapshot(vector)
				if err != nil {
					t.Fatal(err)
				}
				s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject = rowTenant, string(user)
				s.Lookup = session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte(s.SessionID))}
				// Revocation grants no authority and must also terminate records
				// with old/foreign method snapshots; no preservation is attempted.
				record, e := session.NewSession(s)
				if e != nil {
					t.Fatal(e)
				}
				wire, expiry, e := encodeRecord(record)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, rowTenant, string(user), s.FamilyID, s.IssuedAt.UTC().Format(storedTimeLayout)); e != nil {
					t.Fatal(e)
				}
				if _, e = pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,user_id,session_id,family_id,version,family_version,digest_version,digest,state,expires_at,record) VALUES($1,$2,$3,$4,1,1,1,$5,'active',$6,$7::jsonb)`, rowTenant, string(user), s.SessionID, s.FamilyID, s.Lookup.Sum[:], expiry, string(wire)); e != nil {
					t.Fatal(e)
				}
			}
			b := revokeBinding()
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID = tenant, user
			op := passwordResetSessionOperation()
			b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, "password"
			intent := kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: "password", TenantID: tenant, UserID: user, Owner: "identity/password", Kind: identity.CredentialPassword, Version: 7}, ExpectedUserVersion: 101, ExpectedAuthorityVersion: 3}, ExpectedEnabled: false}
			fields, e := kernel.CredentialResetFields(intent)
			if e != nil {
				t.Fatal(e)
			}
			signer, e := capability.NewHMACSHA256Signer("synthetic-reset", bytes.Repeat([]byte{1}, 32))
			if e != nil {
				t.Fatal(e)
			}
			expiry := now.Add(time.Minute).Truncate(time.Second)
			wire, e := capability.Issue(ctx, capability.Payload{Version: 1, Issuer: "https://issuer.test", Audiences: []string{"reset"}, Subject: string(user), Tenant: tenant, Resource: "identity.password/password", Operation: op.OperationID, ID: string(b.CommandID), IssuedAt: now.Truncate(time.Second), NotBefore: now.Truncate(time.Second), ExpiresAt: expiry, MaxUses: 1}, signer, capability.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}
			proof, e := capability.ParseProof(wire, capability.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}
			command, e := identity.NewFeaturePasswordResetCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, "$argon2id$synthetic-command-custody", proof)
			if e != nil {
				t.Fatal(e)
			}
			feature := &resetSessionFeature{effect: effect, intent: intent, command: command, foreign: mode == "foreign-participant", fail: mode == "rollback"}
			auditing, outbox := &revokeAudit{fail: mode == "audit-failure"}, &resetSessionOutbox{revokeOutbox{fail: mode == "outbox-failure"}}
			registry, e := kernel.NewContributorRegistry([]kernel.Contributor{domain, auditing, outbox, feature, &resetSessionCounter{}, &resetSessionCapability{}})
			if e != nil {
				t.Fatal(e)
			}
			coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: revokeQueryPolicy{}}})
			if e != nil {
				t.Fatal(e)
			}
			builder, e := audit.NewBuilder(audit.BuilderConfig{})
			if e != nil {
				t.Fatal(e)
			}
			seed, e := builder.Build(audit.RecordInput{OccurredAt: now, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: b.RecordID}, Context: audit.ContextInput{TenantID: tenant, CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": b.RecordID, "aggregate.before_version": "7", "aggregate.after_version": "8", "retention.class": "protected"}})
			if e != nil {
				t.Fatal(e)
			}
			digest, e := kernel.FeatureAuditBindingDigest(b, op, "credential", seed)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: op}, SubjectType: "credential", Lifecycle: &kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 7, AfterVersion: 8}, CommandCounters: &kernel.CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{3}}, Capability: &kernel.CapabilityPlan{CapabilityID: string(b.CommandID), Purpose: capability.Purpose(op.OperationID), ReplayKeyVersion: 1, ReplayDigest: [32]byte{1}, ProofFingerprint: [32]byte{2}, ExpiresAt: expiry, MaxUses: 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if e != nil {
				t.Fatal("reset plan", e)
			}
			reservation, _, e := coordinator.ReserveCommand(ctx, b, command, plan)
			if e != nil {
				t.Fatal("reset reservation", e)
			}
			w, e := coordinator.Begin(ctx, reservation)
			if e != nil {
				t.Fatal(e)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			result, e := coordinator.ApplyFeature(ctx, w, command)
			if e == nil {
				result, e = coordinator.Commit(w, result)
			} else {
				result, _ = coordinator.Abort(w, e)
			}
			committed := mode == "all" || mode == "empty"
			if committed && (e != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("reset session commit", e, result.Outcome)
			}
			failureOutcome := identity.CommitOutcomeNotCommitted
			if mode == "audit-failure" {
				// Domain rollback succeeds, but the same unavailable mandatory
				// audit owner prevents a terminal abort receipt. Preserve Unknown;
				// authoritative rows below still prove no partial domain effects.
				failureOutcome = identity.CommitOutcomeUnknown
			}
			if !committed && (e == nil || result.Outcome != failureOutcome) {
				t.Fatal("failed reset did not abort", e, result.Outcome)
			}
			var active, revoked, evidence int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'),(SELECT count(*) FROM session_store.password_resets WHERE tenant_id=$1 AND user_id=$2)`, tenant, string(user)).Scan(&active, &revoked, &evidence); e != nil {
				t.Fatal(e)
			}
			if committed && (active != 0 || revoked != selected || evidence != 1) || !committed && (active != selected || revoked != 0 || evidence != 0) {
				t.Fatal("partial session reset escaped", active, revoked, evidence)
			}
			var aggregate, epoch, version string
			var enabled bool
			if e := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,c.version::text,c.enabled FROM identity.users u JOIN identity.credential_references c USING(tenant_id,user_id) WHERE u.tenant_id=$1 AND u.user_id=$2`, tenant, string(user)).Scan(&aggregate, &epoch, &version, &enabled); e != nil {
				t.Fatal(e)
			}
			if committed && (aggregate != "102" || epoch != "4" || version != "8" || !enabled) || !committed && (aggregate != "101" || epoch != "3" || version != "7" || enabled) {
				t.Fatal("reset kernel/session effects diverged")
			}
			var foreignState string
			if e := pool.Raw().QueryRow(ctx, `SELECT state FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2`, foreignTenant, string(user)).Scan(&foreignState); e != nil || foreignState != "active" {
				t.Fatal("reset crossed tenant scope", e)
			}
		})
	}
}
