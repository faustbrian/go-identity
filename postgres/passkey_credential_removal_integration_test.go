//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// This fixture proves only the kernel-owned reference transition and Work
// atomicity. Genuine proof, recovery, protocol and session admission belong to
// the consuming native passkey journey.
type passkeyRemovalPhase struct {
	command    identity.Command
	credential identity.CredentialRef
	authority  UserAuthorityAdmission
	mode       string
	removed    bool
}

func (*passkeyRemovalPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*passkeyRemovalPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (p *passkeyRemovalPhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.command {
		return invalidWork()
	}
	return nil
}
func (p *passkeyRemovalPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	candidate, credential, owner := c, p.credential, FeatureExecutionContributor(p)
	if p.mode == "reconstructed-command" {
		s, _ := c.Feature()
		candidate, _ = identity.NewFeatureCommand(s)
	}
	if p.mode == "changed-reference" {
		credential.ID = "another-reference"
	}
	if p.mode == "foreign-owner" {
		owner = &passkeyRemovalPhase{}
	}
	if p.mode != "skip-removal" {
		if err := w.RemovePasskeyCredential(ctx, owner, candidate, credential, p.authority); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.removed = true
	}
	if p.mode == "duplicate" {
		_ = w.RemovePasskeyCredential(ctx, p, c, credential, p.authority)
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.mode == "altered-successor" {
		if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET enabled=true WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(credential.TenantID), string(credential.UserID), string(credential.ID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: credential.Version, AfterVersion: credential.Version + 1}, nil
}
func (p *passkeyRemovalPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if p.mode == "final-check-failure" {
		return identity.ForbiddenError{}
	}
	return w.CheckRemovedPasskeyCredential(ctx, p, c, p.credential, p.authority)
}
func (*passkeyRemovalPhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func TestPasskeyCredentialRemovalPostgres(t *testing.T) {
	ctx, pool, repo := anonymousKernelDatabase(t)
	for _, mode := range []string{"commit", "foreign-lifecycle", "reconstructed-command", "changed-reference", "foreign-owner", "unknown-field", "duplicate", "already-disabled", "stale-reference", "stale-authority", "banned", "skip-removal", "altered-successor", "native-failure", "audit-failure", "outbox-failure", "final-check-failure"} {
		t.Run(mode, func(t *testing.T) {
			p := &passkeyRemovalPhase{mode: mode}
			op := p.FeatureOperations()[0]
			b := codecBinding()
			var err error
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			user, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			b.UserID, b.ActorID, b.ActorKind = identity.UserID(user), identity.ActorID(user), authorization.SubjectUser
			b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, "passkey-reference"
			p.credential = identity.CredentialRef{ID: identity.CredentialID(b.RecordID), TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 9}
			p.authority = UserAuthorityAdmission{UserAuthorityVersion: 7, IdentifierAuthorityVersion: 11, CredentialAuthorityVersion: 13}
			status, epoch := "active", "13"
			if mode == "banned" {
				status = "banned"
			}
			if mode == "stale-authority" {
				epoch = "14"
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,$3,101,7,11,$4::numeric)`, string(b.TenantID), string(b.UserID), status, epoch); err != nil {
				t.Fatal(err)
			}
			enabled, version := mode != "already-disabled", 9
			if mode == "stale-reference" {
				version++
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',$4,$5)`, string(b.TenantID), string(b.UserID), b.RecordID, version, enabled); err != nil {
				t.Fatal(err)
			}
			fields, err := PasskeyCredentialRemovalFields(p.credential, p.authority)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-field" {
				fields = append(fields, identity.FeatureField{Name: "passkey-removal-reference.unselected", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
			}
			p.command = featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			auditing := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
			outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, outbox, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, "credential"
			plan.Lifecycle = &LifecyclePlan{EventType: "identity.passkey.remove_credential", BeforeVersion: 9, AfterVersion: 10}
			if mode == "foreign-lifecycle" {
				plan.Lifecycle.EventType = "identity.passkey.mark_compromised"
			}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "identity.passkey.remove_credential", "protected"
			seed, err := securityMutationAudit(ctx, b, 9, 10, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, p.command, plan)
			if err != nil {
				t.Fatal("prepare removal reference", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, p.command)
			if applyErr != nil {
				result, err = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			success := mode == "commit"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("removal did not commit in owning Work", err, applyErr)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid removal escaped transaction")
			}
			if (mode == "duplicate" || mode == "altered-successor" || mode == "native-failure" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-check-failure") && !p.removed {
				t.Fatal("rollback control never reached removal", applyErr)
			}
			var currentVersion, userVersion, credentialEpoch string
			var currentEnabled bool
			if err := pool.Raw().QueryRow(ctx, `SELECT c.version::text,c.enabled,u.version::text,u.credential_version::text FROM identity.credential_references c JOIN identity.users u USING(tenant_id,user_id) WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.credential_id=$3`, string(b.TenantID), string(b.UserID), b.RecordID).Scan(&currentVersion, &currentEnabled, &userVersion, &credentialEpoch); err != nil {
				t.Fatal(err)
			}
			wantVersion := "9"
			if success || mode == "stale-reference" {
				wantVersion = "10"
			}
			if currentVersion != wantVersion || currentEnabled != (enabled && !success) || userVersion != "101" || credentialEpoch != epoch {
				t.Fatal("removal changed unrelated authority or lost atomic predecessor", currentVersion, currentEnabled, userVersion, credentialEpoch)
			}
			var audit, lifecycle int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(b.CommandID)).Scan(&audit, &lifecycle); err != nil {
				t.Fatal(err)
			}
			if success && (audit != 1 || lifecycle != 1) || !success && (audit != 0 || lifecycle != 0) {
				t.Fatal("removal effects lost atomicity", audit, lifecycle)
			}
		})
	}
}
