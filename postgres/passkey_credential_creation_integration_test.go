//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// This fixture proves the kernel reference writer under the real coordinator,
// not WebAuthn verification, passkey enrollment policy or session issuance.
type passkeyCredentialWriter interface {
	CreatePasskeyCredential(context.Context, FeatureExecutionContributor, identity.Command, identity.CredentialRef, UserAuthorityAdmission) error
}

type passkeyReferencePhase struct {
	command    identity.Command
	credential identity.CredentialRef
	authority  UserAuthorityAdmission
	mode       string
	created    bool
}

func (*passkeyReferencePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*passkeyReferencePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (p *passkeyReferencePhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.command {
		return invalidWork()
	}
	return nil
}
func (p *passkeyReferencePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	writer, ok := any(w).(passkeyCredentialWriter)
	if !ok {
		return identity.FeatureReceipt{}, identity.InvalidInputError{Field: "passkey_credential_writer_unavailable"}
	}
	candidate, credential, owner := c, p.credential, FeatureExecutionContributor(p)
	if p.mode == "reconstructed-command" {
		s, _ := c.Feature()
		candidate, _ = identity.NewFeatureCommand(s)
	}
	if p.mode == "changed-reference" {
		credential.ID = "another-reference"
	}
	if p.mode == "foreign-owner" {
		owner = &passkeyReferencePhase{}
	}
	if err := writer.CreatePasskeyCredential(ctx, owner, candidate, credential, p.authority); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.created = true
	if p.mode == "duplicate" {
		// Ignored errors must still poison the original transaction.
		_ = writer.CreatePasskeyCredential(ctx, p, c, credential, p.authority)
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], AfterVersion: 1}, nil
}
func (p *passkeyReferencePhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if p.mode == "final-check-failure" || c != p.command {
		return identity.ForbiddenError{}
	}
	_, err := w.RequireActiveCredential(ctx, p, CredentialAdmission{Credential: p.credential, UserAuthorityVersion: p.authority.UserAuthorityVersion, IdentifierAuthorityVersion: p.authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.authority.CredentialAuthorityVersion})
	return err
}
func (*passkeyReferencePhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func passkeyReferenceFields(c identity.CredentialRef, a UserAuthorityAdmission) []identity.FeatureField {
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "passkey-reference." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "passkey-reference." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	return []identity.FeatureField{text("id", string(c.ID)), text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("owner", c.Owner), number("kind", uint64(c.Kind)), number("version", c.Version), number("user-authority", a.UserAuthorityVersion), number("identifier-authority", a.IdentifierAuthorityVersion), number("credential-authority", a.CredentialAuthorityVersion)}
}

func TestPasskeyCredentialCreationPostgres(t *testing.T) {
	ctx, pool, repo := anonymousKernelDatabase(t)
	for _, mode := range []string{"commit", "reconstructed-command", "changed-reference", "foreign-owner", "unknown-field", "duplicate", "existing-disabled", "stale-authority", "banned", "native-failure", "audit-failure", "outbox-failure", "final-check-failure"} {
		t.Run(mode, func(t *testing.T) {
			p := &passkeyReferencePhase{mode: mode}
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
			p.credential = identity.CredentialRef{ID: identity.CredentialID(b.RecordID), TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}
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
			fields := passkeyReferenceFields(p.credential, p.authority)
			if mode == "unknown-field" {
				fields = append(fields, identity.FeatureField{Name: "passkey-reference.unselected", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
			}
			if mode == "existing-disabled" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',1,false)`, string(b.TenantID), string(b.UserID), b.RecordID); err != nil {
					t.Fatal(err)
				}
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
			plan.Lifecycle = &LifecyclePlan{EventType: "passkey.registered.v1", AfterVersion: 1}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "identity.passkey.create_credential", "protected"
			seed, err := securityMutationAudit(ctx, b, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, p.command, plan)
			if err != nil {
				t.Fatal("prepare passkey reference", err)
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
				t.Fatal("initial passkey reference did not commit through its owning Work", err, applyErr)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid passkey reference escaped transaction")
			}
			if (mode == "native-failure" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-check-failure" || mode == "duplicate") && !p.created {
				t.Fatal("rollback control never reached reference creation", applyErr)
			}
			var refs, audit, lifecycle int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2), (SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded), (SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.TenantID), string(b.UserID), string(b.CommandID)).Scan(&refs, &audit, &lifecycle); err != nil {
				t.Fatal(err)
			}
			wantRefs := 0
			if success || mode == "existing-disabled" {
				wantRefs = 1
			}
			if refs != wantRefs || success && (audit != 1 || lifecycle != 1) || !success && (audit != 0 || lifecycle != 0) {
				t.Fatal("reference and required effects lost atomicity", refs, audit, lifecycle)
			}
			if mode == "existing-disabled" {
				var enabled bool
				if err := pool.Raw().QueryRow(ctx, `SELECT enabled FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(b.TenantID), string(b.UserID), b.RecordID).Scan(&enabled); err != nil || enabled {
					t.Fatal("creation resurrected an existing disabled reference", err)
				}
			}
			if success {
				current, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: b.UserID, CredentialID: p.credential.ID})
				if err != nil || !current.Enabled || current.Credential != p.credential || current.User.Version != 101 || current.AuthorityVersion != 13 {
					t.Fatal("creation replaced an independent existing authority", err)
				}
			}
		})
	}
}
