//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This exercises actual native request admission and its primary fences, not
// the production signer/delivery or public signup route.
type magicLinkProspectivePhase struct {
	magicLinkIssuancePhase
	domain   *MagicLinkRegistrationDomain
	intent   MagicLinkRegistrationIntent
	expected identity.Command
}

func (p *magicLinkProspectivePhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	if c != p.expected || plan.Feature == nil || !magicLinkRequestOperation(plan.Feature.Operation) {
		return invalidPlan()
	}
	return nil
}
func (p *magicLinkProspectivePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := p.domain.RequireProspectiveRecipient(ctx, w, p, c, p.intent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if w.state.magicLinkRecipient == nil || w.state.magicLinkRecipient.prospective == nil || w.state.binding.UserID != "" {
		return identity.FeatureReceipt{}, invalidWork()
	}
	return identity.FeatureReceipt{Operation: p.operation}, nil
}
func testMagicLinkProspectiveRequest(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	domain, err := NewMagicLinkRegistrationDomain(repo, MagicLinkRegistrationDomainConfig{ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "occupied-email", "occupied-user", "occupied-identifier", "retired-email", "wrong-policy", "foreign-origin", "outbox-failure"} {
		t.Run(mode, func(t *testing.T) {
			b, plan, _ := magicLinkIssuanceFixture(t)
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID = "prospective-request"
			intent := magicLinkRegistrationIntentFixture()
			intent.Creation.Binding = b
			intent.Creation.Binding.OperationID, intent.Creation.Binding.AnonymousFlowID, intent.Creation.Binding.UserID, intent.Creation.Binding.SchemaID = "identity.user.create", "", identity.UserID("prospective-"+mode), "fields"
			intent.Identifier.UserID, intent.Identifier.ID, intent.Identifier.CanonicalValue = intent.Creation.Binding.UserID, identity.IdentifierID("prospective-email-"+mode), mode+"@example.test"
			if mode == "occupied-user" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(intent.Creation.Binding.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "occupied-email" || mode == "occupied-identifier" || mode == "retired-email" {
				old := "existing-" + mode
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), old); err != nil {
					t.Fatal(err)
				}
				if mode == "retired-email" {
					digest := identifierReuseDigest([32]byte{1}, b.TenantID, identity.IdentifierEmail, intent.Identifier.CanonicalValue)
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until) VALUES($1,$2,$3,'email',1,1,true,$4,1,$5,clock_timestamp(),clock_timestamp()+interval '1 day')`, string(b.TenantID), old, old, string(b.CommandID), digest[:]); err != nil {
						t.Fatal(err)
					}
				} else {
					id, email := old, intent.Identifier.CanonicalValue
					if mode == "occupied-identifier" {
						id, email = string(intent.Identifier.ID), "different-"+email
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES($1,$2,$3,'email',$4,1,1,1)`, string(b.TenantID), old, id, email); err != nil {
						t.Fatal(err)
					}
				}
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation, Fields: []identity.FeatureField{{Name: "request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "prospective-request"}}}})
			if mode == "wrong-policy" {
				intent.EmailPossessionPolicyVersion++
			}
			if mode == "foreign-origin" {
				intent.Creation.Binding.CommandID, _ = identity.NewCommandID()
			}
			native := &magicLinkProspectivePhase{magicLinkIssuancePhase: magicLinkIssuancePhase{resetIssuancePhase{operation: plan.Feature.Operation}}, domain: domain, intent: intent, expected: command}
			outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			registry, err := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, outbox, native})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			seed, err := securityMutationAudit(ctx, b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, native.operation, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.ApplyFeature(ctx, work, command)
			if err == nil {
				result, err = coordinator.Commit(work, result)
			}
			if mode == "commit" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("prospective request", err)
				}
			} else {
				if err == nil {
					t.Fatal("conflicting prospective request committed")
				}
				_, _ = coordinator.Abort(work, err)
			}
			var users, identifiers, created int
			commandID, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND command_id=$3)`, string(b.TenantID), string(intent.Creation.Binding.UserID), commandID).Scan(&users, &identifiers, &created); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "occupied-user" {
				want = 1
			}
			if users != want || identifiers != 0 || created != 0 {
				t.Fatal("request created or verified an account")
			}
		})
	}
}
