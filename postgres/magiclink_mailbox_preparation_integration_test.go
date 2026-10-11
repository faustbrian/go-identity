//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Kernel protocol seam only: no production signer, delivery or signup service.
type magicLinkMailboxPreparationPhase struct {
	magicLinkProspectivePhase
	declaration    CommandPlan
	wantAvailable  bool
	generated      int
	foreignCommand bool
	beforeGenerate func(context.Context) error
}

func (p *magicLinkMailboxPreparationPhase) ValidateFeaturePreparation(c identity.Command, plan CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *magicLinkMailboxPreparationPhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	if p.foreignCommand {
		spec, _ := c.Feature()
		var err error
		c, err = identity.NewFeatureCommand(spec)
		if err != nil {
			return err
		}
	}
	available, err := p.domain.AdmitProspectiveMailbox(ctx, w, p, c, p.intent.Identifier.CanonicalValue)
	if err != nil {
		return err
	}
	if available != p.wantAvailable || w.state.magicLinkRecipient != nil || w.state.magicLinkRequestAccepted {
		return invalidWork()
	}
	return nil
}
func (p *magicLinkMailboxPreparationPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.expected || generation == 0 || ctx.Err() != nil {
		return nil, invalidPreparation()
	}
	p.generated++
	if p.beforeGenerate != nil {
		if err := p.beforeGenerate(ctx); err != nil {
			return nil, err
		}
	}
	return []byte{1}, nil
}
func (p *magicLinkMailboxPreparationPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	if ctx.Err() != nil || c != p.expected || generation == 0 || len(wire) != 1 || wire[0] != 1 {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	return c, p.declaration, nil
}
func (p *magicLinkMailboxPreparationPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, err := p.domain.AdmitProspectiveMailbox(ctx, w, p, c, p.intent.Identifier.CanonicalValue); err == nil {
		return identity.FeatureReceipt{}, invalidWork()
	}
	// The admission-only method must deny Apply without poisoning a legitimate
	// caller's Work merely for observing the wrong invocation phase.
	available, err := p.domain.SelectProspectiveRecipient(ctx, w, p, c, p.intent)
	if err != nil || available != p.available {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.operation}, nil
}

func testMagicLinkMailboxPreparation(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	history, err := (PreparationMigrationSource{Base: MigrationSource{}, Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() == 15 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	domain, err := NewMagicLinkRegistrationDomain(repo, MagicLinkRegistrationDomainConfig{ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"absent", "unverified", "banned", "retired", "missing-key", "foreign-command", "foreign-tenant", "final-collision"} {
		t.Run(mode, func(t *testing.T) {
			b, plan, _ := magicLinkIssuanceFixture(t)
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID = identity.TenantID("mailbox-" + mode)
			plan.MagicLinkRequestAcceptance = true
			intent := magicLinkRegistrationIntentFixture()
			intent.Creation.Binding = b
			intent.Creation.Binding.OperationID, intent.Creation.Binding.AnonymousFlowID, intent.Creation.Binding.UserID, intent.Creation.Binding.SchemaID = "identity.user.create", "", "future-user", "fields"
			intent.Identifier.UserID, intent.Identifier.ID, intent.Identifier.CanonicalValue = "future-user", "future-email", "mailbox@example.test"
			occupy := func(ctx context.Context) error {
				tenant, status := string(b.TenantID), "active"
				if mode == "foreign-tenant" {
					tenant += "-other"
				}
				if mode == "banned" {
					status = "banned"
				}
				_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'occupant',$2,1);`, tenant, status)
				if err != nil {
					return err
				}
				_, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES($1,'occupant','occupied-email','email',$2,1,1,1)`, tenant, intent.Identifier.CanonicalValue)
				return err
			}
			if mode == "unverified" || mode == "banned" || mode == "foreign-tenant" {
				if err := occupy(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "retired" || mode == "missing-key" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'old-user','active',1)`, string(b.TenantID)); err != nil {
					t.Fatal(err)
				}
				version := uint32(1)
				if mode == "missing-key" {
					version = 2
				}
				digest := identifierReuseDigest([32]byte{1}, b.TenantID, identity.IdentifierEmail, intent.Identifier.CanonicalValue)
				_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until) VALUES($1,'old-user','old-email','email',1,1,true,$2,$3,$4,clock_timestamp(),clock_timestamp()+interval '1 day')`, string(b.TenantID), string(b.CommandID), version, digest[:])
				if err != nil {
					t.Fatal(err)
				}
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation, Fields: []identity.FeatureField{{Name: "request", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "mailbox-preparation"}}}})
			native := &magicLinkMailboxPreparationPhase{magicLinkProspectivePhase: magicLinkProspectivePhase{magicLinkIssuancePhase: magicLinkIssuancePhase{resetIssuancePhase{operation: plan.Feature.Operation}}, domain: domain, intent: intent, expected: command}, wantAvailable: mode == "absent" || mode == "foreign-tenant" || mode == "final-collision", foreignCommand: mode == "foreign-command"}
			native.available = mode == "absent" || mode == "foreign-tenant"
			if mode == "final-collision" {
				native.beforeGenerate = occupy
			}
			registry, err := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, native})
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
			plan, err = coordinator.PrepareFeaturePreparationPlan(command, plan)
			if err != nil {
				t.Fatal(err)
			}
			native.declaration = plan
			result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
			if mode == "missing-key" || mode == "foreign-command" {
				if err == nil || native.generated != 0 {
					t.Fatal("unavailable or foreign admission generated output")
				}
			} else if err != nil || result.Outcome != identity.CommitOutcomeCommitted || native.generated != 1 {
				t.Fatal("prepared mailbox classification", err)
			}
		})
	}
}
