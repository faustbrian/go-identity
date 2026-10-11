//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Native SQL seams prove kernel creation/proof/audit/outbox atomicity, not
// real magic-link verification, factor initialization or public session issuance.
type magicLinkRegistrationPhase struct {
	magicLinkConsumptionPhase
	domain *MagicLinkRegistrationDomain
	intent MagicLinkRegistrationIntent
	skip   bool
}

func (p *magicLinkRegistrationPhase) MagicLinkRegistration(c identity.Command) (MagicLinkRegistrationIntent, error) {
	if c != p.expected {
		return MagicLinkRegistrationIntent{}, invalidMagicLinkRegistration()
	}
	return p.intent, nil
}
func (p *magicLinkRegistrationPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if !p.skip {
		if _, err := p.domain.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: magicLinkConsumeOperation()}, nil
}
func (p *magicLinkRegistrationPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if c != p.expected || p.failCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

type magicLinkRegistrationOutbox struct{ recoveryLifecyclePhase }

func (p *magicLinkRegistrationOutbox) PersistMagicLinkRegistration(ctx context.Context, w Work) error {
	if err := p.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	created, err := w.StagedMagicLinkRegistrationLifecycle()
	if err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO public.identity_test_magic_creation_events(event_id,command_id,user_id,event_type,before_version,after_version) VALUES($1,$2,$3,$4,$5,$6)`, created.ID, string(created.CommandID), created.SubjectID, created.EventType, created.BeforeVersion, created.AfterVersion)
	return err
}

func TestMagicLinkRegistrationIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback database required")
	}
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	defer stop()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := admin.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_magic_registration_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error(err)
		}
	}()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	history, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{storageSchema()}})
	if err != nil {
		t.Fatal(err)
	}
	testMagicLinkRegistration(t, ctx, pool, repo)
	t.Run("prospective request", func(t *testing.T) { testMagicLinkProspectiveRequest(t, ctx, pool, repo) })
}

func testMagicLinkRegistration(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	base := PasswordSignupAcceptanceMigrationSource{Base: PasswordRegistrationMigrationSource{Base: CredentialMigrationSource{Base: IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}
	history, err := (MagicLinkRegistrationMigrationSource{Base: base, Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() > 9 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("registration suffix", err)
			}
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_magic_creation_events(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,user_id text NOT NULL,event_type text NOT NULL,before_version numeric NOT NULL,after_version numeric NOT NULL);
CREATE TABLE identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	domain, err := NewMagicLinkRegistrationDomain(repo, MagicLinkRegistrationDomainConfig{ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-creation", "apply-denied", "commit-denied", "audit-failure", "outbox-failure", "finalize-failure", "canonical-conflict", "changed-policy", "changed-creation"} {
		t.Run(mode, func(t *testing.T) {
			b, plan := magicLinkConsumptionPlanFixture(t)
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			plan.Capability.CapabilityID = "magic-registration-" + mode
			intent := magicLinkRegistrationIntentFixture()
			intent.Creation.Binding = b
			intent.Creation.Binding.OperationID, intent.Creation.Binding.AnonymousFlowID, intent.Creation.Binding.SchemaID, intent.Creation.Binding.UserID = "identity.user.create", "", "fields", identity.UserID("magic-created-"+mode)
			intent.Identifier.UserID, intent.Identifier.ID, intent.Identifier.CanonicalValue = intent.Creation.Binding.UserID, identity.IdentifierID("magic-email-"+mode), mode+"@example.test"
			digest, err := MagicLinkRegistrationDigest(intent)
			if err != nil {
				t.Fatal(err)
			}
			plan.MagicLinkRegistration = &MagicLinkRegistrationPlan{UserID: intent.Creation.Binding.UserID, IdentifierID: string(intent.Identifier.ID), CreationDigest: digest, EmailPossessionPolicyVersion: 3, CreationEventIndex: 1}
			fields, err := MagicLinkRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: fields})
			native := &magicLinkRegistrationPhase{magicLinkConsumptionPhase: magicLinkConsumptionPhase{expected: command, proof: *plan.Capability, failApply: mode == "apply-denied", failCommit: mode == "commit-denied"}, domain: domain, intent: intent, skip: mode == "missing-creation"}
			if mode == "canonical-conflict" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'already-owned','active',1) ON CONFLICT DO NOTHING`, string(b.TenantID)); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version) VALUES($1,'already-owned','occupied-email','email',$2,false,false,1,1,1)`, string(b.TenantID), intent.Identifier.CanonicalValue); err != nil {
					t.Fatal(err)
				}
			}
			auditing := &recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}
			outbox := &magicLinkRegistrationOutbox{recoveryLifecyclePhase: recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}}
			cap := &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-failure"}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, outbox, native, &emailVerificationCounterPhase{}, cap})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			seed, err := securityMutationAudit(ctx, b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, magicLinkConsumeOperation(), plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = c.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("signup consuming plan unavailable", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), plan.Capability.Purpose, plan.Capability.CapabilityID, plan.Capability.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			r, _, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := c.Begin(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "changed-policy" {
				native.intent.EmailPossessionPolicyVersion++
			}
			if mode == "changed-creation" {
				native.intent.Identifier.CanonicalValue = "retargeted@example.test"
			}
			result, err := c.ApplyFeature(ctx, w, command)
			if err == nil {
				result, err = c.Commit(w, result)
			}
			if mode == "commit" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("passwordless creation failed", err)
				}
			} else {
				if err == nil {
					t.Fatal("denial committed creation")
				}
				_, _ = c.Abort(w, err)
			}
			var users, identifiers, credentials, bindings, audits, events int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND verified AND verification_state=2 AND verified_at IS NOT NULL),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND user_id=$2 AND credential_id IS NULL),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_magic_creation_events WHERE command_id=$3 AND event_type='user.created.v1' AND before_version=0 AND after_version=1),(SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$4)`, string(b.TenantID), string(intent.Creation.Binding.UserID), string(b.CommandID), plan.Capability.CapabilityID).Scan(&users, &identifiers, &credentials, &bindings, &audits, &events, &state); err != nil {
				t.Fatal(err)
			}
			if mode == "commit" {
				if users != 1 || identifiers != 1 || credentials != 0 || bindings != 1 || audits != 1 || events != 1 || state != "finalized" {
					t.Fatal("split passwordless creation", users, identifiers, credentials, bindings, audits, events, state)
				}
				reservation, replay, err := c.ReserveCommand(ctx, b, command, plan)
				if err != nil || reservation.state != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Binding != b {
					t.Fatal("registration replay lost original receipt", err)
				}
				for _, recoveryCase := range []struct {
					name     string
					expected RecoveryStatus
				}{{"exact", RecoveryCommitted}, {"different-identifier", RecoveryUnknown}, {"other-command-same-user", RecoveryNotCommitted}} {
					// Exercise only the kernel evidence reader on a fresh primary
					// transaction. This is not full ambiguous-commit orchestration.
					frozen := *r.state.plan
					frozen.magicLinkRegistration = cloneMagicLinkRegistrationPlan(frozen.magicLinkRegistration)
					if recoveryCase.name == "different-identifier" {
						frozen.magicLinkRegistration.IdentifierID = "different-id"
					}
					if recoveryCase.name == "other-command-same-user" {
						frozen.binding.CommandID, err = identity.NewCommandID()
						if err != nil {
							t.Fatal(err)
						}
					}
					tx, err := pool.Raw().Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					work := Work{state: &workState{ctx: ctx, tx: tx, binding: frozen.binding}}
					recovery := RecoveryWork{state: &recoveryWorkState{work: work, entry: registeredContributor{descriptor: repo.Descriptor(), contributor: repo}, plan: &frozen, active: true}}
					status, evidenceErr := repo.RecoverParticipant(ctx, recovery)
					recovery.state.active = false
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
					if evidenceErr != nil || status != recoveryCase.expected {
						t.Fatal("registration recovery evidence", recoveryCase.name, status, evidenceErr)
					}
				}
			} else if users != 0 || identifiers != 0 || credentials != 0 || bindings != 0 || events != 0 || state == "consuming" || state == "finalized" {
				t.Fatal("denial retained effects", users, identifiers, credentials, bindings, events, state)
			}
		})
	}
}
