//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This SQL feature seam proves the kernel's one-use/effect transaction. Real
// capability verification, session persistence and public login composition
// remain separate consumer obligations; this fixture grants none of those.
type magicLinkConsumptionPhase struct {
	expected              identity.Command
	proof                 CapabilityPlan
	failApply, failCommit bool
	retained              Work
}

func (*magicLinkConsumptionPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}
func (*magicLinkConsumptionPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{magicLinkConsumeOperation()}
}
func (p *magicLinkConsumptionPhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.expected {
		return invalidPlan()
	}
	return nil
}
func (p *magicLinkConsumptionPhase) ValidateMagicLinkConsumption(c identity.Command, proof CapabilityPlan) error {
	if c != p.expected || proof != p.proof {
		return invalidPlan()
	}
	return nil
}
func (p *magicLinkConsumptionPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, err := w.MagicLinkConsumption(p)
	if err != nil || b.Plan != p.proof {
		return identity.FeatureReceipt{}, invalidWork()
	}
	// A foreign invocation cannot borrow the legitimate owner's one-use input.
	if _, err := w.MagicLinkConsumption(&magicLinkConsumptionPhase{}); err == nil {
		return identity.FeatureReceipt{}, invalidWork()
	}
	p.retained = w
	n, err := w.Exec(ctx, `INSERT INTO public.identity_test_magic_consumption(command_id,tenant_id,proof_id) VALUES($1,$2,$3)`, string(b.Command.CommandID), string(b.Command.TenantID), b.Plan.CapabilityID)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: magicLinkConsumeOperation()}, nil
}
func (p *magicLinkConsumptionPhase) CheckFeatureCommit(ctx context.Context, w Work, _ identity.Command) error {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if _, err := w.MagicLinkConsumption(p); err == nil {
		return invalidWork()
	}
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (*magicLinkConsumptionPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_magic_consumption")
}

func testMagicLinkConsumption(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_magic_consumption(command_id text PRIMARY KEY,tenant_id text NOT NULL,proof_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "apply-denied", "commit-denied", "audit-failure", "outbox-failure", "finalize-failure", "counter-denied", "competing-command", "expired-after-reservation"} {
		t.Run(mode, func(t *testing.T) {
			b, plan := magicLinkConsumptionPlanFixture(t)
			var err error
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			plan.Capability.CapabilityID = "magic-consume-" + mode
			if mode == "expired-after-reservation" {
				plan.Capability.ExpiresAt = time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
			}
			native := &magicLinkConsumptionPhase{proof: *plan.Capability, failApply: mode == "apply-denied", failCommit: mode == "commit-denied"}
			auditing := &recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}
			lifecycle := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			counters := &emailVerificationCounterPhase{deny: mode == "counter-denied"}
			cap := &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-failure"}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, native, counters, cap})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: plan.Capability.CapabilityID}}}})
			native.expected = command
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
				t.Fatal("consumption plan", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), string(plan.Capability.Purpose), plan.Capability.CapabilityID, plan.Capability.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			r, _, err := c.ReserveCommand(ctx, b, command, plan)
			if mode == "counter-denied" {
				if err == nil || r.state != nil {
					t.Fatal("denied counters obtained reservation")
				}
			} else {
				if err != nil {
					t.Fatal("consume reserve", err)
				}
				if mode == "competing-command" {
					other := b
					other.CommandID, err = identity.NewCommandID()
					if err != nil {
						t.Fatal(err)
					}
					s, _ := command.Feature()
					s.Binding = other
					second := featureCodecCommand(t, s)
					native.expected = second
					otherPlan := plan
					seed, err := securityMutationAudit(ctx, other, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, other.AnonymousFlowID, "protected", true)
					if err != nil {
						t.Fatal(err)
					}
					otherPlan.Audits = append([]AuditPlan(nil), plan.Audits...)
					otherPlan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(other, magicLinkConsumeOperation(), plan.SubjectType, seed)
					if err != nil {
						t.Fatal(err)
					}
					otherPlan, err = c.PrepareCommandPlan(other, second, otherPlan)
					if err != nil {
						t.Fatal(err)
					}
					if got, _, err := c.ReserveCommand(ctx, other, second, otherPlan); err == nil || got.state != nil {
						t.Fatal("same proof admitted competing command")
					}
					native.expected = command
				}
				if mode == "expired-after-reservation" {
					// Wait on the primary clock, without changing original expiry or
					// reservation identity. A live lease cannot renew the token.
					if _, err := pool.Raw().Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.01)`, plan.Capability.ExpiresAt); err != nil {
						t.Fatal(err)
					}
				}
				w, err := c.Begin(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Abort(w, identity.UnavailableError{})
				result, err := c.ApplyFeature(ctx, w, command)
				if err == nil {
					result, err = c.Commit(w, result)
				}
				if mode == "commit" || mode == "competing-command" {
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("login effect did not commit atomically", err)
					}
					replayReservation, replay, err := c.ReserveCommand(ctx, b, command, plan)
					if err != nil || replayReservation.state != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Binding != b {
						t.Fatal("lost committed replay", err)
					}
				} else {
					if err == nil {
						t.Fatal("denial committed login")
					}
					_, _ = c.Abort(w, err)
				}
				if _, err := native.retained.MagicLinkConsumption(native); err == nil {
					t.Fatal("returned invocation retained consuming custody")
				}
			}
			var effect, audits, events int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_magic_consumption WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1),(SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$2)`, string(b.CommandID), plan.Capability.CapabilityID).Scan(&effect, &audits, &events, &state); err != nil {
				t.Fatal(err)
			}
			if mode == "commit" || mode == "competing-command" {
				if effect != 1 || audits != 1 || events != 1 || state != "finalized" {
					t.Fatal("split successful transaction", effect, audits, events, state)
				}
			} else if effect != 0 || events != 0 || state == "consuming" || state == "finalized" {
				t.Fatal("denial retained protected effects", effect, audits, events, state)
			}
		})
	}
}
