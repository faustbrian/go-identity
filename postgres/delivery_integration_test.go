//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This owned SQL seam proves coordinator atomicity, not delivery encryption,
// provider interoperability, or production adapter admission.
type deliverySQLPhase struct {
	mode     string
	retained Work
}

type deliveryAuditPhase struct{ domainAuditPhase }

func (*deliveryAuditPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_audits")
}

type deliveryLifecyclePhase struct {
	domainLifecyclePhase
	until time.Time
}

func (p *deliveryLifecyclePhase) PersistLifecycle(ctx context.Context, w Work) error {
	if err := p.domainLifecyclePhase.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	if !p.until.IsZero() {
		_, err := w.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp()))+0.001,0))`, p.until)
		return err
	}
	return nil
}

func (*deliveryLifecyclePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_lifecycle")
}

func (*deliverySQLPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.effects", Version: 1}
}
func (*deliverySQLPhase) ValidateDeliveryPlan(_ identity.CommandBinding, p DeliveryPlan) error {
	if !validDeliveryPlan(&p) {
		return invalidPlan()
	}
	return nil
}
func (p *deliverySQLPhase) PersistDelivery(ctx context.Context, w Work) error {
	p.retained = w
	b, plan, err := w.DeliveryScope(p)
	if err != nil {
		return err
	}
	if _, _, err := w.DeliveryScope(&deliverySQLPhase{}); err == nil {
		return invalidWork()
	}
	envelopes, err := w.StagedDelivery(p)
	if err != nil {
		return err
	}
	for i, intent := range plan.Intents {
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_delivery(command_id,effect_id,digest,ciphertext) VALUES($1,$2,$3,$4)`, string(b.CommandID), intent.EffectID, intent.IntentDigest[:], envelopes[i].Ciphertext); err != nil {
			return err
		}
	}
	switch p.mode {
	case "error":
		return identity.UnavailableError{}
	case "panic":
		panic("synthetic private delivery diagnostic")
	case "sql-error":
		_, err = w.Exec(ctx, "SELECT 1/0")
		return err
	}
	return nil
}
func (p *deliverySQLPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, _, err := w.DeliveryScope(p); err != nil {
		return RecoveryUnknown, err
	}
	if p.mode == "recovery-veto" {
		return RecoveryUnknown, nil
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_delivery")
}

func testDeliveryExecution(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	_, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE public.identity_test_delivery(command_id text UNIQUE NOT NULL,effect_id text PRIMARY KEY,digest bytea NOT NULL,ciphertext bytea NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "missing", "error", "panic", "sql-error", "later-failure", "expiry-after-persistence", "recovery-veto", "recovery-negative"} {
		t.Run(mode, func(t *testing.T) {
			delivery := &deliverySQLPhase{mode: mode}
			auditing := &deliveryAuditPhase{}
			lifecycle := &deliveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "later-failure"}}
			r, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, delivery})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, r, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}
			b := codecBinding()
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			b.UserID = identity.UserID(id)
			_, original, ap := auditFixture(t)
			record := changedAudit(t, original, func(in *audit.RecordInput) {
				in.Subject.ID = string(b.UserID)
				in.Attributes["command.id"] = string(b.CommandID)
				in.Attributes["aggregate.id"] = string(b.UserID)
				in.Changes = audit.ChangeSetInput{Redacted: true}
			}, "", true)
			ap.BindingDigest, err = AuditBindingDigest(b, record)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive})
			if err != nil {
				t.Fatal(err)
			}
			p, err := c.PrepareCommandPlan(b, command, CommandPlan{Contributors: r.Descriptors(), Audits: []AuditPlan{ap}, Lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, Delivery: &DeliveryPlan{Contributor: delivery.Descriptor(), Intents: []DeliveryIntentPlan{{EffectID: "effect-" + string(b.CommandID), IntentDigest: [32]byte{1}, Purpose: "verification", SubjectID: string(b.UserID), TemplateID: "verify", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)}}}})
			if err != nil {
				t.Fatal("original command delivery preparation", err)
			}
			if mode == "expiry-after-persistence" {
				p.Delivery.Intents[0].ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(100 * time.Millisecond)
				lifecycle.until = p.Delivery.Intents[0].ExpiresAt
				p, err = c.PrepareCommandPlan(b, command, p)
				if err != nil {
					t.Fatal(err)
				}
			}
			reservation, result, err := c.ReserveCommand(ctx, b, command, p)
			if err != nil || reservation.state == nil {
				t.Fatal("delivery reservation", err)
			}
			if mode == "recovery-veto" || mode == "recovery-negative" {
				id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				q, caller := queryInputs(b)
				observed, err := c.RecoverCommand(ctx, q, caller)
				if mode == "recovery-veto" {
					if err == nil || observed.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("delivery unknown did not veto noncommit", err)
					}
				} else {
					if observed.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("unanimous delivery negative recovery", err)
					}
				}
				var effects int
				if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_delivery WHERE command_id=$1`, string(b.CommandID)).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("recovery reissued delivery", err)
				}
				return
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			user, err := repo.ApplyUserCreation(ctx, w, command)
			if err != nil {
				t.Fatal(err)
			}
			now, err := w.DatabaseTime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			record = changedAudit(t, record, func(in *audit.RecordInput) { in.OccurredAt = now; in.Changes = audit.ChangeSetInput{Redacted: true} }, record.ID(), true)
			if err = w.StageAudit(0, record); err != nil {
				t.Fatal(err)
			}
			if err = w.StageLifecycle(0, now); err != nil {
				t.Fatal(err)
			}
			if mode != "missing" {
				if err = w.StageDelivery(DeliveryEnvelope{KeyID: "synthetic-key", Ciphertext: []byte{1, 2, 3}}); err != nil {
					t.Fatal(err)
				}
			}
			count := func(want int) {
				t.Helper()
				var u, d, a, l int
				err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE user_id=$1 AND tenant_id=$2),(SELECT count(*) FROM public.identity_test_delivery WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.UserID), string(b.TenantID), string(b.CommandID)).Scan(&u, &d, &a, &l)
				if err != nil || u != want || d != want || l != want || want == 1 && a != 1 {
					t.Fatalf("atomic original state %d/%d/%d/%d: %v", u, d, a, l, err)
				}
			}
			count(0)
			result, err = c.Commit(w, identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
			if mode == "success" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("delivery commit", err)
				}
				count(1)
				_, repeat, err := c.ReserveCommand(ctx, b, command, p)
				if err != nil || repeat.Outcome != identity.CommitOutcomeCommitted || repeat.Binding.CommandID != b.CommandID {
					t.Fatal("original replay", err)
				}
				count(1)
			} else {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("failed delivery committed original mutation")
				}
				count(0)
			}
			if _, _, err := delivery.retained.DeliveryScope(delivery); err == nil {
				t.Fatal("retained delivery invocation survived")
			}
		})
	}
}
