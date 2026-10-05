//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This owned SQL phase proves coordinator atomicity and invocation custody,
// not the forthcoming capability-owned producer, encrypted delivery adapter,
// or an end-user verification workflow. No issued seed rows stand in for writes.
type issuanceSQLPhase struct {
	mode        string
	retained    CapabilityIssuanceWork
	observe     func()
	invocations int
}

func (*issuanceSQLPhase) Descriptor() ContributorDescriptor { return issuanceTestPlan().Contributor }
func (*issuanceSQLPhase) ValidateCapabilityIssuance(_ identity.CommandBinding, p CapabilityIssuancePlan) error {
	if !validCapabilityIssuancePlan(&p) {
		return invalidPlan()
	}
	return nil
}
func (p *issuanceSQLPhase) PersistCapabilityIssuance(ctx context.Context, w CapabilityIssuanceWork) error {
	p.retained, p.invocations = w, p.invocations+1
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if _, err := w.Binding(&issuanceSQLPhase{}); err == nil {
		return invalidWork()
	}
	grants, err := w.Grants(p)
	if err != nil || len(grants) != len(b.Plan.Grants) {
		return invalidWork()
	}
	for i, g := range b.Plan.Grants {
		if grants[i].Payload().ID != g.CapabilityID {
			return invalidWork()
		}
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_issuance(command_id,capability_id,proof_fingerprint,replay_digest,generation) VALUES($1,$2,$3,$4,$5)`, string(b.Command.CommandID), g.CapabilityID, g.ProofFingerprint[:], g.ReplayDigest[:], b.Generation); err != nil {
			return err
		}
	}
	if p.observe != nil {
		p.observe()
	}
	if p.mode == "error" {
		return identity.UnavailableError{}
	}
	if p.mode == "panic" {
		panic("synthetic private issuance diagnostic")
	}
	return nil
}
func (p *issuanceSQLPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, err := w.CapabilityIssuanceBinding(p); err != nil {
		return RecoveryUnknown, err
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_issuance")
}

func testIssuanceExecution(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	_, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "missing", "error", "panic", "later-failure", "expiry-after-persistence", "wrong-subject", "wrong-tenant", "wrong-id", "wrong-purpose", "wrong-max-uses", "wrong-expiry", "zero-grant", "foreign-owner", "duplicate-stage"} {
		t.Run(mode, func(t *testing.T) {
			owner := &issuanceSQLPhase{mode: mode}
			auditing := &deliveryAuditPhase{}
			lifecycle := &deliveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "later-failure"}}
			r, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, owner})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, r, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
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
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, err := capability.NewHMACSHA256Signer("test-key", key)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(key)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			expires := now.Add(time.Hour)
			if mode == "expiry-after-persistence" {
				expires = now.Add(2 * time.Second)
				lifecycle.until = expires
			}
			payload := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: string(b.UserID), Resource: "identifier-verification", Operation: "identity.identifier.verify", IssuedAt: now, NotBefore: now, ExpiresAt: expires, ID: string(b.CommandID), Tenant: string(b.TenantID), MaxUses: 1}
			if mode == "wrong-subject" {
				payload.Subject = "different-subject"
			}
			switch mode {
			case "wrong-tenant":
				payload.Tenant = "different-tenant"
			case "wrong-id":
				payload.ID = "different-id"
			case "wrong-purpose":
				payload.Operation = "identity.identifier.attach"
			case "wrong-max-uses":
				payload.MaxUses = 2
			case "wrong-expiry":
				payload.ExpiresAt = expires.Add(time.Second)
			}
			token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			grant, err := capability.Verify(ctx, token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
				return capability.ResolvedKey{Verifier: verifier}, nil
			}), capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "zero-grant" {
				grant = capability.Grant{}
			}
			issue := issuanceTestPlan()
			issue.Grants[0].CapabilityID, issue.Grants[0].ExpiresAt, issue.Grants[0].ProofFingerprint = string(b.CommandID), expires, sha256.Sum256([]byte(token))
			p, err := c.PrepareCommandPlan(b, command, CommandPlan{Contributors: r.Descriptors(), Audits: []AuditPlan{ap}, Lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}, CapabilityIssuance: issue})
			if err != nil {
				t.Fatal("issuance preparation", err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, command, p)
			if err != nil || reservation.state == nil {
				t.Fatal("issuance reservation", err)
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
			primary, err := w.DatabaseTime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			record = changedAudit(t, record, func(in *audit.RecordInput) {
				in.OccurredAt = primary
				in.Changes = audit.ChangeSetInput{Redacted: true}
			}, record.ID(), true)
			if err = w.StageAudit(0, record); err != nil {
				t.Fatal(err)
			}
			if err = w.StageLifecycle(0, primary); err != nil {
				t.Fatal(err)
			}
			count := func(want int) {
				t.Helper()
				var u, i, a, l int
				err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE user_id=$1 AND tenant_id=$2),(SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.UserID), string(b.TenantID), string(b.CommandID)).Scan(&u, &i, &a, &l)
				if err != nil || u != want || i != want || a != want || l != want {
					t.Fatalf("atomic issuance state %d/%d/%d/%d: %v", u, i, a, l, err)
				}
			}
			owner.observe = func() { count(0) }
			if mode == "foreign-owner" {
				if err = w.StageCapabilityIssuanceFor(&issuanceSQLPhase{}, 0, grant); err == nil {
					t.Fatal("foreign issuer accepted")
				}
			}
			if mode != "missing" {
				err = w.StageCapabilityIssuanceFor(owner, 0, grant)
				if strings.HasPrefix(mode, "wrong-") || mode == "zero-grant" {
					if err == nil {
						t.Fatal("foreign subject accepted")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "duplicate-stage" {
				if err = w.StageCapabilityIssuanceFor(owner, 0, grant); err == nil {
					t.Fatal("duplicate staged")
				}
			}
			result, err := c.Commit(w, identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: record.ID()})
			if mode == "success" || mode == "foreign-owner" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("issuance commit", err)
				}
				count(1)
				_, replay, err := c.ReserveCommand(ctx, b, command, p)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || owner.invocations != 1 {
					t.Fatal("replay issued another capability", err)
				}
			} else {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("failed issuance committed")
				}
				count(0)
			}
			if _, err := owner.retained.Binding(owner); err == nil {
				t.Fatal("retained issuance invocation survived")
			}
			if _, err := owner.retained.Exec(ctx, "SELECT 1"); err == nil {
				t.Fatal("retained phase retained SQL authority")
			}
		})
	}
}
