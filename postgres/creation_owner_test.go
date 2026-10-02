package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestCreationOwnerRejectsInvalidComposition(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	for _, candidate := range []*Coordinator{nil, {}, c} {
		owner, err := NewCreationUnitOfWork(candidate, &Repository{}, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
		if owner != nil || err == nil {
			t.Fatal("unowned repository or coordinator admitted")
		}
	}
	var owner *CreationUnitOfWork
	if _, err := owner.Execute(context.Background(), identity.Command{}); err == nil {
		t.Fatal("zero owner executed")
	}
	if _, err := owner.Recover(context.Background(), identity.RecoveryQuery{}); err == nil {
		t.Fatal("zero owner recovered")
	}
}

func TestCreationOwnerReceiptAndAuditBoundary(t *testing.T) {
	b := codecBinding()
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeConflict, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeInProgress, identity.CommitOutcomeUnknown} {
		r := identity.CommandResult{Binding: b, Outcome: outcome}
		if outcome == identity.CommitOutcomeInProgress {
			r.RetryAfter = time.Microsecond
		}
		got, e := coreCreationReceipt(r, identity.UnavailableError{})
		if got != r || (e != nil) != (outcome == identity.CommitOutcomeUnknown) {
			t.Fatal("authoritative outcome adaptation changed", outcome)
		}
	}
	for _, class := range []string{"committed", "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		r, e := creationAudit(context.Background(), b, time.Now().UTC().Truncate(time.Microsecond), class)
		if e != nil || !validKernelAuditRecord(r) {
			t.Fatal("owned audit violates mandatory privacy profile", class, e)
		}
		if _, e := AuditBindingDigest(b, r); e != nil {
			t.Fatal(e)
		}
		if class == "committed" && !r.Changes().Redacted() || class != "committed" && !r.Changes().NoChange() {
			t.Fatal("failure claimed a mutation")
		}
	}
	unsupported := b
	unsupported.ActorKind = "apikey"
	if _, e := creationAudit(context.Background(), unsupported, time.Now().UTC(), "committed"); e == nil {
		t.Fatal("unsupported actor silently coerced")
	}
	if _, e := creationAudit(context.Background(), b, time.Now().UTC(), "invented"); e == nil {
		t.Fatal("unknown failure classification admitted")
	}
	owner := CreationUnitOfWork{}
	if fmt.Sprintf("%#v", owner) != "postgres.CreationUnitOfWork(redacted)" {
		t.Fatal("runtime composition exposed")
	}
	if body, e := json.Marshal(owner); e == nil || len(body) != 0 {
		t.Fatal("runtime owner serialized")
	}
}
