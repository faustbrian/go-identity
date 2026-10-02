package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func coordinatorFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	_, _, ap := auditFixture(t)
	domain := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	auditing := ContributorDescriptor{Owner: "audit/postgres", ContractID: "audit.records", Version: 1}
	outbox := ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
	registry, err := NewContributorRegistry([]Contributor{&registryContributor{domain}, &planAuditContributor{registryContributor{auditing}}, &planLifecycleContributor{registryContributor{outbox}}})
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{registry: registry, maximumDuration: time.Second, leaseDuration: time.Second, keys: claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}}
	plan := CommandPlan{Contributors: registry.Descriptors(), Audits: []AuditPlan{ap}, Lifecycle: &LifecyclePlan{EventType: "identity.created.v1", AfterVersion: 1}}
	return c, codecCreation(t, nil), plan
}

// A narrow driver closure seam verifies conservative outcome policy. Real
// PostgreSQL tests separately prove actual rollback and commit failures.
type rollbackClosureTx struct {
	pgx.Tx
	failure error
}

func (tx rollbackClosureTx) Rollback(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return errors.New("cleanup context invalid")
	}
	return tx.failure
}

func TestReservationRollbackRequiresProof(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	known := identity.CommandResult{Binding: codecBinding(), Outcome: identity.CommitOutcomeConflict}
	for _, failure := range []error{nil, errors.New("private driver diagnostic")} {
		r, result, err := c.failedReservation(rollbackClosureTx{failure: failure}, codecBinding(), known, identity.ConflictError{})
		if r.state != nil {
			t.Fatal("failed closure issued ownership")
		}
		if failure == nil {
			var conflict identity.ConflictError
			if result.Outcome != known.Outcome || !errors.As(err, &conflict) {
				t.Fatal("proven rollback lost observation")
			}
		} else {
			var unavailable identity.UnavailableError
			if result.Outcome != identity.CommitOutcomeUnknown || !errors.As(err, &unavailable) || strings.Contains(err.Error(), "private") {
				t.Fatal("unproven rollback forged outcome")
			}
		}
	}
}

func TestCoordinatorPreparesOwnedPlanAndRejectsChangedBinding(t *testing.T) {
	c, command, plan := coordinatorFixture(t)
	prepared, err := c.PrepareCommandPlan(codecBinding(), command, plan)
	if err != nil || prepared.Digest == ([32]byte{}) {
		t.Fatal("typed plan not prepared", err)
	}
	original := prepared.Digest
	plan.Contributors[0] = ContributorDescriptor{}
	plan.Audits[0].MaxRecordBytes = 1
	plan.Lifecycle.AfterVersion = 9
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := KernelPlanDigest(codecBinding(), claimFingerprint([32]byte{1}, q.canonical), prepared)
	if err != nil || expected != original {
		t.Fatal("caller changed owned plan")
	}
	binding := codecBinding()
	binding.ActorID = "other-actor"
	if _, err := c.PrepareCommandPlan(binding, command, prepared); err == nil {
		t.Fatal("foreign binding admitted")
	}
	prepared.Lifecycle = nil
	prepared.Contributors = prepared.Contributors[:2]
	if _, err := c.PrepareCommandPlan(codecBinding(), command, prepared); err == nil {
		t.Fatal("audit-only public admission")
	}
}

func TestCoordinatorInvalidAndSecretSurfaces(t *testing.T) {
	c, command, plan := coordinatorFixture(t)
	if _, err := NewCoordinator(nil, c.registry, CoordinatorConfig{}); err == nil {
		t.Fatal("nil pool admitted")
	}
	var zero Coordinator
	if _, err := zero.PrepareCommandPlan(codecBinding(), command, plan); err == nil {
		t.Fatal("zero coordinator admitted")
	}
	if _, _, err := c.ReserveCommand(nil, codecBinding(), command, plan); err == nil {
		t.Fatal("nil context admitted")
	}
	cfg := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1, 2, 3}}}
	if _, err := json.Marshal(cfg); err == nil {
		t.Fatal("configuration leaked keys")
	}
	if strings.Contains(fmt.Sprintf("%#v", cfg), "RetainedFingerprintKeys") {
		t.Fatal("formatter exposed keys")
	}
	for _, value := range []any{c, *c} {
		if fmt.Sprintf("%#v", value) != "postgres.Coordinator(redacted)" {
			t.Fatal("coordinator exposed secret keys")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("coordinator serialized secret keys")
		}
	}
	var reservation Reservation
	if _, err := json.Marshal(reservation); err == nil {
		t.Fatal("reservation serialized")
	}
	if fmt.Sprintf("%#v", reservation) != "postgres.Reservation(redacted)" {
		t.Fatal("reservation exposed authority")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prepared, err := c.PrepareCommandPlan(codecBinding(), command, plan)
	if err != nil {
		t.Fatal(err)
	}
	if r, result, err := c.ReserveCommand(ctx, codecBinding(), command, prepared); err == nil || r.state != nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("cancelled admission fabricated outcome")
	}
}
