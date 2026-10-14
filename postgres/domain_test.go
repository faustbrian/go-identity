package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestDomainOwnershipRejectsZeroAndForeignHandles(t *testing.T) {
	c, command, _ := coordinatorFixture(t)
	if _, err := c.Begin(context.Background(), Reservation{}); err == nil {
		t.Fatal("zero reservation issued Work")
	}
	if _, err := c.Commit(Work{}, identity.CommandResult{}); err == nil {
		t.Fatal("zero Work committed")
	}
	if _, err := c.Abort(Work{}, identity.UnavailableError{}); err == nil {
		t.Fatal("zero Work aborted")
	}
	if _, err := (&Repository{}).ApplyUserCreation(context.Background(), Work{}, command); err == nil {
		t.Fatal("zero Work mutated domain")
	}
	if (&Repository{}).Descriptor() != (ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}) {
		t.Fatal("owned domain descriptor missing")
	}
}
