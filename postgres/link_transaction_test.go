package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestPreparedAccountLinkZeroHasNoExecutionAuthority(t *testing.T) {
	var prepared PreparedAccountLink
	var _ identity.LinkUnitOfWork = prepared
	if _, _, ok := prepared.Intent(); ok {
		t.Fatal("zero prepared link exposed execution intent")
	}
	if _, ok := prepared.Observation(); ok {
		t.Fatal("zero prepared link invented durable observation")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		out, err := prepared.WithinLink(ctx, identity.LinkCommand{}, identity.LinkParticipants{})
		if _, observed := out.Receipt(); err == nil || observed {
			t.Fatal("zero handle executed or invented a receipt")
		}
	}
	if raw, err := json.Marshal(prepared); err == nil || len(raw) != 0 {
		t.Fatal("prepared reservation serialized")
	}
}

func TestNativeAuthoritativeLinkerRequiresInvocationLocalWork(t *testing.T) {
	for _, linker := range []*accountLinkWriter{nil, {}} {
		var selected identity.AuthoritativeLinker = linker
		out, err := selected.ApplyLink(context.Background(), identity.LinkCommand{})
		if _, applied := out.Application(); err == nil || applied {
			t.Fatal("unbound writer applied a mutation")
		}
		if _, committed := out.Receipt(); committed {
			t.Fatal("writer fabricated durable commitment")
		}
	}
}

func TestPreparedAccountLinkMissingOwnerCannotPrepare(t *testing.T) {
	for _, owner := range []*AccountLinkUnitOfWork{nil, {}} {
		out, err := owner.PrepareLink(context.Background(), identity.Command{}, CommandPlan{})
		if _, _, ready := out.Intent(); err == nil || ready {
			t.Fatal("missing native composition prepared link authority")
		}
		if _, observed := out.Observation(); observed {
			t.Fatal("missing native owner invented durable outcome")
		}
	}
}

// This is an admission/custody test with an existing coordinator fixture. It
// deliberately supplies no SQL driver: expired, spent or substituted handoffs
// must fail before Begin. The reference journey separately proves real effects.
func TestPreparedAccountLinkPreservesDeadlineAndRejectsSubstitutionBeforeSQL(t *testing.T) {
	c, work, original, _ := accountLinkInvocationFixture(t)
	repository := &Repository{}
	owner := &AccountLinkUnitOfWork{coordinator: c, repository: repository}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))
	defer cancel()
	prepared, err := owner.reservedLink(ctx, Reservation{state: work.state.execution.reservation}, original)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	command, participants, ready := prepared.Intent()
	if !ready || !prepared.state.deadline.Equal(deadline) || !prepared.matches(command, participants) {
		t.Fatal("handoff changed original deadline or intent")
	}
	foreign, err := identity.NewLinkParticipants(&accountLinkWriter{repository: repository}, command.Contributors())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.matches(command, foreign) {
		t.Fatal("descriptor-equivalent foreign writer replaced the selected owner")
	}
	spec, counters, ok := original.AccountLinkCounterCommand()
	if !ok {
		t.Fatal("fixture lacks protected counters")
	}
	counters.Network = "192.0.2.201"
	bare, err := identity.NewAccountLinkCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := identity.NewAccountLinkCounterCommand(bare, counters)
	if err != nil {
		t.Fatal(err)
	}
	substitute, err := identity.NewLinkCommand(changed, identity.LinkPreserveExistingAccess, command.Contributors())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.matches(substitute, participants) {
		t.Fatal("changed protected attribution replaced original intent")
	}
	if _, err := participants.Linker().ApplyLink(ctx, command); err == nil {
		t.Fatal("projected unbound writer obtained transaction authority")
	}
	prepared.state.deadline = time.Now().Add(-time.Second)
	if _, err := prepared.WithinLink(context.Background(), command, participants); !errors.Is(err, context.DeadlineExceeded) || prepared.state.started.Load() {
		t.Fatal("expired preparation opened SQL or restarted its budget", err)
	}
	prepared.state.deadline = time.Now().Add(time.Second)
	prepared.state.started.Store(true)
	alias := prepared
	if _, err := alias.WithinLink(context.Background(), command, participants); err == nil {
		t.Fatal("a copy revived spent execution authority")
	}
}
