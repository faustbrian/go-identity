package risk

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

type counterDeclarationReader interface {
	Declaration(CounterCommand) (CounterOutcome, []Counter, error)
}

func declarationFor(t *testing.T, result CounterResult, command CounterCommand) (CounterOutcome, []Counter, error) {
	t.Helper()
	reader, ok := any(result).(counterDeclarationReader)
	if !ok {
		t.Fatal("opaque native result has no command-bound journal declaration")
	}
	return reader.Declaration(command)
}

func TestCounterDeclarationConservesOriginalOutcomeWithoutFreshness(t *testing.T) {
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { panic("declaration dispatched effects") }))
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	c.state.clock = func() time.Time { return testContext().Now.Add(time.Hour) }
	reprepared, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	// A later public preparation must not replace the original snapshots.
	for _, outcome := range []CounterOutcome{CounterCommitted, CounterNotCommitted, CounterUnknown} {
		var original []Counter
		if outcome == CounterCommitted {
			original = snapshotFor(command, math.MaxUint64)
		}
		result, err := NewCounterResult(command, outcome, original)
		if err != nil {
			t.Fatal(err)
		}
		want := append([]Counter(nil), original...)
		if len(original) != 0 {
			original[0].Value = 0
		}
		// Projection is pure historical conservation, not a new authority read.
		c.state.clock = func() time.Time { panic("declaration sampled a new clock") }
		for _, selected := range []CounterCommand{command, reprepared} {
			got, snapshot, err := declarationFor(t, result, selected)
			if err != nil || got != outcome || !reflect.DeepEqual(snapshot, want) {
				t.Fatal("native declaration changed original outcome or snapshot", err)
			}
			if len(snapshot) != 0 {
				snapshot[0].Value = 0
				snapshot[0].ObservedAt = time.Time{}
			}
			_, retained, err := declarationFor(t, result, selected)
			if err != nil || !reflect.DeepEqual(retained, want) {
				t.Fatal("projection mutation changed retained result", err)
			}
		}
		var joined sync.WaitGroup
		for range 16 {
			joined.Go(func() {
				got, snapshot, err := declarationFor(t, result, command)
				if err != nil || got != outcome || !reflect.DeepEqual(snapshot, want) {
					t.Error("concurrent declaration changed", err)
				}
				if len(snapshot) != 0 {
					snapshot[0].Value = 0
				}
			})
		}
		joined.Wait()
	}
}

func TestCounterDeclarationRejectsZeroAndForeignLogicalCommand(t *testing.T) {
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { panic("declaration dispatched effects") }))
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewCounterResult(command, CounterCommitted, snapshotFor(command, 1))
	if err != nil {
		t.Fatal(err)
	}
	assertInvalid := func(result CounterResult, command CounterCommand) {
		t.Helper()
		outcome, snapshot, err := declarationFor(t, result, command)
		if !errors.Is(err, ErrInvalidCounterResult) || outcome != 0 || snapshot != nil {
			t.Fatal("invalid declaration exposed facts", err)
		}
	}
	assertInvalid(CounterResult{}, command)
	assertInvalid(result, CounterCommand{})
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Tenant += "-other" },
		func(c *Context, _ *Subject) { c.Attempt += "-other" },
		func(c *Context, _ *Subject) { c.Operation = "identity.otp.send" },
		func(_ *Context, s *Subject) { s.Network = "2001:db8::2" },
	} {
		scope, subject := testContext(), counterSubject()
		change(&scope, &subject)
		foreign, err := c.Prepare(scope, subject, BeforeCredential)
		if err != nil {
			t.Fatal(err)
		}
		assertInvalid(result, foreign)
	}
}
