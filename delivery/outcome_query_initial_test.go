package delivery_test

import (
	"context"
	"errors"
	"github.com/faustbrian/go-identity/delivery"
	"strings"
	"testing"
	"time"
)

func TestOutcomeQueryInitialCursor(t *testing.T) {
	query := queryFixture()
	query.Checkpoint = ""
	executor, err := delivery.NewOutcomeQueryExecutor(time.Second, 1, outcomeQueryFunc(func(_ context.Context, got delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		if got != query {
			t.Fatal("initial cursor invented", got.Checkpoint)
		}
		return delivery.OutcomeObservation{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Query(context.Background(), query); err != nil {
		t.Fatal("first provider poll rejected", err)
	}
}

func TestOutcomeQueryCursorBounds(t *testing.T) {
	for _, cursor := range []string{"", "x", strings.Repeat("x", 512)} {
		query := queryFixture()
		query.Checkpoint = cursor
		if err := query.Validate(); err != nil {
			t.Fatal("valid cursor rejected", len(cursor), err)
		}
	}
	for _, cursor := range []string{strings.Repeat("x", 513), "\x00", "\n", "é"} {
		query := queryFixture()
		query.Checkpoint = cursor
		if err := query.Validate(); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("invalid provider cursor accepted", len(cursor), err)
		}
	}
}
