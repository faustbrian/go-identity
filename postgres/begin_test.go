package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestBeginNilInputs(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		fence, err := beginJournal(ctx, nil, claimRequest{}, claimKeys{}, journalReservation{}, [16]byte{})
		var invalid identity.InvalidInputError
		if fence != (journalWorkFence{}) || !errors.As(err, &invalid) || invalid.Field != "command_begin" {
			t.Fatal("nil begin admitted authority")
		}
	}
}
