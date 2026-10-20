package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPhoneResetMetadataRequiresOriginalCustody(t *testing.T) {
	for _, owner := range []*PhonePasswordResetIssuer{nil, {}, {read: func() *phonePasswordResetIssuer { panic("controlled owner failure") }}} {
		ctx, stop := context.WithCancel(context.Background())
		stop()
		for _, caller := range []context.Context{nil, context.Background(), ctx} {
			id, at, until, err := owner.ReadOriginalMetadata(caller, identity.Command{}, PhonePasswordResetMetadataInput{}, 1, nil)
			if err == nil || id != "" || !at.IsZero() || !until.IsZero() {
				t.Fatal("missing original custody disclosed partial metadata")
			}
			if caller == ctx && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost before configured owner", err)
			}
		}
	}
}
