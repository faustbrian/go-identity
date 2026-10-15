package mfapostgres

import (
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestFactorVerificationSourceCannotReadWithoutNativePrimary(t *testing.T) {
	if source, err := NewFactorVerificationSource(nil, time.Second); err == nil || source != nil {
		t.Fatal("absent primary resource admitted proof source")
	}
	for _, source := range []*FactorVerificationSource{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			record, err := source.Reauthentication(ctx, "AAAAAAAAAAAAAAAAAAAAAQ")
			if err == nil || record.Proof != (auth.ReauthenticationProof{}) || len(record.Signature) != 0 {
				t.Fatal("missing source fabricated signed factor evidence")
			}
		}
	}
}
