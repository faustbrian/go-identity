package mfapostgres

import (
	"context"
	"github.com/faustbrian/go-identity/mfa"
	"testing"
)

func TestURIRateSourceRejectsMissingNativeCustody(t *testing.T) {
	for _, source := range []*TOTPURIService{nil, {}} {
		if duration, until, err := source.TotpUriRateSource(context.Background(), mfa.TotpUriRequest{}); err == nil || duration != 0 || !until.IsZero() {
			t.Fatal("missing native source disclosed challenge quota")
		}
	}
}
