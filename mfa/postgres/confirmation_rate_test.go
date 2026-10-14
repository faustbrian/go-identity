package mfapostgres

import (
	"context"
	"github.com/faustbrian/go-identity/mfa"
	"testing"
)

func TestConfirmationRateSourceRejectsMissingOriginalCustody(t *testing.T) {
	for _, s := range []*TOTPConfirmationService{nil, {}} {
		lifetime, until, err := s.EnrollmentConfirmationRateSource(context.Background(), mfa.TotpVerifyRequest{})
		if err == nil || lifetime != 0 || !until.IsZero() {
			t.Fatal("missing source supplied confirmation authority")
		}
	}
}
