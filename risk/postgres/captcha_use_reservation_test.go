package postgres

import (
	"context"
	"testing"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

var _ identitypostgres.CaptchaUseReservationContributor = (*Repository)(nil)

func TestCaptchaUseReservationRejectsUnownedHandles(t *testing.T) {
	for _, r := range []*Repository{nil, {}, {schema: "risk_store"}} {
		for _, f := range []func(context.Context, identitypostgres.CaptchaUseReservationWork) error{r.ReserveCaptchaEvidence, r.RebindCaptchaEvidence} {
			if err := f(context.Background(), identitypostgres.CaptchaUseReservationWork{}); err == nil {
				t.Fatal("zero native consuming handle admitted")
			}
			if err := f(nil, identitypostgres.CaptchaUseReservationWork{}); err == nil {
				t.Fatal("nil context admitted")
			}
		}
	}
}
