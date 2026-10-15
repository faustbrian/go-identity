package emailhttp_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

func TestNativeDenialWithoutReceiptDoesNotBecomeOutageOrRollback(t *testing.T) {
	for _, mode := range []string{"denied", "malformed-commit"} {
		t.Run(mode, func(t *testing.T) {
			c, native, body := fixture(t)
			native.result = func(email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
				out := email.VerificationConfirmResult{}
				if mode == "malformed-commit" {
					out.Outcome = identity.CommitOutcomeCommitted
				}
				return out, identity.ForbiddenError{}
			}
			h, err := emailhttp.NewConfirmationHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(body))
			want, outcome := 403, "unknown"
			if mode == "malformed-commit" {
				want, outcome = 503, "committed"
			}
			var out emailhttp.ConfirmationResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != want || out.CommitOutcome != outcome || out.Confirmed || out.Address != nil || out.Recovery != nil || len(w.Result().Cookies()) != 0 {
				t.Fatal("native denial forged a receipt, rollback or outage", w.Code, out.CommitOutcome)
			}
		})
	}
}
