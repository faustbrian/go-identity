package emailhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Response custody is the unit boundary here; genuine native issuance is proven
// by the PostgreSQL/HTTPS reference journey, not by this transport-only fixture.
func TestVerificationChallengeResponseCommitment(t *testing.T) {
	for _, mode := range []string{"fresh", "expired", "cancelled", "failed-status", "unselected"} {
		t.Run(mode, func(t *testing.T) {
			p := &confirmationPipeline{pipeline: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				a := attemptFor(r)
				a.out.Confirmed = true
				a.out.CommitOutcome = "committed"
				a.out.Signin = &VerificationSigninResponse{ChallengeRequired: mode != "unselected", ChallengeID: "AAAAAAAAAAAAAAAAAAAAAQ", ChallengeMethod: "totp", ChallengeExpiresAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)}
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				a.ctx = ctx
				a.challenge = "synthetic-owned-child"
				a.deliveryFresh = func() bool { return mode != "expired" }
				if mode == "cancelled" {
					cancel()
				}
				w.Header()["x-mfa-token"] = []string{"middleware-injected"}
				w.Header().Set(http.TrailerPrefix+"X-MFA-Token", "middleware-trailer")
				w.Header().Set("Set-Cookie", "injected=session")
				status := http.StatusOK
				if mode == "failed-status" {
					status = http.StatusServiceUnavailable
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(a.out)
				w.Header().Set("x-mfa-token", "unwind-injected")
			})}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "https://app.test/v1/email/verification-confirm", nil)
			p.ServeHTTP(w, r)
			var out ConfirmationResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Confirmed || out.CommitOutcome != "committed" || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get(http.TrailerPrefix+"X-MFA-Token") != "" {
				t.Fatal("pending response lost known verification or disclosed unrelated credentials")
			}
			if mode == "fresh" {
				if w.Code != http.StatusOK || w.Result().Header.Get("X-MFA-Token") != "synthetic-owned-child" || out.Signin == nil || !out.Signin.ChallengeRequired {
					t.Fatal("fresh response lost exclusively owned pending credential")
				}
			} else if w.Result().Header.Get("X-MFA-Token") != "" || mode != "unselected" && (w.Code != http.StatusServiceUnavailable || out.Signin.ChallengeRequired || out.Signin.ChallengeID != "" || !out.Signin.ChallengeExpiresAt.IsZero()) {
				t.Fatal("expired, failed or unselected response disclosed a child or pending-success metadata")
			}
		})
	}
}
