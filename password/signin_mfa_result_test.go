package password_test

import (
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

func TestSigninChallengeCannotBecomeSessionOrRenewedHistory(t *testing.T) {
	r := signinResult(t, identity.CommitOutcomeCommitted)
	r.State = auth.SignInStateChallengeRequired
	r.SessionID = ""
	r.Issuance.Session = session.Session{}
	r.Issuance.Replayed = true
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r.Challenge = password.MFAChallengeResult{ID: id, Method: "totp", ExpiresAt: time.Date(2026, 10, 12, 17, 0, 0, 0, time.UTC)}
	if err := r.Validate(); err != nil {
		t.Fatal("valid proof-free committed challenge history denied", err)
	}
	for _, mutate := range []func(*password.SigninResult){
		func(r *password.SigninResult) { r.SessionID = "session" },
		func(r *password.SigninResult) { r.Issuance.Session = signinSession(t) },
		func(r *password.SigninResult) { r.State = auth.SignInStateAuthenticated },
		func(r *password.SigninResult) { r.Issuance.CommitOutcome = identity.CommitOutcomeUnknown },
		func(r *password.SigninResult) { r.Challenge.ID = "invalid" },
		func(r *password.SigninResult) { r.Challenge.Method = "password" },
		func(r *password.SigninResult) { r.Challenge.ExpiresAt = time.Time{} },
		func(r *password.SigninResult) { r.Challenge.ExpiresAt = r.Challenge.ExpiresAt.Add(time.Nanosecond) },
		func(r *password.SigninResult) { r.Issuance.Cookie.Name = "__Host-session" },
	} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("mixed or malformed challenge accepted")
		}
	}
}
