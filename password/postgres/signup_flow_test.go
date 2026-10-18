package passwordpostgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

func nativeSignupFlow(t testing.TB) (password.SignupRequest, session.PreAuthTransaction, session.DigestKey, time.Time) {
	t.Helper()
	r, old, key, now := nativeSigninFlow(t)
	s, _ := old.Bindings()
	s.Binding.Intent.Action = "identity.password.signup"
	token, _ := session.ParseToken(r.Cookie.Token())
	s.Cookie, _ = token.PreAuthDigest(key, s.Binding)
	flow, err := session.NewPreAuthTransaction(s)
	if err != nil {
		t.Fatal(err)
	}
	r.Caller.Request.Action = "identity.password.signup"
	r.Caller.Request.Resource.ID = "identity.password.signup"
	return password.SignupRequest{TenantID: r.TenantID, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Email: "person@example.test", Password: r.Password, RememberPolicy: r.Remember, Origin: r.Origin, CallbackURL: r.CallbackURL, Caller: r.Caller, Network: r.Network}, flow, key, now
}

func TestUsernameSignupFlowRetainsDistinctOriginalAction(t *testing.T) {
	r, legacy, key, now := nativeSignupFlow(t)
	r.Username = "Straße"
	r.Caller.Request.Action, r.Caller.Request.Resource.ID = "identity.username.signup", "identity.username.signup"
	s, _ := legacy.Bindings()
	s.Binding.Intent.Action = "identity.username.signup"
	token, _ := session.ParseToken(r.Cookie.Token())
	s.Cookie, _ = token.PreAuthDigest(key, s.Binding)
	flow, err := session.NewPreAuthTransaction(s)
	if err != nil || (&Repository{}).admitSignupFlow(r, flow, key, "login", 3, now) != nil {
		t.Fatal("original username flow cannot enter existing native signup", err)
	}
	if (&Repository{}).admitSignupFlow(r, legacy, key, "login", 3, now) == nil {
		t.Fatal("username signup relabeled a password origin")
	}
	r.Username = ""
	if (&Repository{}).admitSignupFlow(r, flow, key, "login", 3, now) == nil {
		t.Fatal("password signup borrowed a username origin")
	}
}

// SU04: exact original possession and intent must survive every continuation;
// no signup input may reuse a signin flow or renew the original timeline.
func TestSignupFlowRequiresOriginalPossessionAndIntent(t *testing.T) {
	owner := &Repository{}
	r, flow, key, now := nativeSignupFlow(t)
	if err := owner.admitSignupFlow(r, flow, key, "login", 3, now); err != nil {
		t.Fatal("original signup flow denied")
	}
	for _, mutate := range []func(*password.SignupRequest){
		func(r *password.SignupRequest) { r.TenantID = "foreign" },
		func(r *password.SignupRequest) { r.PreAuthID = "AgICAgICAgICAgICAgICAg" },
		func(r *password.SignupRequest) { r.Origin = "https://foreign.test" },
		func(r *password.SignupRequest) { r.CallbackURL = "" },
		func(r *password.SignupRequest) {
			r.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32)))
		},
		func(r *password.SignupRequest) {
			r.RememberPolicy, _ = session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		},
	} {
		bad := r
		mutate(&bad)
		if owner.admitSignupFlow(bad, flow, key, "login", 3, now) == nil {
			t.Fatal("substituted original signup intent admitted")
		}
	}
	_, signin, _, _ := nativeSigninFlow(t)
	wrong, _ := session.NewDigestKey(1, bytes.Repeat([]byte{98}, 32))
	if owner.admitSignupFlow(r, signin, key, "login", 3, now) == nil || owner.admitSignupFlow(r, flow, wrong, "login", 3, now) == nil || owner.admitSignupFlow(r, flow, key, "foreign", 3, now) == nil || owner.admitSignupFlow(r, flow, key, "login", 4, now) == nil || owner.admitSignupFlow(r, session.PreAuthTransaction{}, key, "login", 3, now) == nil {
		t.Fatal("foreign action/key/policy or missing original admitted")
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(5 * time.Minute), now.Add(6 * time.Minute)} {
		if owner.admitSignupFlow(r, flow, key, "login", 3, at) == nil {
			t.Fatal("original signup timeline renewed")
		}
	}
	if owner.admitSignupFlow(r, flow, key, "login", 3, now.Add(5*time.Minute-time.Microsecond)) != nil {
		t.Fatal("exclusive original expiry denied early")
	}
}
