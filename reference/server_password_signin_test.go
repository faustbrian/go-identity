package reference

import (
	"testing"
	"time"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func TestPasswordSigninSelectedServerRoutes(t *testing.T) {
	c, d, f := serverFixture(t)
	selection := serverOTPSelection(t, c)
	selection.HTTPEmailSignin = nil
	p, err := composePreAuthHTTP(selection)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := composeHTTPRate(selection.HTTPRate, d.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.limiter.Close() })
	query := kernel.CommandQueryPolicy{Authorization: c.Policies.Authorize, PolicyVersion: 9}
	selection.PasswordSignin = &PasswordSigninConfiguration{Native: passwordpg.SigninConfig{Coordinator: kernel.CoordinatorConfig{QueryPolicy: &query, AdmissionPolicy: &query}, PolicyID: "password-login", Issuance: session.IssuerConfig{Cookie: selection.OTP.Signin.Issuer.Cookie}, Profile: sessionpg.IdentifierAdmissionConfig{Audience: "service-a"}}, PreAuth: &PasswordPreAuthConfiguration{ActorID: "operator", Origin: "https://login.example", CallbackURL: "https://login.example/after", FlowTTL: 5 * time.Minute, Cookie: p.deployment.Cookie}}
	selection.HTTPPasswordSignin = &HTTPPasswordSigninConfiguration{ActorID: "operator", PolicyRevision: 9}
	h, err := composePasswordSigninHTTP(selection, p)
	if err != nil || h == nil {
		t.Fatal("selected password HTTP config unavailable", err)
	}
	f.state.httpRate = rate
	f.state.features.httpPreAuth = p
	f.state.features.preauth = &session.PreAuthIssuer{}
	f.state.features.passwordPreauth = &session.PreAuthIssuer{}
	f.state.features.passwordSignin = &passwordpg.SigninService{}
	f.state.features.httpPasswordSignin = h
	f.state.features.timeout = time.Second
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal("selected server cannot compose password route", err)
	}
	seen := map[string]bool{}
	for _, op := range s.OpenAPI().Operations() {
		seen[op.Record.OperationID] = true
	}
	if !seen["identity.password.signin"] || !seen["identity.session.preauth-issue"] || len(seen) != 4 {
		t.Fatal("password route omitted or unrelated route selected")
	}
	f.state.features.httpPasswordSignin = nil
	s, err = NewServer(c, d, f)
	if err != nil || len(s.OpenAPI().Operations()) != 3 {
		t.Fatal("disabled password HTTP retained route", err)
	}
	if h, err := composePasswordSigninHTTP(StoreConfiguration{}, nil); err != nil || h != nil {
		t.Fatal("unselected password HTTP acquired dependencies", err)
	}
	for _, mutate := range []func(*StoreConfiguration){
		func(s *StoreConfiguration) { s.PasswordSignin = nil },
		func(s *StoreConfiguration) { s.PasswordSignin.PreAuth = nil },
		func(s *StoreConfiguration) { s.HTTPRate = nil },
		func(s *StoreConfiguration) { s.HTTPPasswordSignin.PolicyRevision = 8 },
		func(s *StoreConfiguration) { s.HTTPPasswordSignin.ActorID = "" },
	} {
		x := selection
		n := *selection.PasswordSignin
		x.PasswordSignin = &n
		config := *selection.HTTPPasswordSignin
		x.HTTPPasswordSignin = &config
		mutate(&x)
		if h, err := composePasswordSigninHTTP(x, p); err == nil || h != nil {
			t.Fatal("incompatible native graph exposed password HTTP")
		}
	}
}
