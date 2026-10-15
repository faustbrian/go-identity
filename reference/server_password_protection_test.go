package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestPasswordProtectionSelectionCannotDisappear(t *testing.T) {
	for _, c := range []StoreConfiguration{
		{HTTPPasswordVerification: &HTTPPasswordProtectionConfiguration{}},
		{HTTPPasswordChange: &HTTPPasswordProtectionConfiguration{}},
	} {
		if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
			t.Fatal("explicit protected password HTTP selection silently disappeared")
		}
	}
}

func TestPasswordProtectionCredentialSelection(t *testing.T) {
	original := HTTPPasswordProtectionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{"https://login.example"}}
	frozen, err := copyPasswordProtectionHTTP(&original, true)
	if err != nil {
		t.Fatal(err)
	}
	original.TrustedOrigins[0] = "https://changed.example"
	if frozen.TrustedOrigins[0] != "https://login.example" {
		t.Fatal("retained origin allowlist remained mutable")
	}
	for _, c := range []HTTPPasswordProtectionConfiguration{
		{},
		{Transport: session.CredentialCookie},
		{Transport: session.CredentialBearer, TrustedOrigins: []identityhttp.Origin{"https://login.example"}},
	} {
		if _, err := copyPasswordProtectionHTTP(&c, true); err == nil {
			t.Fatal("invalid credential channel accepted")
		}
	}
	if _, err := copyPasswordProtectionHTTP(&frozen, false); err == nil {
		t.Fatal("cookie channel without native CSRF custody accepted")
	}
}

func TestPasswordProtectionSelectedRoutes(t *testing.T) {
	c, d, f := serverFixture(t)
	selection := serverOTPSelection(t, c)
	p, err := composePreAuthHTTP(selection)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := composeHTTPRate(selection.HTTPRate, d.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.limiter.Close() })
	lookup, _ := session.NewDigestKey(1, bytes.Repeat([]byte{2}, 32))
	reader, err := sessionpg.NewSessionService(d.PostgreSQL, sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := passwordpg.NewRepository(d.PostgreSQL, passwordpg.Config{MaximumDuration: time.Second, HashPolicy: primitive.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	verifyRate, err := identityhttp.NewPasswordVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: rate.backend, Namespace: "unit-password-verify", Key: [32]byte{3}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { verifyRate.Close() })
	changeRate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: "unit-password-change", Key: [32]byte{4}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { changeRate.Close() })
	f.state.httpRate = rate
	f.state.features.httpPreAuth = p
	f.state.features.preauth = &session.PreAuthIssuer{}
	f.state.features.timeout = time.Second
	f.state.features.session = &sessionState{reader: reader, config: sessionpg.SignOutServiceConfig{Cookie: selection.OTP.Signin.Issuer.Cookie}}
	f.state.features.passwordVerification = &passwordVerificationState{bearer: &passwordpg.VerificationWorkflow{}, cookie: &passwordpg.CookieVerificationWorkflow{}, proofs: proofs}
	f.state.features.passwordChange = &passwordChangeState{bearer: &passwordpg.ChangeWorkflow{}, cookie: &passwordpg.CookieChangeWorkflow{}}
	h := HTTPPasswordProtectionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{"https://login.example"}}
	f.state.features.httpPasswordVerification = &passwordVerificationHTTPState{config: h, rate: verifyRate, now: time.Now, revision: 9}
	f.state.features.httpPasswordChange = &passwordChangeHTTPState{config: h, rate: changeRate, now: time.Now, revision: 9}
	server, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal("selected password protection server", err)
	}
	seen := map[string]bool{}
	for _, op := range server.OpenAPI().Operations() {
		seen[op.Record.OperationID] = true
	}
	if len(seen) != 5 || !seen["identity.password.verify"] || !seen["identity.password.change"] {
		t.Fatal("protected routes missing or duplicated")
	}
	for _, path := range []string{"/v1/password/verify", "/v1/password/change"} {
		r := httptest.NewRequest("POST", "https://login.example"+path, nil)
		r.RequestURI = path
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		var out struct {
			CommitOutcome string `json:"commitOutcome"`
			Error         string `json:"error"`
		}
		// The server-wide readiness gate precedes endpoint handling and exposes
		// only its generic unavailable response, never a mutation observation.
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommitOutcome != "" || out.Error != "unavailable" || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("uninitialized protected HTTP reached borrowed IO or lost neutral outcome", w.Code)
		}
	}
	f.state.features.httpPasswordVerification = nil
	server, err = NewServer(c, d, f)
	if err != nil || len(server.OpenAPI().Operations()) != 4 {
		t.Fatal("verification could not be independently disabled", err)
	}
	f.state.features.httpPasswordChange = nil
	server, err = NewServer(c, d, f)
	if err != nil || len(server.OpenAPI().Operations()) != 3 {
		t.Fatal("disabled protected HTTP retained metadata", err)
	}
}

func TestPasswordProtectionHTTPJoinsGraphLifetime(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &storeState{lifetime: lifetime, features: &featureState{composed: true, ready: true, timeout: time.Second}}
	server := Server{state: s}
	entered, finished := make(chan struct{}), make(chan struct{})
	h := server.guardPasswordProtectionLifetime(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }), "identity.password.change")
	go func() {
		defer close(finished)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "https://login.example/v1/password/change", nil))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("protected handler did not enter")
	}
	s.mu.Lock()
	active := s.active
	s.closed = true
	s.mu.Unlock()
	if active != 1 {
		t.Fatal("protected reader/proof IO not owned by graph drain")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("graph shutdown did not cancel protected HTTP")
	}
	s.mu.Lock()
	active = s.active
	s.mu.Unlock()
	if active != 0 {
		t.Fatal("protected HTTP leaked graph admission")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "https://login.example/v1/password/change", nil))
	var out passwordhttp.ChangeResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Changed || out.CommitOutcome != "none" {
		t.Fatal("closed graph admitted retained HTTP handle")
	}
}
