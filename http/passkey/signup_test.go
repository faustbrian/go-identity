package passkeyhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passkey "github.com/faustbrian/go-passkey"
)

// This double only denies native work. Real signup and session delivery are
// exercised by the PostgreSQL Reference journey, not fabricated at this port.
type deniedSignup struct {
	options, sources, completions int
	last                          passkey.KeyedSignupOptionsRequest
	source                        passkey.CeremonyRateSource
	afterSource                   func()
}

func (s *deniedSignup) KeyedSignupOptions(_ context.Context, r passkey.KeyedSignupOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error) {
	s.options++
	s.last = r
	return passkey.KeyedRegistrationOptionsResult{}, identity.ForbiddenError{}
}
func (s *deniedSignup) SignupRateSource(context.Context, passkey.SignupCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	s.sources++
	if s.afterSource != nil {
		s.afterSource()
	}
	return s.source, nil
}
func (s *deniedSignup) Signup(context.Context, passkey.SignupCompletion) (passkey.SignupResult, error) {
	s.completions++
	return passkey.SignupResult{}, identity.ForbiddenError{}
}

func signupFixture(t *testing.T) (SignupConfig, *deniedSignup, *http.Cookie, *http.Cookie) {
	t.Helper()
	c, _, flow, device := signinFixture(t)
	owner := &deniedSignup{}
	return SignupConfig{Network: c.Network, Service: owner, OptionsRate: c.OptionsRate, VerificationRate: c.VerificationRate, Origin: c.Origin, FlowCookie: c.FlowCookie, SessionCookie: c.SessionCookie, Device: c.Device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner, flow, device
}

func signupRequest(operation, body string, flow, device *http.Cookie) *http.Request {
	r := signinRequest(operation, body, flow, device)
	if operation == "register-options" {
		r.Header.Set("Idempotency-Key", "original-signup-options")
	}
	return r
}

func TestSignupOptionsPreservesOriginalFlowAndRejectsMixedCustody(t *testing.T) {
	c, owner, flow, device := signupFixture(t)
	h, err := NewSignupOptionsHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signupRequest("register-options", body, flow, device))
	if w.Code != 403 || owner.options != 1 || owner.last.FlowID != "AAAAAAAAAAAAAAAAAAAAAQ" || owner.last.CommandID != "" || owner.last.Device == "" || owner.last.Network != "198.51.100.7" || owner.last.Caller.Request.Resource.ID != "AAAAAAAAAAAAAAAAAAAAAQ" {
		t.Fatal("signup changed original custody or bypassed native owner", w.Code)
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		func(r *http.Request) { r.Header.Set("X-CSRF-Token", "unselected-session-proof") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer unselected") },
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "unselected"}) },
		func(r *http.Request) { r.Header.Add("Cookie", flow.String()) },
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "second-key") },
		func(r *http.Request) { r.URL.RawQuery = "mode=signup" },
		func(r *http.Request) { r.TLS = nil },
	} {
		r := signupRequest("register-options", body, flow, device)
		mutate(r)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.options != 1 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("mixed/invalid custody reached native signup options", w.Code)
		}
	}
}

func TestSignupVerificationRequiresAnonymousOriginalSource(t *testing.T) {
	c, owner, flow, device := signupFixture(t)
	h, err := NewSignupVerifyHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{}}`
	original := passkey.CeremonyRateSource{Kind: passkey.RateSourceAnonymousFlow, AnonymousFlowID: "AAAAAAAAAAAAAAAAAAAAAQ", CeremonyID: "AAAAAAAAAAAAAAAAAAAAAw", Lifetime: 5 * time.Minute}
	for _, mutate := range []func(*passkey.CeremonyRateSource){
		func(r *passkey.CeremonyRateSource) { r.UserID = "prospective-user" },
		func(r *passkey.CeremonyRateSource) { r.Identifier = "unselected@example.invalid" },
		func(r *passkey.CeremonyRateSource) { r.Kind = passkey.RateSourceUser },
		func(r *passkey.CeremonyRateSource) { r.AnonymousFlowID = "different-flow" },
		func(r *passkey.CeremonyRateSource) { r.CeremonyID = "different-ceremony" },
		func(r *passkey.CeremonyRateSource) { r.Lifetime = time.Minute },
	} {
		owner.source = original
		mutate(&owner.source)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, signupRequest("register-verify", body, flow, device))
		if w.Code != 503 || owner.completions != 0 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("invalid source acquired signup authority", w.Code)
		}
	}
	owner.source = original
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signupRequest("register-verify", body, flow, device))
	if w.Code != 403 || owner.completions != 1 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "prospective") {
		t.Fatal("valid source bypassed native denial or delivered credentials", w.Code)
	}
	r := signupRequest("register-verify", body, flow, device)
	r.Header.Set("Idempotency-Key", "forbidden-completion-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || owner.completions != 1 {
		t.Fatal("non-keyed completion accepted another retry channel")
	}
}

func TestRegistrationUnionDispatchesOnlyExplicitSelectedMode(t *testing.T) {
	c, signup, flow, device := signupFixture(t)
	enrollment, old, _, cookie, _, csrf := registrationFixture(t)
	c.OptionsRate, c.VerificationRate = enrollment.OptionsRate, enrollment.VerificationRate
	f, err := NewFeature(FeatureConfig{Registration: &enrollment, Signup: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || len(ops) != 2 {
		t.Fatal("registration union duplicated canonical operation", err)
	}
	h, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if op.Route.CSRF.Mode != identityhttp.CSRFVariantOriginSessionState {
			t.Fatal("combined route misadvertised one CSRF branch")
		}
	}
	if !strings.Contains(string(document.JSON()), `"signup"`) || !strings.Contains(string(document.JSON()), `"oneOf"`) {
		t.Fatal("selected wire omitted explicit signup variant")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signupRequest("register-options", `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	if w.Code != 403 || signup.options != 1 || old.options != 0 {
		t.Fatal("signup denied by or fell back to enrollment", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, registrationRequest("register-options", `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, cookie, device, csrf))
	if w.Code != 403 || signup.options != 1 || old.options != 1 {
		t.Fatal("retained enrollment dispatched to signup", w.Code)
	}
	for _, candidate := range []struct {
		body    string
		cookies []*http.Cookie
		csrf    string
	}{
		{" \n" + `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}` + "\n ", []*http.Cookie{flow, device}, ""},
		{" \n" + `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}` + "\n ", []*http.Cookie{cookie, device}, csrf},
	} {
		r := signupRequest("register-options", candidate.body, nil, nil)
		for _, cookie := range candidate.cookies {
			r.AddCookie(cookie)
		}
		if candidate.csrf != "" {
			r.Header.Set("X-CSRF-Token", candidate.csrf)
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("valid whitespace-framed registration did not reach its native branch", w.Code)
		}
	}
	if signup.options != 2 || old.options != 2 {
		t.Fatal("whitespace dispatch bypassed selected native owners")
	}
}

func TestSignupAdmissionCannotBeReusedAfterClosureOrSourceDelay(t *testing.T) {
	const body = `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{}}`
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "source-expiry", true: "limiter-close"}[closed], func(t *testing.T) {
			c, owner, flow, device := signupFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			owner.source = passkey.CeremonyRateSource{Kind: passkey.RateSourceAnonymousFlow, AnonymousFlowID: "AAAAAAAAAAAAAAAAAAAAAQ", CeremonyID: "AAAAAAAAAAAAAAAAAAAAAw", Lifetime: 5 * time.Minute}
			owner.afterSource = func() {
				if closed {
					_ = c.VerificationRate.Close()
				} else {
					now = now.Add(2 * c.MaximumDuration)
				}
			}
			h, err := NewSignupVerifyHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, signupRequest("register-verify", body, flow, device))
			if w.Code != 503 || owner.sources != 1 || owner.completions != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("post-source admission was skipped or renewed", w.Code)
			}
		})
	}
	c, owner, flow, device := signupFixture(t)
	h, err := NewSignupOptionsHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.OptionsRate.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signupRequest("register-options", `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	if w.Code != 503 || owner.options != 0 {
		t.Fatal("closed preliminary rate owner admitted signup")
	}
}
