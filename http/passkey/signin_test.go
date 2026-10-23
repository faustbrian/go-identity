package passkeyhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// This is the native workflow boundary only. Real transport admission and the
// primitive's memory backend execute here; PostgreSQL Reference tests own the
// genuine authentication/commit/cookie success journey, not this denial double.
type deniedSignin struct {
	options, sources, completions int
	last                          passkey.KeyedSigninOptionsRequest
	commandID                     identity.CommandID
	err                           error
	waitForDeadline               bool
}

func (o *deniedSignin) KeyedAuthenticationOptions(ctx context.Context, r passkey.KeyedSigninOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	o.options++
	o.last = r
	if o.waitForDeadline {
		<-ctx.Done()
	}
	if o.err != nil {
		return passkey.KeyedAssertionOptionsResult{CommandID: o.commandID}, o.err
	}
	return passkey.KeyedAssertionOptionsResult{}, identity.ForbiddenError{}
}
func (o *deniedSignin) KeyedDiscoverableAuthenticationOptions(context.Context, passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	o.options++
	return passkey.KeyedAssertionOptionsResult{}, identity.ForbiddenError{}
}
func (o *deniedSignin) SigninRateSource(context.Context, passkey.SigninCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	o.sources++
	return passkey.CeremonyRateSource{}, identity.ForbiddenError{}
}
func (o *deniedSignin) DiscoverableSigninRateSource(context.Context, passkey.DiscoverableCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	o.sources++
	return passkey.CeremonyRateSource{}, identity.ForbiddenError{}
}
func (o *deniedSignin) Signin(context.Context, passkey.SigninCompletion) (passkey.SigninResult, error) {
	o.completions++
	return passkey.SigninResult{}, identity.ForbiddenError{}
}
func (o *deniedSignin) DiscoverableSignin(context.Context, passkey.DiscoverableSigninCompletion) (passkey.SigninResult, error) {
	o.completions++
	return passkey.SigninResult{}, identity.ForbiddenError{}
}

type parserRates struct{ *memory.Store }

func (*parserRates) Name() string { return "passkey-http-parser" }
func (s *parserRates) AdmitStrict(ctx context.Context, request ratelimit.Request) (ratelimit.Decision, error) {
	p := request.Policy
	request.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, request)
}
func (*parserRates) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, request := range r.Requests {
		out.Decisions[i] = ratelimit.Decision{Allowed: true, Remaining: request.Policy.Limit() - request.Cost, Limit: request.Policy.Limit(), Reset: request.Now.Add(request.Policy.Period()), Reason: ratelimit.ReasonAllowed}
	}
	return out, ctx.Err()
}

func signinFixture(t *testing.T) (SigninConfig, *deniedSignin, *http.Cookie, *http.Cookie) {
	t.Helper()
	store, err := memory.New(memory.Options{MaxKeys: 512, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	backend := &parserRates{store}
	now := func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "passkey-http", IdentifierKey: [32]byte{1}, Now: now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	verify, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "passkey-http", Key: [32]byte{2}, Now: now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { verify.Close() })
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	flowCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	key, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{3}, 32))
	deviceConfig := session.BrowserDeviceConfig{Namespace: "passkey-http", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(t.Context(), now(), "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	parsed := (&http.Response{Header: http.Header{"Set-Cookie": {device.CookieHeader()}}}).Cookies()
	if len(parsed) != 1 {
		t.Fatal("missing genuine device cookie")
	}
	flow, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := flow.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "passkey-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, CaseFold: true, MaximumBytes: 320})
	if err != nil {
		t.Fatal(err)
	}
	owner := &deniedSignin{}
	address, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 320, Canonicalization: profile})
	if err != nil {
		t.Fatal(err)
	}
	return SigninConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 300000, MaximumDecodedBytes: 300000, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: owner, OptionsRate: rate, VerificationRate: verify, Origin: "https://tenant.example", FlowCookie: flowCookie, SessionCookie: cookie, Device: deviceConfig, Address: address, ActorID: "service-a", PolicyRevision: authorization.Revision(9), Audience: "identity", Now: now, MaximumDuration: time.Second}, owner, &http.Cookie{Name: "__Host-identity_flow", Value: wire}, parsed[0]
}

func signinRequest(operation, body string, flow, device *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/passkey/"+operation, strings.NewReader(body))
	r.Host, r.RemoteAddr, r.TLS = "tenant.example", "198.51.100.7:1234", &tls.ConnectionState{}
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("Content-Type", "application/json")
	if operation == "signin-options" {
		r.Header.Set("Idempotency-Key", "original-options")
	}
	if flow != nil {
		r.AddCookie(flow)
	}
	if device != nil {
		r.AddCookie(device)
	}
	return r
}

func TestSigninOptionsHasStrictIngressAndSingleNativeCall(t *testing.T) {
	const body = `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"Person@Example.Invalid"}`
	c, owner, flow, device := signinFixture(t)
	h, err := NewSigninOptionsHandler(c)
	if err != nil || owner.options != 0 {
		t.Fatal("constructor performed work or rejected selected owner", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", body, flow, device))
	if w.Code != 403 || owner.options != 1 || owner.last.Identifier != "person@example.invalid" || owner.last.CommandID != "" || owner.last.Caller.Request.Subject.Kind != authorization.SubjectServiceAccount || owner.last.Caller.Request.Resource.ID != "AAAAAAAAAAAAAAAAAAAAAQ" || owner.last.IdempotencyKey == (identity.IdempotencyKey{}) {
		t.Fatal("native admission was bypassed or request acquired alternate authority", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "Person") {
		t.Fatal("denial disclosed sensitive input or emitted credentials")
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "second-key") },
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic-other") },
		func(r *http.Request) { r.Header.Set("X-CSRF-Token", "unexpected") },
		func(r *http.Request) { r.Header.Add("Cookie", flow.String()) },
		func(r *http.Request) { r.URL.RawQuery = "tenantID=other" },
		func(r *http.Request) { r.Host = "foreign.example" },
		func(r *http.Request) { r.TLS = nil },
	} {
		r := signinRequest("signin-options", body, flow, device)
		mutate(r)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.options != 1 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("invalid ingress reached native options")
		}
	}
}

func TestSigninModesDoNotFallbackAndCompletionRequiresOriginalSource(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	options, err := NewSigninOptionsHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	options.ServeHTTP(w, signinRequest("signin-options", `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	if w.Code != 400 || owner.options != 0 {
		t.Fatal("unselected discovery reached a native owner")
	}
	c.Discoverable = true
	verify, err := NewSigninVerifyHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	verify.ServeHTTP(w, signinRequest("signin-verify", `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"AAAAAAAAAAAAAAAAAAAAAg","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{"id":"synthetic-assertion"}}`, flow, device))
	if w.Code != 403 || owner.sources != 1 || owner.completions != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("source denial reached cryptographic completion or disclosed credentials")
	}
}

func TestSigninUnknownOptionsRetainsOriginalCommandWithoutChallenge(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	owner.commandID = "AAAAAAAAAAAAAAAAAAAAAQ"
	owner.err = identity.UnknownCommitError{CommandID: owner.commandID}
	h, err := NewSigninOptionsHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAg","identifier":"Person@Example.Invalid"}`, flow, device))
	var out struct {
		CommandID     identity.CommandID `json:"commandID"`
		CommitOutcome string             `json:"commitOutcome"`
		Options       json.RawMessage    `json:"options"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 503 || out.CommandID != owner.commandID || out.CommitOutcome != "unknown" || len(out.Options) != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("ambiguous options lost original recovery identity or disclosed a challenge", w.Code, err)
	}
}

func TestSigninEmailUsesOwnedLocalPartAndNontransitionalDomainPolicy(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	h, err := NewSigninOptionsHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"Straße@faß.de"}`, flow, device))
	if w.Code != 403 || owner.options != 1 || owner.last.Identifier != "strasse@xn--fa-hia.de" {
		t.Fatal("signin did not preserve the email owner's independent local-part and IDNA comparison policy", w.Code)
	}
	for _, mailbox := range []string{"not-a-mailbox", "a@@example.invalid", "a@example.invalid."} {
		w = httptest.NewRecorder()
		body, _ := json.Marshal(map[string]any{"mode": "identified", "flowID": "AAAAAAAAAAAAAAAAAAAAAQ", "identifier": mailbox})
		h.ServeHTTP(w, signinRequest("signin-options", string(body), flow, device))
		if w.Code != 400 || owner.options != 1 {
			t.Fatal("malformed mailbox reached native signin", w.Code)
		}
	}
}
