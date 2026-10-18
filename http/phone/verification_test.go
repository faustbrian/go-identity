package phonehttp_test

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

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// This parser fixture cannot grant identity authority. Source custody always
// denies; the genuine native/reference journey owns success and durability proof.
type deniedOwner struct{ reads, effects int }

func (o *deniedOwner) SendVerification(context.Context, phone.EnrollmentRequest) (phone.EnrollmentResult, error) {
	o.effects++
	return phone.EnrollmentResult{}, identity.ForbiddenError{}
}
func (o *deniedOwner) Verify(context.Context, phone.VerificationRequest) (phone.VerificationResult, error) {
	o.effects++
	return phone.VerificationResult{}, identity.ForbiddenError{}
}
func (o *deniedOwner) RecoverVerification(context.Context, phone.VerificationRecoveryRequest) (phone.VerificationResult, error) {
	o.effects++
	return phone.VerificationResult{}, identity.ForbiddenError{}
}
func (o *deniedOwner) PhoneVerificationSession(context.Context, identity.TenantID, otp.SendFlow) (session.Session, error) {
	o.reads++
	return session.Session{}, identity.ForbiddenError{}
}
func (*deniedOwner) PhoneEnrollmentDestination(context.Context, phone.EnrollmentRequest) (phone.Number, error) {
	return phone.Number{}, identity.ForbiddenError{}
}
func (*deniedOwner) PhoneVerificationLifetime(context.Context, phone.VerificationRequest) (time.Duration, error) {
	return 0, identity.ForbiddenError{}
}
func (*deniedOwner) Reauthentication(context.Context, auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	return auth.SignedReauthenticationRecord{}, identity.ForbiddenError{}
}

type parserRates struct{ *memory.Store }

func (*parserRates) Name() string { return "phone-parser-only" }
func (s *parserRates) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, r)
}
func (*parserRates) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, request := range r.Requests {
		out.Decisions[i] = ratelimit.Decision{Allowed: true, Remaining: request.Policy.Limit() - request.Cost, Limit: request.Policy.Limit(), Reset: request.Now.Add(request.Policy.Period()), Reason: ratelimit.ReasonAllowed}
	}
	return out, ctx.Err()
}

func fixture(t *testing.T) (phonehttp.VerificationConfig, *deniedOwner) {
	t.Helper()
	store, err := memory.New(memory.Options{MaxKeys: 128, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	backend := &parserRates{store}
	now := func() time.Time { return time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC) }
	delivery, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "phone-parser", IdentifierKey: [32]byte{1}, Now: now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = delivery.Close() })
	verify, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "phone-parser", Key: [32]byte{2}, Now: now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verify.Close() })
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewCSRFKey(1, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	owner := &deniedOwner{}
	return phonehttp.VerificationConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 64, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: owner, Source: owner, Proofs: owner, NumberPolicy: policy, DeliveryRate: delivery, VerificationRate: verify, Cookie: cookie, Origin: "https://tenant.example", CSRFKeys: []session.CSRFKey{key}, PolicyRevision: 9, Now: now, MaximumDuration: time.Second}, owner
}

func request(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/phone/verify", strings.NewReader(body))
	r.Host, r.RemoteAddr = "tenant.example", "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: strings.Repeat("A", 43)})
	return r
}

func TestVerificationRejectsAlternateAuthorityBeforeOwners(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"flowID":"session","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456","userID":"override"}`, `{"flowID":"session","flowID":"other","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456"}`, `{"flowID":"session","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456","remember":true}`} {
		c, owner := fixture(t)
		h, err := phonehttp.NewVerifyHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(body))
		if w.Code != http.StatusBadRequest || owner.reads != 0 || owner.effects != 0 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "123456") {
			t.Fatalf("malformed phone input reached native authority or disclosed input: status=%d", w.Code)
		}
	}
}

func TestVerificationRequiresExplicitOwners(t *testing.T) {
	for _, factory := range []func(phonehttp.VerificationConfig) (http.Handler, error){phonehttp.NewSendHandler, phonehttp.NewVerifyHandler, phonehttp.NewRecoveryHandler} {
		if h, err := factory(phonehttp.VerificationConfig{}); h != nil || err == nil {
			t.Fatal("missing owners exposed a phone operation")
		}
	}
}

func TestVerificationFeatureSelectsOnlyExplicitEnrollment(t *testing.T) {
	c, owner := fixture(t)
	deviceKey, err := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.Device = session.BrowserDeviceConfig{Namespace: "phone-parser", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	feature, err := phonehttp.NewVerificationFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &raw) != nil || len(raw.Paths) != 3 || owner.reads != 0 || owner.effects != 0 {
		t.Fatal("selection invoked owners or advertised unrelated phone behavior")
	}
	for _, path := range []string{"/v1/phone/send-verification", "/v1/phone/verify", "/v1/phone/verify/recover"} {
		if raw.Paths[path] == nil {
			t.Fatal("selected enrollment route missing")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(`{}`))
	if w.Code != 400 || owner.reads != 0 || owner.effects != 0 {
		t.Fatal("selected parser bypassed closed input")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	off.ServeHTTP(w, request(`{}`))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "phone") {
		t.Fatal("disabled feature exposed a phone route or metadata")
	}
	invalid := c
	invalid.NumberPolicy = &phone.NumberPolicy{}
	partial, err := phonehttp.NewVerificationFeature(invalid)
	if err == nil || len(partial.Operations()) != 0 {
		t.Fatal("zero number policy exposed a partial or unusable phone feature")
	}
}

func FuzzVerificationClosedInput(f *testing.F) {
	for _, body := range []string{`{}`, `null`, `{"flowID":"session","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456"}`, `{"flowID":"session","recovery":null}`, `{"flowID":"session","flowID":"duplicate"}`, `{"tenantID":"override","code":"123456"}`} {
		f.Add(body, false)
		f.Add(body, true)
	}
	f.Fuzz(func(t *testing.T, body string, recovery bool) {
		if len(body) > 4096 {
			t.Skip()
		}
		c, owner := fixture(t)
		factory, path := phonehttp.NewVerifyHandler, "/v1/phone/verify"
		if recovery {
			factory, path = phonehttp.NewRecoveryHandler, "/v1/phone/verify/recover"
		}
		h, err := factory(c)
		if err != nil {
			t.Fatal(err)
		}
		r := request(body)
		r.URL.Path = path
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if owner.effects != 0 || w.Code == 200 || w.Code == 202 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("closed phone input acquired authority or delivered credentials")
		}
	})
}
