package phonehttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

func (o *deniedOwner) SendChange(context.Context, phone.ChangeRequest) (identity.CommandResult, error) {
	o.effects++
	return identity.CommandResult{}, identity.ForbiddenError{}
}
func (o *deniedOwner) Update(context.Context, phone.UpdateRequest) (phone.UpdateResult, error) {
	o.effects++
	return phone.UpdateResult{}, identity.ForbiddenError{}
}
func (o *deniedOwner) RecoverUpdate(context.Context, phone.UpdateRecoveryRequest) (phone.UpdateResult, error) {
	o.effects++
	return phone.UpdateResult{}, identity.ForbiddenError{}
}
func (o *deniedOwner) PhoneChangeSession(context.Context, identity.TenantID, otp.SendFlow) (session.Session, error) {
	o.reads++
	return session.Session{}, identity.ForbiddenError{}
}
func (*deniedOwner) PhoneChangeDestination(context.Context, phone.ChangeRequest) (phone.Number, error) {
	return phone.Number{}, identity.ForbiddenError{}
}
func (*deniedOwner) PhoneUpdateLifetime(context.Context, phone.UpdateRequest) (time.Duration, error) {
	return 0, identity.ForbiddenError{}
}

func changeFixture(t *testing.T) (phonehttp.ChangeConfig, *deniedOwner) {
	t.Helper()
	c, owner := fixture(t)
	store, err := memory.New(memory.Options{MaxKeys: 128, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: &parserRates{store}, Namespace: "phone-change-parser", Key: [32]byte{5}, Now: c.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rate.Close() })
	return phonehttp.ChangeConfig{Network: c.Network, Service: owner, Source: owner, Proofs: owner, NumberPolicy: c.NumberPolicy, DeliveryRate: c.DeliveryRate, UpdateRate: rate, RecoveryRate: c.VerificationRate, Cookie: c.Cookie, Origin: c.Origin, CSRFKeys: c.CSRFKeys, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner
}

func TestUpdateRejectsAlternateAuthorityBeforeOwners(t *testing.T) {
	const valid = `{"flowID":"session","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456","proofID":"AAAAAAAAAAAAAAAAAAAAAQ","reason":"user-requested"}`
	for _, body := range []string{`{}`, `null`, strings.TrimSuffix(valid, "}") + `,"userID":"override"}`, strings.TrimSuffix(valid, "}") + `,"idempotencyKey":"body-key"}`, strings.TrimSuffix(valid, "}") + `,"code":"654321"}`} {
		c, owner := changeFixture(t)
		h, err := phonehttp.NewUpdateHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		r := request(body)
		r.URL.Path = "/v1/phone/update"
		r.RequestURI = r.URL.RequestURI()
		r.Header.Set("Idempotency-Key", "original-update")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || owner.reads != 0 || owner.effects != 0 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "123456") {
			t.Fatal("malformed replacement reached an owner or disclosed input", w.Code)
		}
	}
}

func TestUpdateRequiresHeaderRetryKeyAndOriginalSession(t *testing.T) {
	const valid = `{"flowID":"session","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456","proofID":"AAAAAAAAAAAAAAAAAAAAAQ","reason":"user-requested"}`
	for _, keyed := range []bool{false, true} {
		c, owner := changeFixture(t)
		h, err := phonehttp.NewUpdateHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		r := request(valid)
		r.URL.Path = "/v1/phone/update"
		r.RequestURI = r.URL.RequestURI()
		if keyed {
			r.Header.Set("Idempotency-Key", "original-update")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !keyed && (w.Code != 400 || owner.reads != 0) || keyed && (w.Code != 403 || owner.reads != 1) || owner.effects != 0 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("replacement bypassed header key or original possession", keyed, w.Code, owner.reads)
		}
	}
}

func TestUpdateTransportDeniesBeforeReadingOriginalSession(t *testing.T) {
	const valid = `{"flowID":"session","sendCommandID":"AgICAgICAgICAgICAgICAg","code":"123456","proofID":"AAAAAAAAAAAAAAAAAAAAAQ","reason":"user-requested"}`
	for _, scenario := range []struct {
		name   string
		status int
		alter  func(*http.Request)
	}{
		{"foreign-origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"missing-origin", 403, func(r *http.Request) { r.Header.Del("Origin") }},
		{"missing-synchronizer", 403, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
		{"missing-cookie", 403, func(r *http.Request) { r.Header.Del("Cookie") }},
		{"alternate-bearer", 400, func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic-override") }},
		{"duplicate-key", 400, func(r *http.Request) { r.Header.Add("Idempotency-Key", "different-key") }},
		{"insecure-transport", 403, func(r *http.Request) { r.TLS = nil }},
		{"wrong-method", 405, func(r *http.Request) { r.Method = http.MethodGet }},
		{"path-alias", 404, func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.RequestURI() }},
		{"query-override", 400, func(r *http.Request) { r.URL.RawQuery = "userID=override"; r.RequestURI = r.URL.RequestURI() }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			c, owner := changeFixture(t)
			h, err := phonehttp.NewUpdateHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := request(valid)
			r.URL.Path = "/v1/phone/update"
			r.RequestURI = r.URL.RequestURI()
			r.Header.Set("Idempotency-Key", "original-update")
			scenario.alter(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != scenario.status || owner.reads != 0 || owner.effects != 0 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "123456") {
				t.Fatal("transport denial reached authority or disclosed input", w.Code, owner.reads)
			}
		})
	}
}

func TestChangeFeatureSelectsOnlyReplacementAndOriginalHistory(t *testing.T) {
	c, owner := changeFixture(t)
	key, err := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.Device = session.BrowserDeviceConfig{Namespace: "phone-change-parser", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: cookie}
	feature, err := phonehttp.NewChangeFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &raw) != nil || len(raw.Paths) != 3 || owner.reads != 0 || owner.effects != 0 {
		t.Fatal("replacement selection invoked owners or exposed unrelated operations")
	}
	for _, path := range []string{"/v1/phone/send-verification", "/v1/phone/update", "/v1/phone/update/recover"} {
		if raw.Paths[path] == nil {
			t.Fatal("selected replacement route missing", path)
		}
	}
	r := request(`{}`)
	r.URL.Path = "/v1/phone/update"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("Idempotency-Key", "original-update")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || owner.reads != 0 || owner.effects != 0 {
		t.Fatal("selected replacement handler bypassed closed parsing", w.Code)
	}
	if _, err := phonehttp.NewChangeFeature(phonehttp.ChangeConfig{}); err == nil {
		t.Fatal("unconfigured replacement was advertised")
	}
}
