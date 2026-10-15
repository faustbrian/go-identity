package otphttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

type sendOwner struct {
	t      *testing.T
	calls  int
	last   otp.SendRequest
	result otp.SendResult
	err    error
}

func (s *sendOwner) Send(ctx context.Context, r otp.SendRequest) (otp.SendResult, error) {
	s.calls++
	s.last = r
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		s.t.Error("invalid or unbounded native send")
	}
	return s.result, s.err
}

func sendFixture(t *testing.T) (otphttp.EmailSigninSendConfig, *sendOwner, *http.Request) {
	t.Helper()
	c, _, _ := fixture(t)
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "send-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewBrowserDeviceKey(1, []byte("dedicated-device-send-test-key-12"))
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	devices := session.BrowserDeviceConfig{Namespace: "send-http", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: policy}
	codec, _ := session.NewBrowserDeviceCodec(devices)
	device, err := codec.Issue(t.Context(), c.Now(), "tenant-a", string(c.Origin))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	s := &sendOwner{t: t, result: otp.SendResult{CommandID: id, Outcome: identity.CommitOutcomeCommitted}}
	r := request(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"user@faß.de"}`)
	r.URL.Path = "/v1/otp/send"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("Idempotency-Key", "same-send-001")
	r.AddCookie(cookie)
	return otphttp.EmailSigninSendConfig{Network: c.Network, Service: s, Rate: c.Rate, Origin: c.Origin, FlowCookie: c.FlowCookie, Device: devices, Address: email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile}, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, TargetID: "identity.otp.signin", Now: c.Now, MaximumDuration: c.MaximumDuration}, s, r
}

func TestEmailSigninSendPreservesTrustedNativeInput(t *testing.T) {
	c, s, r := sendFixture(t)
	h, err := otphttp.NewEmailSigninSendHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out otphttp.SendResponse
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Accepted || out.CommandID != s.result.CommandID || out.CommitOutcome != "committed" {
		t.Fatal("safe native acceptance missing", w.Code)
	}
	if s.calls != 1 || s.last.Channel != otp.ChannelEmail || s.last.Purpose != otp.PurposeSignin || s.last.Destination.Value() != "user@xn--fa-hia.de" || s.last.Network != "198.51.100.7" || s.last.UserID != "" || s.last.TenantID != "tenant-a" || s.last.TargetID != c.TargetID || s.last.Caller.Request.Action != "identity.otp.send" {
		t.Fatal("trusted/canonical scope not preserved")
	}
	codec, _ := session.NewBrowserDeviceCodec(c.Device)
	for _, cookie := range r.Cookies() {
		if cookie.Name == "__Host-identity_device" {
			d, _ := codec.Resolve(t.Context(), c.Now(), "tenant-a", string(c.Origin), cookie.Value)
			if s.last.Device != d.DeviceID() {
				t.Fatal("device replaced")
			}
		}
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
	expected, keyErr := key.Digest([32]byte{1})
	actual, actualErr := s.last.IdempotencyKey.Digest([32]byte{1})
	if err != nil || keyErr != nil || actualErr != nil || expected != actual {
		t.Fatal("idempotency changed")
	}
	if len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "user@") || strings.Contains(w.Body.String(), s.last.Device) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive delivery response")
	}
}

func TestEmailSigninSendClosedChannels(t *testing.T) {
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Cookie") },
		func(r *http.Request) { r.Header.Add("Cookie", "__Host-identity_device=bad") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer replacement") },
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		func(r *http.Request) { r.URL.RawQuery = "device=override" },
		func(r *http.Request) { r.Body = http.NoBody },
	} {
		c, s, r := sendFixture(t)
		change(r)
		h, err := otphttp.NewEmailSigninSendHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || s.calls != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid input reached owner", w.Code)
		}
	}
}

func TestEmailSigninSendAmbiguityNeverRetriesOrClaimsDelivery(t *testing.T) {
	c, s, r := sendFixture(t)
	s.result.Outcome = identity.CommitOutcomeUnknown
	s.err = errors.New("private destination/code")
	h, err := otphttp.NewEmailSigninSendHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out otphttp.SendResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Accepted || out.CommandID != s.result.CommandID || out.CommitOutcome != "unknown" || s.calls != 1 || strings.Contains(w.Body.String(), "private") {
		t.Fatal("ambiguous outcome not preserved")
	}
}

func TestEmailSigninSendBodyCannotSelectAuthority(t *testing.T) {
	for _, field := range []string{"device", "tenantID", "userID", "purpose", "channel", "targetID", "idempotencyKey", "remember"} {
		c, s, r := sendFixture(t)
		body := `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"user@example.invalid","` + field + `":"override"}`
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		h, err := otphttp.NewEmailSigninSendHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || s.calls != 0 {
			t.Fatal("body selected authority", field, w.Code)
		}
	}
}

func TestEmailSigninSendRateAndPostcommitCancellation(t *testing.T) {
	c, s, r := sendFixture(t)
	h, err := otphttp.NewEmailSigninSendHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r.Clone(t.Context()))
		if i < 5 && w.Code != 202 {
			t.Fatal("delivery budget changed", i, w.Code)
		}
		if i == 5 && (w.Code != 429 || s.calls != 5 || w.Header().Get("Retry-After") == "") {
			t.Fatal("denied send reached owner")
		}
		r.Body = io.NopCloser(strings.NewReader(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"user@faß.de"}`))
	}
	// Reconstruct body per request; duplicate logical keys still pass unchanged
	// to the native owner, which exclusively owns durable replay semantics.
	c, s, r = sendFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Service = cancelSend{owner: s, cancel: cancel}
	h, err = otphttp.NewEmailSigninSendHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r.WithContext(ctx))
	var out otphttp.SendResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Accepted || out.CommitOutcome != "committed" || out.CommandID != s.result.CommandID || len(w.Result().Cookies()) != 0 {
		t.Fatal("canceled commitment misreported")
	}
}

type cancelSend struct {
	owner  *sendOwner
	cancel context.CancelFunc
}

func (s cancelSend) Send(ctx context.Context, r otp.SendRequest) (otp.SendResult, error) {
	out, err := s.owner.Send(ctx, r)
	s.cancel()
	return out, err
}

func TestEmailSigninSendFeatureActualWire(t *testing.T) {
	c, s, r := sendFixture(t)
	f, err := otphttp.NewEmailSigninSendFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	if s.calls != 0 || !strings.Contains(string(doc.JSON()), "__Host-identity_device") || !strings.Contains(string(doc.JSON()), "Idempotency-Key") {
		t.Fatal("selected wire or pure construction missing")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 202 || s.calls != 1 {
		t.Fatal("selected handler missing", w.Code)
	}
}

func TestEmailSigninSendRouterResponsesMatchWire(t *testing.T) {
	for _, mode := range []string{"success", "unknown", "conflict", "in_progress", "canceled-commit", "canceled-unknown", "canceled-conflict", "canceled-in_progress", "invalid", "plaintext", "origin", "host", "method"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, r := sendFixture(t)
			want, media := 202, "application/json"
			switch mode {
			case "unknown":
				owner.result.Outcome, want = identity.CommitOutcomeUnknown, 503
			case "conflict":
				owner.result.Outcome, want = identity.CommitOutcomeConflict, 409
			case "in_progress":
				owner.result.Outcome, owner.result.RetryAfter, want = identity.CommitOutcomeInProgress, 1500*time.Millisecond, 409
			case "canceled-commit", "canceled-unknown", "canceled-conflict", "canceled-in_progress":
				switch mode {
				case "canceled-unknown":
					owner.result.Outcome = identity.CommitOutcomeUnknown
				case "canceled-conflict":
					owner.result.Outcome = identity.CommitOutcomeConflict
				case "canceled-in_progress":
					owner.result.Outcome = identity.CommitOutcomeInProgress
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				c.Service = cancelSend{owner: owner, cancel: cancel}
				r, want = r.WithContext(ctx), 503
			case "invalid":
				r.Header.Del("Idempotency-Key")
				want = 400
			case "plaintext":
				r.TLS, r.URL.Scheme, want = nil, "http", 403
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
				want, media = 403, "text/plain"
			case "host":
				r.Host, want = "unknown.example", 421
			case "method":
				r.Method, want = http.MethodGet, 405
			}
			f, err := otphttp.NewEmailSigninSendFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || !strings.HasPrefix(w.Header().Get("Content-Type"), media) {
				t.Fatalf("status/media mismatch: %d", w.Code)
			}
			if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" || (mode == "in_progress" && w.Header().Get("Retry-After") != "2") {
				t.Fatal("unsafe response custody or retry")
			}
			if strings.HasPrefix(mode, "canceled-") {
				var out otphttp.SendResponse
				wantOutcome := strings.TrimPrefix(mode, "canceled-")
				if wantOutcome == "commit" {
					wantOutcome = "committed"
				}
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommandID != owner.result.CommandID || out.CommitOutcome != wantOutcome || out.Accepted || owner.calls != 1 {
					t.Fatal("router discarded original canceled commitment")
				}
			}
			parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/otp/send", "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("actual response absent from wire")
				}
			}
			body := w.Body.Bytes()
			if media == "text/plain" {
				body, _ = json.Marshal(string(body))
			}
			instance, err := parse.JSON(t.Context(), bytes.NewReader(body), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatalf("actual response violates wire: %v %+v", err, report.Diagnostics())
			}
			if media == "application/json" {
				var bad map[string]any
				if json.Unmarshal(body, &bad) != nil {
					t.Fatal("response")
				}
				bad["credential"] = "forbidden"
				body, _ = json.Marshal(bad)
				instance, _ = parse.JSON(t.Context(), bytes.NewReader(body), parse.DefaultLimits())
				report, err = validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("wire admits credential output")
				}
			}
		})
	}
}

func TestEmailSigninCombinedFeatureIsAtomicAndRoutesRealOwners(t *testing.T) {
	c, send, r := sendFixture(t)
	signin, finish, body := fixture(t)
	finish.result = func(_ context.Context, input otp.SigninRequest) (otp.SigninResult, error) {
		return issuance(t, signin, input), nil
	}
	recovery, history, historical, _ := recoveryFixture(t)
	f, err := otphttp.NewEmailSigninFeature(c, signin, recovery)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	if send.calls != 0 || finish.sources != 0 || history.calls != 0 {
		t.Fatal("construction invoked owner")
	}
	var document map[string]any
	if json.Unmarshal(doc.JSON(), &document) != nil {
		t.Fatal("document")
	}
	if len(document["paths"].(map[string]any)) != 3 || len(document["components"].(map[string]any)["securitySchemes"].(map[string]any)) != 2 {
		t.Fatal("duplicate or missing selected contracts")
	}
	for i, req := range []*http.Request{r, request(body), recoveryRequest(historical)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := 200
		if i == 0 {
			want = 202
		}
		if w.Code != want {
			t.Fatal("combined dispatch", i, w.Code)
		}
	}
	if send.calls != 1 || finish.attempts != 1 || history.calls != 1 {
		t.Fatal("real owner dispatch missing")
	}
	recovery.Service = nil
	bad, err := otphttp.NewEmailSigninFeature(c, signin, recovery)
	if err == nil || len(bad.Operations()) != 0 || send.calls != 1 {
		t.Fatal("partial feature escaped invalid composition")
	}
}

func TestEmailSigninSendRejectsForeignOrExpiredDeviceWithoutReplacement(t *testing.T) {
	for _, mode := range []string{"expired", "tenant", "origin"} {
		c, owner, r := sendFixture(t)
		codec, _ := session.NewBrowserDeviceCodec(c.Device)
		tenant, origin := identity.TenantID("tenant-a"), string(c.Origin)
		if mode == "tenant" {
			tenant = "tenant-other"
		}
		if mode == "origin" {
			origin = "https://foreign.example"
		}
		device, err := codec.Issue(t.Context(), c.Now(), tenant, origin)
		if err != nil {
			t.Fatal(err)
		}
		cookie, _ := http.ParseSetCookie(device.CookieHeader())
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, old := range cookies {
			if old.Name != "__Host-identity_device" {
				r.AddCookie(old)
			}
		}
		r.AddCookie(cookie)
		if mode == "expired" {
			c.Now = func() time.Time { return device.ExpiresAt() }
		}
		h, err := otphttp.NewEmailSigninSendHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || owner.calls != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("device custody replaced or foreign", mode)
		}
	}
}

func TestEmailSigninSendMiddlewareKeepsOriginalInputAndNoCredentialOutput(t *testing.T) {
	c, owner, r := sendFixture(t)
	var observed bool
	var retained *http.Request
	middleware := []identityhttp.MiddlewareDescriptor{
		hook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			r.Host = "foreign.example"
			r.Header.Set("Cookie", "replacement=value")
			r.Body = http.NoBody
			w.Header()["set-cookie"] = []string{"forged=value"}
			w.Header()["x-csrf-token"] = []string{"forged"}
			next.ServeHTTP(w, r)
			next.ServeHTTP(w, r)
			w.Header()[http.TrailerPrefix+"Set-Cookie"] = []string{"forged=value"}
		}),
		hook(identityhttp.MiddlewareAfterHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			retained = r
			state, ok := identityhttp.PipelineValue[otphttp.SendState](r)
			out, attempted := state.Attempt()
			observed = ok && attempted && out.Accepted && out.CommandID == owner.result.CommandID
			out.CommandID = "detached"
			copy, _ := state.Attempt()
			if copy.CommandID == "detached" {
				t.Error("mutable state projection")
			}
			formatted := fmt.Sprintf("%#v", struct{ state otphttp.SendState }{state})
			if strings.Contains(formatted, "user@") || strings.Contains(formatted, owner.last.Device) {
				t.Error("private wrapper traversed sensitive input")
			}
			if _, err := json.Marshal(state); err == nil {
				t.Error("state implicitly exported")
			}
			next.ServeHTTP(w, r)
		}),
	}
	h, err := otphttp.NewEmailSigninSendHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	h, err = identityhttp.WithOperationMiddleware(h, middleware)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 202 || owner.calls != 1 || !observed || owner.last.Destination.Value() != "user@xn--fa-hia.de" || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("X-CSRF-Token") != "" || w.Result().Trailer.Get("Set-Cookie") != "" {
		t.Fatal("middleware changed native input or output custody")
	}
	if _, ok := identityhttp.PipelineValue[otphttp.SendState](retained); ok {
		t.Fatal("state survives request")
	}
}

func TestEmailSigninSendValidatesCompositionBeforeIO(t *testing.T) {
	for _, invalidate := range []func(*otphttp.EmailSigninSendConfig){
		func(c *otphttp.EmailSigninSendConfig) { c.Service = nil },
		func(c *otphttp.EmailSigninSendConfig) { c.Rate = nil },
		func(c *otphttp.EmailSigninSendConfig) { c.Now = nil },
		func(c *otphttp.EmailSigninSendConfig) { c.MaximumDuration = 31 * time.Second },
		func(c *otphttp.EmailSigninSendConfig) { c.Device = session.BrowserDeviceConfig{} },
		func(c *otphttp.EmailSigninSendConfig) { c.Address = email.AddressPolicy{} },
		func(c *otphttp.EmailSigninSendConfig) { c.TargetID = "invalid target" },
		func(c *otphttp.EmailSigninSendConfig) { c.FlowCookie = session.CookiePolicy{} },
		func(c *otphttp.EmailSigninSendConfig) { c.PolicyRevision = 0 },
	} {
		c, owner, _ := sendFixture(t)
		invalidate(&c)
		h, err := otphttp.NewEmailSigninSendHandler(c)
		if err == nil || h != nil || owner.calls != 0 {
			t.Fatal("invalid composition escaped")
		}
	}
}

func TestEmailSigninSendRechecksDeviceLifetimeAndCancellationAfterHooks(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		c, owner, r := sendFixture(t)
		now := c.Now()
		c.Now = func() time.Time { return now }
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		h, err := otphttp.NewEmailSigninSendHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{hook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if canceled {
				cancel()
			} else {
				now = now.Add(24 * time.Hour)
			}
			next.ServeHTTP(w, r)
		})})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r.WithContext(ctx))
		want := 400
		if canceled {
			want = 503
		}
		if w.Code != want || owner.calls != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("hook bypassed live custody", canceled, w.Code)
		}
	}
}
