package mfahttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// This double is the native authentication boundary, not a substitute for the
// real PostgreSQL delivered-code journey. Transport must preserve its input and
// refuse to deliver credentials for historical or unreconciled results.
type otpNative struct {
	rate         *strictRate
	reads, calls int
	fail         bool
	result       func(mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error)
}

func (s *otpNative) OtpVerificationRateSource(_ context.Context, r mfa.OtpVerifyRequest) (identity.UserID, string, time.Duration, error) {
	s.reads++
	if s.rate.calls != 1 || r.Validate() != nil || r.FactorID != "" || r.Enrollment != nil {
		panic("OTP source not admitted under original login input")
	}
	if s.fail {
		return "", "", 0, identity.ForbiddenError{}
	}
	return "user-a", string(r.ContinuationID), time.Minute, nil
}

func (s *otpNative) OtpVerify(_ context.Context, r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) {
	s.calls++
	if s.rate.calls != 2 || r.Validate() != nil {
		panic("OTP completion not admitted")
	}
	if s.result != nil {
		return s.result(r)
	}
	return mfa.OtpVerifyResult{Outcome: identity.CommitOutcomeCommitted, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeCommitted, Replayed: true}}, nil
}

func otpHandlerFixture(t *testing.T) (OTPVerifyConfig, *otpNative, *native, string, *http.Cookie) {
	t.Helper()
	c, totp, raw, device := handlerFixture(t)
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	body["continuationID"] = body["challengeID"]
	delete(body, "challengeID")
	delete(body, "factorID")
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	owner := &otpNative{rate: totp.rate}
	return OTPVerifyConfig{Network: c.Network, Service: owner, Rate: c.Rate, Origin: c.Origin, CallbackURL: c.CallbackURL, SessionCookie: c.SessionCookie, Device: c.Device, ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner, totp, string(wire), device
}

func otpRequest(c OTPVerifyConfig, body string, device *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/otp-verify", strings.NewReader(body))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "127.0.0.1:4242"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", string(c.Origin))
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
	if device != nil {
		r.AddCookie(device)
	}
	return r
}

func TestOTPHTTPClosedLoginAndNoCredentialReplay(t *testing.T) {
	for _, mode := range []string{"replay", "conflict", "unknown", "origin", "idempotency", "authorization", "query", "duplicate", "user", "factor", "channel", "variant", "missing-device", "missing-flow", "source-denied"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, totp, body, device := otpHandlerFixture(t)
			switch mode {
			case "duplicate":
				body = strings.Replace(body, `"code":"123456"`, `"code":"123456","code":"111111"`, 1)
			case "user", "factor", "channel":
				body = strings.TrimSuffix(body, "}") + `,"` + mode + `ID":"foreign"}`
			case "missing-device":
				device = nil
			case "source-denied":
				owner.fail = true
			case "conflict", "unknown":
				owner.result = func(r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) {
					outcome := identity.CommitOutcomeUnknown
					if mode == "conflict" {
						outcome = identity.CommitOutcomeConflict
					}
					return mfa.OtpVerifyResult{Outcome: outcome, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: outcome}}, nil
				}
			}
			h, err := NewOTPVerifyHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := otpRequest(c, body, device)
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "idempotency":
				r.Header.Set("Idempotency-Key", "forbidden")
			case "authorization":
				r.Header.Set("Authorization", "Bearer forbidden")
			case "variant":
				r.Header.Set("X-MFA-Variant", "enrollment")
			case "query":
				r.URL.RawQuery = "code=123456"
				r.RequestURI = r.URL.RequestURI()
			case "missing-flow":
				r.Header.Del("Cookie")
				r.AddCookie(device)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			w.Header().Set("X-MFA-Token", "injected")
			h.ServeHTTP(w, r)
			var out OTPVerifyResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.SignedIn || out.SessionID != "" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("X-MFA-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("failed OTP attempt leaked credentials", mode, w.Code)
			}
			if totp.reads != 0 || totp.calls != 0 {
				t.Fatal("OTP fell back to TOTP")
			}
			if mode == "replay" || mode == "conflict" || mode == "unknown" {
				want := 409
				if mode == "unknown" {
					want = 503
				}
				if w.Code != want || owner.reads != 1 || owner.calls != 1 || owner.rate.calls != 2 {
					t.Fatal("OTP lost original-source admission", mode, w.Code)
				}
			} else if owner.calls != 0 || w.Code == 200 {
				t.Fatal("hostile input completed", mode, w.Code)
			}
		})
	}
}

func TestOTPHTTPRequiresActualOwner(t *testing.T) {
	c, _, _, _, _ := otpHandlerFixture(t)
	c.Service = (*otpNative)(nil)
	if h, err := NewOTPVerifyHandler(c); err == nil || h != nil {
		t.Fatal("nil owner acquired completion authority")
	}
}

func otpIssuance(t *testing.T, c OTPVerifyConfig, r mfa.OtpVerifyRequest, method string) mfa.OtpVerifyResult {
	t.Helper()
	base := TOTPVerifyConfig{PasswordPrimary: true, Now: c.Now, Audience: c.Audience, SessionCookie: c.SessionCookie}
	issued := issuance(t, base, mfa.TotpVerifyRequest{TenantID: r.TenantID, CommandID: r.CommandID, ChallengeID: mfa.ChallengeID(r.ContinuationID), FactorID: "BAQEBAQEBAQEBAQEBAQEBA"})
	factor, _ := issued.Session.Session.MFAAuthentication().Bindings()
	factor.Method = method
	metadata, err := session.NewMFAAuthentication(factor)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := issued.Session.Session.Bindings()
	record, err := session.NewSessionWithPasswordMFAAndCSRF(spec, metadata, issued.Session.Session.CSRFState())
	if err != nil {
		t.Fatal(err)
	}
	issued.Session.Session = record
	return mfa.OtpVerifyResult{Outcome: issued.Outcome, Session: issued.Session, CSRFToken: issued.CSRFToken}
}

func TestOTPHTTPFreshDeliveryRequiresPasswordOTPAndOriginalChild(t *testing.T) {
	for _, mode := range []string{"fresh", "totp-result", "foreign-child", "error-with-custody", "expired", "trust-device", "callback", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, body, device := otpHandlerFixture(t)
			initial := c.Now()
			now := initial
			c.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			owner.result = func(r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) {
				if r.TrustDevice {
					return mfa.OtpVerifyResult{}, identity.ForbiddenError{}
				}
				if r.Callback != c.CallbackURL || r.Origin != string(c.Origin) || r.Cookie.Token() == "" || r.Device == "" {
					t.Fatal("lost original browser/callback scope")
				}
				actual := r
				if mode == "foreign-child" {
					actual.ContinuationID = "BgYGBgYGBgYGBgYGBgYGBg"
				}
				method := "otp"
				if mode == "totp-result" {
					method = "totp"
				}
				out := otpIssuance(t, c, actual, method)
				if mode == "expired" {
					now = initial.Add(time.Minute)
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "error-with-custody" {
					return out, identity.UnavailableError{}
				}
				return out, nil
			}
			if mode == "trust-device" {
				body = strings.Replace(body, `"trustDevice":false`, `"trustDevice":true`, 1)
			}
			if mode == "callback" {
				body = strings.Replace(body, c.CallbackURL, "https://foreign.example", 1)
			}
			h, err := NewOTPVerifyHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, otpRequest(c, body, device).WithContext(ctx))
			var out OTPVerifyResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatal("invalid OTP outcome")
			}
			if mode == "fresh" {
				if w.Code != 200 || !out.SignedIn || out.SessionID != "session-a" || len(w.Result().Cookies()) != 1 || w.Header().Get("X-CSRF-Token") == "" {
					t.Fatal("fresh OTP credential tuple missing", w.Code)
				}
				cookie := w.Result().Cookies()[0]
				if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || strings.Contains(w.Body.String(), cookie.Value) || strings.Contains(w.Body.String(), w.Header().Get("X-CSRF-Token")) {
					t.Fatal("unsafe OTP credential delivery")
				}
			} else if w.Code == 200 || out.SignedIn || out.SessionID != "" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("invalid OTP custody escaped", mode, w.Code)
			}
			if mode == "callback" && owner.reads != 0 {
				t.Fatal("foreign callback read native state")
			}
		})
	}
}

func TestOTPHTTPFinalWriteRechecksFreshness(t *testing.T) {
	c, owner, _, body, device := otpHandlerFixture(t)
	now := c.Now()
	c.Now = func() time.Time { return now }
	owner.result = func(r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) { return otpIssuance(t, c, r, "otp"), nil }
	h, err := NewOTPVerifyHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/mfa", Middleware: identityhttp.Middleware{Name: "delay", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(commitWriter{ResponseWriter: w, before: func() { now = now.Add(time.Minute) }}, r)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, otpRequest(c, body, device))
	var out OTPVerifyResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out.SignedIn || out.CommitOutcome != "committed" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("expired OTP tuple delivered at first write", w.Code)
	}
}

func TestOTPHTTPSelectedFeatureHasOnlyNativeRoute(t *testing.T) {
	c, owner, _, body, device := otpHandlerFixture(t)
	feature, err := NewFeature(FeatureConfig{OTPVerify: &c})
	if err != nil || len(feature.Operations()) != 1 {
		t.Fatal("explicit OTP feature missing", err)
	}
	op := feature.Operations()[0]
	if op.Record.OperationID != "identity.mfa.otp-verify" || op.Route.Path != "/v1/mfa/otp-verify" || op.Route.Method != http.MethodPost || op.Wire == nil {
		t.Fatal("OTP route/schema mismatch")
	}
	var wire map[string]any
	if err := json.Unmarshal(op.Wire.Definition, &wire); err != nil {
		t.Fatal(err)
	}
	schema := wire["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	if len(properties) != 7 || properties["continuationID"] == nil || properties["factorID"] != nil || properties["challengeID"] != nil || schema["additionalProperties"] != false {
		t.Fatal("OTP schema permits original-source override")
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 1 {
		t.Fatal("OTP canonical composition failed", err)
	}
	w := httptest.NewRecorder()
	ops[0].Handler.ServeHTTP(w, otpRequest(c, body, device))
	if w.Code != 409 || owner.calls != 1 {
		t.Fatal("selected descriptor did not execute OTP", w.Code)
	}
	base, _, _, _ := handlerFixture(t)
	other, err := NewFeature(FeatureConfig{TOTPVerify: &base})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range other.Operations() {
		if operation.Record.OperationID == "identity.mfa.otp-verify" {
			t.Fatal("disabled OTP exposed route")
		}
	}
}
