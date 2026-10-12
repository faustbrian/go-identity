package mfahttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
	rate "github.com/faustbrian/go-rate-limit/v2"
)

func TestTOTPHTTPRequiresOwnedComposition(t *testing.T) {
	if h, err := NewTOTPVerifyHandler(TOTPVerifyConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured HTTP acquired completion authority")
	}
}

type strictRate struct {
	rate.StrictBackend
	calls int
}

func (*strictRate) Name() string { return "totp-test" }
func (s *strictRate) AdmitAtomicStrict(_ context.Context, r rate.AtomicBatchRequest) (rate.AtomicBatchDecision, error) {
	s.calls++
	out := rate.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true}
	for _, v := range r.Requests {
		out.Decisions = append(out.Decisions, rate.Decision{Allowed: true, Limit: v.Policy.Limit(), Remaining: v.Policy.Limit() - 1, Reset: v.Now.Add(v.Policy.Period()), Reason: rate.ReasonAllowed})
	}
	return out, nil
}

type native struct {
	rate         *strictRate
	reads, calls int
	fail         bool
	result       func(mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error)
}

func (s *native) TotpVerificationRateSource(_ context.Context, r mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error) {
	s.reads++
	if s.rate.calls != 1 || r.Validate() != nil {
		panic("source not admitted")
	}
	if s.fail {
		return "", "", 0, identity.ForbiddenError{}
	}
	return "user-a", string(r.ChallengeID), time.Minute, nil
}
func (s *native) TotpVerify(_ context.Context, r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
	s.calls++
	if s.rate.calls != 2 || r.Validate() != nil {
		panic("completion not admitted")
	}
	if s.result != nil {
		return s.result(r)
	}
	return mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeCommitted, Replayed: true}}, nil
}

func handlerFixture(t *testing.T) (TOTPVerifyConfig, *native, string, *http.Cookie) {
	t.Helper()
	now := time.Unix(1800000000, 0)
	backend := &strictRate{}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "totp-test", Key: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := limiter.Close(); err != nil {
			t.Error(err)
		}
	})
	key, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{42}, 32))
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	device := session.BrowserDeviceConfig{Namespace: "totp-device", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(device)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := codec.Issue(t.Context(), now, "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{Header: http.Header{"Set-Cookie": []string{issued.CookieHeader()}}}
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	owner := &native{rate: backend}
	c := TOTPVerifyConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 8192, MaximumDecodedBytes: 8192, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: owner, Rate: limiter, Origin: "https://tenant.example", CallbackURL: "https://tenant.example/login", SessionCookie: cookie, Device: device, ActorID: "ingress", PolicyRevision: 1, Audience: "identity", Now: func() time.Time { return now }, MaximumDuration: time.Second}
	signer, _ := capability.NewHMACSHA256Signer("fixture", []byte(strings.Repeat("x", 32)))
	wire, err := capability.Issue(t.Context(), capability.Payload{Version: 1, ID: "AgICAgICAgICAgICAgICAg", Issuer: "https://issuer.test", Tenant: "tenant-a", Subject: "user-a", Audiences: []string{"identity"}, Resource: "identity.mfa/user-a", Operation: "identity.mfa.complete", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"commandID": "AQEBAQEBAQEBAQEBAQEBAQ", "preAuthID": "AwMDAwMDAwMDAwMDAwMDAw", "challengeID": "AgICAgICAgICAgICAgICAg", "factorID": "BAQEBAQEBAQEBAQEBAQEBA", "token": wire, "code": "123456", "callbackURL": c.CallbackURL, "trustDevice": false})
	return c, owner, string(body), response.Cookies()[0]
}

func TestTOTPHTTPClosedInputAndReplayHaveNoCredentialDelivery(t *testing.T) {
	for _, mode := range []string{"replay", "origin", "idempotency", "duplicate", "unknown-field", "source-denied", "missing-device"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, body, device := handlerFixture(t)
			h, err := NewTOTPVerifyHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "duplicate":
				body = strings.Replace(body, `"code":"123456"`, `"code":"123456","code":"111111"`, 1)
			case "unknown-field":
				body = strings.TrimSuffix(body, "}") + `,"userID":"foreign"}`
			case "source-denied":
				owner.fail = true
			}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
			r.RequestURI = r.URL.RequestURI()
			r.RemoteAddr = "127.0.0.1:4242"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", string(c.Origin))
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			if mode != "missing-device" {
				r.AddCookie(device)
			}
			if mode == "origin" {
				r.Header.Set("Origin", "https://foreign.example")
			}
			if mode == "idempotency" {
				r.Header.Set("Idempotency-Key", "forbidden")
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			w.Header().Set("X-MFA-Token", "injected")
			h.ServeHTTP(w, r)
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("X-MFA-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("denial/replay leaked credentials or cacheable output")
			}
			if mode == "replay" {
				if w.Code != 409 || owner.calls != 1 || owner.reads != 1 || owner.rate.calls != 2 {
					t.Fatal("replay lost ordered native/rate admission", w.Code, owner.calls, owner.reads)
				}
			} else if owner.calls != 0 || w.Code == http.StatusOK {
				t.Fatal("hostile/unadmitted input completed", mode, w.Code)
			}
		})
	}
}
