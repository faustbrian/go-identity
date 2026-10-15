//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/mfa"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// Transport borrows actual native owners and a real PostgreSQL strict limiter.
// The only captured external seam is the explicit email sender in the parent
// journey. No domain service, transaction participant or session is replaced.
type otpHTTPJourney struct {
	proofWire    string
	device       session.BrowserDevice
	deviceCookie *http.Cookie
	sendConfig   mfahttp.OTPSendConfig
	verifyConfig mfahttp.OTPVerifyConfig
}

func (f *otpHTTPJourney) captureProof(t *testing.T, ctx context.Context, r *mfa.OtpSendRequest) {
	t.Helper()
	// Transport consumes opaque result custody. The client keeps its explicit
	// wire copy and parses a new submitted value for each native retry; reusing
	// the transferred alias would test an invalid input rather than replay.
	if err := r.Proof.Transfer(ctx, func(_ context.Context, wire []byte) error {
		f.proofWire = string(wire)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var err error
	r.Proof, err = capability.ParseProof(f.proofWire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.proofWire = "" })
}

func newOTPHTTPJourney(t *testing.T, ctx context.Context, pool *database.Pool, tenant identity.TenantID, origin, callback, network string, cookie session.CookiePolicy, audience string, caller authorization.DecisionContext) *otpHTTPJourney {
	t.Helper()
	key, err := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{125}, 32))
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	deviceConfig := session.BrowserDeviceConfig{Namespace: "secondary-otp-http", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(ctx, time.Now(), tenant, origin)
	if err != nil {
		t.Fatal(err)
	}
	cookies := (&http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}).Cookies()
	if len(cookies) != 1 {
		t.Fatal("original device cookie unavailable")
	}
	var installed bool
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('public.rate_limit_states') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		if _, err := pool.Raw().Exec(ctx, ratepg.SchemaMigration().Up); err != nil {
			t.Fatal("native strict limiter migration unavailable", err)
		}
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('public.rate_limit_atomic_commands') IS NOT NULL`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		if _, err := pool.Raw().Exec(ctx, ratepg.AtomicSchemaMigration().Up); err != nil {
			t.Fatal("native atomic verification quota migration unavailable", err)
		}
	}
	backend, err := ratepg.OpenStrict(ctx, pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal("native strict HTTP limiter unavailable", err)
	}
	sendRate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "secondary-otp-send-http", IdentifierKey: [32]byte{126}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	verifyRate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "secondary-otp-verify-http", Key: [32]byte{127}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sendRate.Close(); err != nil {
			t.Error(err)
		}
		if err := verifyRate.Close(); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || net.ParseIP(network) == nil {
		t.Fatal("native browser network unavailable")
	}
	n := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: u.Hostname(), TenantID: tenant}}}
	return &otpHTTPJourney{device: device, deviceCookie: cookies[0], sendConfig: mfahttp.OTPSendConfig{Network: n, Rate: sendRate, Origin: identityhttp.Origin(origin), CallbackURL: callback, Device: deviceConfig, ActorID: identity.ActorID(caller.Request.Subject.ID), PolicyRevision: caller.PolicyRevision, Now: time.Now, MaximumDuration: 3 * time.Second}, verifyConfig: mfahttp.OTPVerifyConfig{Network: n, Rate: verifyRate, Origin: identityhttp.Origin(origin), CallbackURL: callback, Device: deviceConfig, ActorID: identity.ActorID(caller.Request.Subject.ID), PolicyRevision: caller.PolicyRevision, Now: time.Now, MaximumDuration: 3 * time.Second, SessionCookie: cookie, Audience: audience}}
}

func (f *otpHTTPJourney) request(t *testing.T, ctx context.Context, path, network, cookie string, body map[string]any) *http.Request {
	t.Helper()
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal("HTTP input encoding failed")
	}
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, string(f.sendConfig.Origin)+path, bytes.NewReader(wire))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = net.JoinHostPort(network, "44321")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", string(f.sendConfig.Origin))
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: cookie})
	r.AddCookie(f.deviceCookie)
	return r
}

func (f *otpHTTPJourney) send(t *testing.T, ctx context.Context, native *reference.PasswordOTPLoginSendService, r mfa.OtpSendRequest) mfa.OtpSendResult {
	t.Helper()
	c := f.sendConfig
	c.Service = native
	feature, err := mfahttp.NewFeature(mfahttp.FeatureConfig{OTPSend: &c})
	if err != nil {
		t.Fatal("selected native HTTP sending unavailable", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	request := f.request(t, ctx, "/v1/mfa/otp-send", r.Network, r.Cookie.Token(), map[string]any{"preAuthID": r.PreAuthID, "continuationID": r.ContinuationID, "factorID": r.FactorID, "channel": "email", "token": f.proofWire, "callbackURL": r.Callback})
	// Browser-owned input was captured before constructing its opaque native
	// representation; the public type intentionally has no secret accessor.
	request.Header.Set("Idempotency-Key", "actual-password-otp-send-after-cooldown")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	var out mfahttp.OTPSendResponse
	if json.Unmarshal(response.Body.Bytes(), &out) != nil || response.Code != http.StatusAccepted || !out.Accepted || out.CommitOutcome != "committed" || out.DeliveryState != "queued" || response.Header().Get("Cache-Control") != "no-store" || len(response.Result().Cookies()) != 0 {
		t.Fatalf("selected HTTP did not queue native delivery without credentials: status=%d error=%s", response.Code, out.Error)
	}
	unselected := httptest.NewRecorder()
	h.ServeHTTP(unselected, f.request(t, ctx, "/v1/mfa/otp-verify", r.Network, r.Cookie.Token(), map[string]any{}))
	if unselected.Code != http.StatusNotFound {
		t.Fatal("send-only selection exposed verification")
	}
	return mfa.OtpSendResult{CommandID: out.CommandID, Outcome: identity.CommitOutcomeCommitted, DeliveryState: delivery.StateQueued, ChallengeID: out.ChallengeID}
}

func (f *otpHTTPJourney) complete(t *testing.T, ctx context.Context, pool *database.Pool, source passwordpg.ReauthenticationConfig, native *reference.PasswordOTPLoginCompletionService, r mfa.OtpVerifyRequest, code string) {
	t.Helper()
	c := f.verifyConfig
	c.Service = native
	feature, err := mfahttp.NewFeature(mfahttp.FeatureConfig{OTPVerify: &c})
	if err != nil {
		t.Fatal("selected native HTTP completion unavailable", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"commandID": r.CommandID, "preAuthID": r.PreAuthID, "continuationID": r.ContinuationID, "token": f.proofWire, "code": code, "callbackURL": r.Callback, "trustDevice": false}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, f.request(t, ctx, "/v1/mfa/otp-verify", r.Network, r.Cookie.Token(), body))
	var out mfahttp.OTPVerifyResponse
	if json.Unmarshal(response.Body.Bytes(), &out) != nil || response.Code != http.StatusOK || !out.SignedIn || out.CommitOutcome != "committed" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("actual delivered OTP did not authenticate over selected HTTP: status=%d error=%s outcome=%s", response.Code, out.Error, out.CommitOutcome)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatal("HTTP session cookie lost secure custody")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("HTTP bearer missing")
	}
	if _, err := session.ParseCSRFToken(response.Header().Get("X-CSRF-Token")); err != nil {
		t.Fatal("HTTP synchronizer missing")
	}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: source.Profile.Audience, Clock: clock.System{}, MaximumDuration: source.Session.MaximumDuration, ClockUncertainty: time.Millisecond, LookupKeys: source.LookupKeys}
	reader, err := sessionpg.NewSelectedSessionService(pool, sessionpg.SelectedSessionServiceConfig{Repository: source.Session, Validation: validation, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: sessionpg.SingleFactorSessionAdmissionConfig{Verified: &source.Profile}, MFAPassword: &source.Profile}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	get := session.GetRequest{TenantID: r.TenantID, Credential: credential}
	current, err := reader.Get(ctx, get)
	if err != nil || !current.Authenticated {
		t.Fatal("HTTP-issued session not accepted by public selected reader", err)
	}
	bindings, err := current.Session.Bindings()
	factor, factorErr := current.Session.MFAAuthentication().Bindings()
	if err != nil || factorErr != nil || factor.Method != "otp" || bindings.Authentication.Proof.Method != "password" {
		t.Fatal("HTTP session lost native primary/factor provenance")
	}
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, f.request(t, ctx, "/v1/mfa/otp-verify", r.Network, r.Cookie.Token(), body))
	var replayOut mfahttp.OTPVerifyResponse
	if json.Unmarshal(replay.Body.Bytes(), &replayOut) != nil || replayOut.SignedIn || len(replay.Result().Cookies()) != 0 || replay.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP replay redelivered credentials")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(bindings.TenantID), string(bindings.UserID)); err != nil {
		t.Fatal(err)
	}
	if current, err := reader.Get(ctx, get); err != nil || current.Authenticated {
		t.Fatal("HTTP session survived factor authority invalidation", err)
	}
	if strings.Contains(response.Body.String(), code) || strings.Contains(response.Body.String(), f.proofWire) || strings.Contains(response.Body.String(), cookies[0].Value) {
		t.Fatal("HTTP metadata disclosed credential material")
	}
}
