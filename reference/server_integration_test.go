//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identifier "github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

type nativeServerTenant struct{ foreign atomic.Bool }

func (r *nativeServerTenant) ResolveTenant(ctx context.Context) (identity.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.foreign.Load() {
		return "other", nil
	}
	return otpTenant, nil
}

// This case uses the sole public composition graph, native contributed
// migrations and graph-owned rate/issuer resources. No application handler,
// rate backend or domain-store override supplies the initiation workflow.
func TestReferenceServerNativeOriginalFlow(t *testing.T) {
	testNativeServerOriginalFlow(t, false)
}

func TestReferenceServerNativeEmailSignin(t *testing.T) {
	testNativeServerOriginalFlow(t, true)
}

func testNativeServerOriginalFlow(t *testing.T, consuming bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	configureReferencePreAuth(t, &c)
	networkServer := httptest.NewUnstartedServer(nil)
	t.Cleanup(networkServer.Close)
	origin := "https://" + networkServer.Listener.Addr().String()
	c.OTP.PreAuth.Origin = origin
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-server-native", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	c.HTTPPreAuth = &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}
	codes := make(chan string, 1)
	if consuming {
		configureReferenceSignin(t, &c)
		c.OTP.RequestKeys.Policy.Authorization = otpReferenceSigninPolicy{}
		profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "reference-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		key, err := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{0x6b}, 32))
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
		if err != nil {
			t.Fatal(err)
		}
		c.HTTPPreAuth.Device = &session.BrowserDeviceConfig{Namespace: "reference-server-native", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: cookie}
		c.HTTPEmailSignin = &reference.HTTPEmailSigninConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9, TargetID: "login", Address: email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile}}
		deps.DeliverySender = nativeBrowserCodeSender{codes: codes}
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	base := c
	baseOTP := *c.OTP
	baseOTP.PreAuth = nil
	base.OTP, base.HTTPPreAuth, base.HTTPRate, base.HTTPEmailSignin = &baseOTP, nil, nil, nil
	baseStores, err := reference.ComposeStores(base, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := baseStores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	installOTPGraphFixture(t, ctx, f, baseStores)
	request := applyRequest(t, ctx, stores, []reference.ModuleID{"identity/session/postgres", "rate-limit/postgres"})
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("native selected migration", err)
	}
	tenant := &nativeServerTenant{}
	policies := identity.PolicySet{Authorize: c.OTP.RequestKeys.Policy.Authorization,
		AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			panic("unused risk callback")
		},
		MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			panic("unused claims callback")
		},
		DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			panic("unused retention callback")
		},
		Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			panic("unused redaction callback")
		}}
	config := reference.ReferenceConfig{Profile: reference.PostgresWithValkey, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Reference native", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: tenant}}
	if consuming {
		config.HTTP.Network.Limits.MaximumFields = 44
		config.HTTP.Network.Limits.MaximumDepth = 3
	}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("native server construction", err)
	}
	expectedOperations := 3
	if consuming {
		expectedOperations = 6
	}
	if len(server.OpenAPI().Operations()) != expectedOperations || !strings.Contains(string(server.OpenAPI().JSON()), "/v1/session/preauth-issue") {
		t.Fatal("selected server metadata")
	}
	networkServer.Config.Handler = server.Handler()
	networkServer.StartTLS()
	client := networkServer.Client()
	client.Timeout = 5 * time.Second
	call := func() (*http.Response, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "POST", networkServer.URL+"/v1/session/preauth-issue", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if err != nil || len(payload) > 16384 {
			t.Fatal("bounded response", err)
		}
		return response, payload
	}
	response, _ := call()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("uninitialized server admitted", response.StatusCode)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if consuming {
		if owner, err := stores.RecoverVelocity(ctx, otpTenant); err == nil || owner != nil {
			t.Fatal("fresh coverage manufactured")
		}
		// This fixture seeds historical coverage in its disposable database; it
		// does not claim a fresh production journal is eligible without warmup.
		if _, err := f.pool.Raw().Exec(ctx, "UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '61 minutes' WHERE tenant_id=$1 AND state='replaying'", otpTenant); err != nil {
			t.Fatal(err)
		}
		wait(ctx, t, 6*time.Second)
		if owner, err := stores.RecoverVelocity(ctx, otpTenant); err != nil || owner == nil {
			t.Fatal("historical native activation", err)
		}
	}
	tenant.foreign.Store(true)
	response, _ = call()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("conflicting tenant reached workflow", response.StatusCode)
	}
	var count int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM session_store.preauth_transactions").Scan(&count); err != nil || count != 0 {
		t.Fatal("denied tenant wrote flow", err)
	}
	tenant.foreign.Store(false)
	response, payload := call()
	var out sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(payload, &out) != nil || !out.Issued || out.CommitOutcome != "committed" || out.FlowID == "" {
		t.Fatal("native server issuance", response.StatusCode)
	}
	cookies := response.Cookies()
	expectedCookies := 1
	if consuming {
		expectedCookies = 2
	}
	if len(cookies) != expectedCookies {
		t.Fatal("server credential custody")
	}
	for _, cookie := range cookies {
		if cookie.Name != "__Host-identity_flow" && cookie.Name != "__Host-identity_device" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || strings.Contains(string(payload), cookie.Value) {
			t.Fatal("server credential custody")
		}
	}
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2 AND state='issued'", otpTenant, string(out.FlowID)).Scan(&count); err != nil || count != 1 {
		t.Fatal("server durable issuance", err)
	}
	if consuming {
		proveNativeServerEmailSignin(t, ctx, f, workers, client, networkServer.URL, origin, out, cookies, codes)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	response, _ = call()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("closed server issued credential", response.StatusCode)
	}
}

type nativeBrowserCodeSender struct{ codes chan<- string }

func (s nativeBrowserCodeSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	select {
	case s.codes <- a.Body:
		return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
	case <-ctx.Done():
		return delivery.DeliveryResult{}, ctx.Err()
	}
}

func proveNativeServerEmailSignin(t *testing.T, ctx context.Context, f liveStores, workers reference.WorkerSet, client *http.Client, baseURL, origin string, flow sessionhttp.PreAuthResponse, cookies []*http.Cookie, codes <-chan string) {
	t.Helper()
	call := func(path string, body any, key string, selectedCookies []*http.Cookie, requestOrigin string) (*http.Response, []byte) {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal("request serialization")
		}
		r, err := http.NewRequestWithContext(ctx, "POST", baseURL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", requestOrigin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range selectedCookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("native browser request", err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if err != nil || len(payload) > 16384 {
			t.Fatal("bounded browser response")
		}
		return response, payload
	}
	sendBody := map[string]any{"flowID": flow.FlowID, "email": "recipient@example.invalid"}
	flowOnly := []*http.Cookie{}
	for _, cookie := range cookies {
		if cookie.Name == "__Host-identity_flow" {
			flowOnly = append(flowOnly, cookie)
		}
	}
	for _, denied := range []struct {
		cookies []*http.Cookie
		origin  string
		status  int
	}{{flowOnly, origin, 400}, {cookies, "https://foreign.example", 403}} {
		response, _ := call("/v1/otp/send", sendBody, "browser-send-001", denied.cookies, denied.origin)
		if response.StatusCode != denied.status || len(response.Cookies()) != 0 {
			t.Fatal("unsafe Send admitted", response.StatusCode)
		}
	}
	response, payload := call("/v1/otp/send", sendBody, "browser-send-001", cookies, origin)
	var sent otphttp.SendResponse
	if response.StatusCode != 202 || json.Unmarshal(payload, &sent) != nil || !sent.Accepted || sent.CommitOutcome != "committed" || sent.CommandID == "" || len(response.Cookies()) != 0 {
		t.Fatal("native HTTP Send", response.StatusCode)
	}
	before := nativeAttemptFacts(t, ctx, f)
	response, replayPayload := call("/v1/otp/send", sendBody, "browser-send-001", cookies, origin)
	var replay otphttp.SendResponse
	if response.StatusCode != 202 || json.Unmarshal(replayPayload, &replay) != nil || replay != sent || nativeAttemptFacts(t, ctx, f) != before {
		t.Fatal("HTTP Send replay changed native authority")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("native browser delivery", err)
	}
	var code string
	select {
	case code = <-codes:
	case <-ctx.Done():
		t.Fatal("native sender did not receive code")
	}
	if len(code) != 6 {
		t.Fatal("selected code profile")
	}
	signinBody := map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": code}
	response, payload = call("/v1/otp/signin", signinBody, "", cookies, origin)
	var signed otphttp.SigninResponse
	if response.StatusCode != 200 || json.Unmarshal(payload, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || signed.SessionID == "" || signed.Recovery == nil {
		t.Fatal("native HTTP signin", response.StatusCode)
	}
	issued := response.Cookies()
	csrf := response.Header.Get("X-CSRF-Token")
	if len(issued) != 1 || issued[0].Name != "__Host-session" || !issued[0].Secure || !issued[0].HttpOnly || issued[0].Path != "/" || issued[0].Domain != "" || issued[0].MaxAge != 0 || !issued[0].Expires.IsZero() || csrf == "" || strings.Contains(string(payload), issued[0].Value) || strings.Contains(string(payload), csrf) || strings.Contains(string(payload), `"`+code+`"`) {
		t.Fatal("native signin credential disclosure")
	}
	var finalized, consumed, sessions int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT (SELECT count(*) FROM otp_store.challenges WHERE state='finalized'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM session_store.session_issuances)").Scan(&finalized, &consumed, &sessions); err != nil || finalized != 1 || consumed != 1 || sessions != 1 {
		t.Fatal("native browser effects diverged", err)
	}
	response, payload = call("/v1/otp/signin/recover", map[string]any{"flowID": flow.FlowID, "recovery": signed.Recovery}, "", cookies, origin)
	var recovered otphttp.SigninResponse
	if response.StatusCode != 200 || json.Unmarshal(payload, &recovered) != nil || recovered.SessionID != signed.SessionID || recovered.SignedIn || recovered.CommitOutcome != "committed" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("native historical recovery redelivered credentials", response.StatusCode)
	}
	response, _ = call("/v1/otp/signin", signinBody, "", cookies, origin)
	if response.StatusCode != 503 || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("consumed flow issued again", response.StatusCode)
	}
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM session_store.session_issuances").Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("replay added session", err)
	}
}
