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
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func proveReferenceEmailOTPChangeHTTPS(t *testing.T, ctx context.Context, f liveStores, options referenceEmailChangeOptions, workers reference.WorkerSet, messages <-chan string, user identity.UserID, original passwordpg.EmailManagementRequest, cookies []*http.Cookie, csrf, oldAddress, oldID string, oldVersion, oldVerification uint64, oldVerified time.Time) {
	t.Helper()
	c := options.configuration
	owner := options.otpChange
	if c.Session == nil || c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil {
		t.Fatal("selected actual session/device owners missing")
	}
	var client *http.Client
	var base, origin string
	if options.httpChange != nil {
		selected := options.httpChange
		if selected.client == nil || selected.server == nil || selected.base == "" || selected.origin == "" {
			t.Fatal("selected reference change HTTPS fixture missing")
		}
		client, base, origin = selected.client, selected.base, selected.origin
		document := string(selected.server.OpenAPI().JSON())
		for _, path := range []string{"/v1/otp/email-change-request", "/v1/otp/email-change-confirm", "/v1/otp/email-change-confirm/recover"} {
			if !strings.Contains(document, path) {
				t.Fatal("selected reference change route absent from OpenAPI")
			}
		}
	} else {
		server := httptest.NewUnstartedServer(nil)
		t.Cleanup(server.Close)
		origin = "https://" + server.Listener.Addr().String()
		backend, err := ratepg.NewStrict(f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		var atomicSchema bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT to_regclass('public.rate_limit_atomic_commands') IS NOT NULL`).Scan(&atomicSchema); err != nil {
			t.Fatal(err)
		}
		if !atomicSchema {
			if _, err := f.pool.Raw().Exec(ctx, ratepg.AtomicSchemaMigration().Up); err != nil {
				t.Fatal("selected native atomic-rate history", err)
			}
		}
		requestRate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "primary-change-http", Key: [32]byte{97}, Now: time.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := requestRate.Close(); err != nil {
				t.Error(err)
			}
		})
		verification, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "primary-change-http", Key: [32]byte{97}, Now: time.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := verification.Close(); err != nil {
				t.Error(err)
			}
		})
		config := otphttp.EmailChangeConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}, Service: owner, Source: owner, RequestRate: requestRate, VerificationRate: verification, Cookie: c.Session.Native.Cookie, Origin: identityhttp.Origin(origin), CSRFKeys: c.Session.CSRFKeys, Device: *c.HTTPPreAuth.Device, PolicyRevision: 9, Now: time.Now, MaximumDuration: 4 * time.Second}
		feature, err := otphttp.NewEmailChangeFeature(config)
		if err != nil {
			t.Fatal("selected primary-change feature", err)
		}
		handler, document, err := identityhttp.NewDocumentedHandler(ctx, identityhttp.DocumentConfig{Title: "Primary change", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal("selected primary-change OpenAPI/dispatcher", err)
		}
		for _, path := range []string{"/v1/otp/email-change-request", "/v1/otp/email-change-confirm", "/v1/otp/email-change-confirm/recover"} {
			if !strings.Contains(string(document.JSON()), path) {
				t.Fatal("selected change route absent from OpenAPI")
			}
		}
		for _, path := range []string{"/v1/otp/send", "/v1/otp/email-verify", "/v1/otp/signin"} {
			if strings.Contains(string(document.JSON()), path) {
				t.Fatal("primary change exposed unselected verification/signin")
			}
		}
		server.Config.Handler = handler
		server.StartTLS()
		client, base = server.Client(), server.URL
	}
	devices, err := session.NewBrowserDeviceCodec(*c.HTTPPreAuth.Device)
	if err != nil {
		t.Fatal(err)
	}
	device, err := devices.Issue(ctx, time.Now(), otpTenant, origin)
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, cookie := range cookies {
		if cookie.Name == "__Host-session" {
			token = cookie.Value
		}
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, parsed)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := options.features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("genuine HTTP source session", err)
	}
	b, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(path string, body any, key string, modify func(*http.Request)) (int, otphttp.EmailChangeResponse) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		r.AddCookie(deviceCookie)
		if modify != nil {
			modify(r)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("actual change HTTPS request", err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(raw) > 16384 {
			t.Fatal("unbounded change response")
		}
		var out otphttp.EmailChangeResponse
		if options.httpChange != nil && response.StatusCode == 403 && response.Header.Get("Content-Type") == "text/plain; charset=utf-8" && string(raw) == "identity.http.origin_denied\n" {
			out.CommitOutcome, out.Error = "none", "origin_or_csrf_denied"
		} else if json.Unmarshal(raw, &out) != nil {
			t.Fatal("invalid change response", response.StatusCode)
		}
		if len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("change response leaked credentials or caching")
		}
		return response.StatusCode, out
	}
	request := map[string]any{"flowID": b.SessionID, "originCommandID": original.Primary.CommandID, "addressID": original.Primary.AddressID}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"flowID":null,"originCommandID":"AQEBAQEBAQEBAQEBAQEBAQ","addressID":"pending"}`, `{"flowID":"a","flowID":"b","originCommandID":"AQEBAQEBAQEBAQEBAQEBAQ","addressID":"pending"}`, `{"flowID":"a","addressID":"pending","addressVersion":1}`, `{"flowID":"a","originCommandID":"AQEBAQEBAQEBAQEBAQEBAQ","addressID":"pending","userID":"override"}`} {
		status, out := invoke("/v1/otp/email-change-request", request, "original-http-change", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		})
		if status != 400 || out.Accepted || out.Changed || out.CommandID != "" {
			t.Fatal("hostile change body entered native issuance", status)
		}
	}
	for _, modify := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") }} {
		status, out := invoke("/v1/otp/email-change-request", request, "original-http-change", modify)
		if status != 403 || out.Accepted || out.Changed {
			t.Fatal("change escaped actual Origin/CSRF", status)
		}
	}
	var beforeNotices int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&beforeNotices); err != nil {
		t.Fatal(err)
	}
	status, sent := invoke("/v1/otp/email-change-request", request, "original-http-change", nil)
	if status != 202 || !sent.Accepted || sent.Changed || sent.CommitOutcome != "committed" || sent.CommandID == "" {
		t.Fatal("actual primary-change HTTP issuance", status, sent.Error)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("actual HTTP-issued change code missing")
	}
	assertEmailChangeOTPRecipient(t, ctx, options.deliveries, code, string(original.Address), oldAddress)
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	confirm := map[string]any{"flowID": b.SessionID, "sendCommandID": sent.CommandID, "code": wrong}
	status, denied := invoke("/v1/otp/email-change-confirm", confirm, "", nil)
	if status != 403 || denied.Changed || denied.CommitOutcome != "not_committed" || denied.Recovery == nil {
		t.Fatal("wrong change code lost counted denial", status, denied.Error)
	}
	status, history := invoke("/v1/otp/email-change-confirm/recover", map[string]any{"flowID": b.SessionID, "recovery": denied.Recovery}, "", nil)
	if status != 200 || history.CommitOutcome != "not_committed" || history.Changed || history.AddressID != "" {
		t.Fatal("denied original HTTP change recovery", status, history.Error)
	}
	status, _ = invoke("/v1/otp/email-change-confirm/recover", map[string]any{"flowID": b.SessionID, "recovery": denied.Recovery, "code": code}, "", nil)
	if status != 400 {
		t.Fatal("change recovery accepted code-bearing variant")
	}
	confirm["code"] = code
	for _, modify := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") }, func(r *http.Request) { r.Header.Set("Authorization", "Bearer forbidden") }} {
		status, out := invoke("/v1/otp/email-change-confirm", confirm, "", modify)
		if status != 400 || out.Changed {
			t.Fatal("change consuming transport accepted alternate credential/key", status)
		}
	}
	status, changed := invoke("/v1/otp/email-change-confirm", confirm, "", nil)
	if status != 200 || !changed.Changed || changed.Accepted || changed.CommitOutcome != "committed" || changed.AddressID != original.Primary.AddressID || changed.AddressVersion != 2 || changed.Recovery == nil {
		t.Fatal("actual primary-change HTTP confirmation", status, changed.Error)
	}
	if options.readSession(cookies) {
		t.Fatal("HTTP primary change preserved pre-confirm session")
	}
	for range 2 {
		status, history = invoke("/v1/otp/email-change-confirm/recover", map[string]any{"flowID": b.SessionID, "recovery": changed.Recovery}, "", nil)
		if status != 200 || history.CommandID != changed.CommandID || history.CommitOutcome != "committed" || history.Changed || history.AddressID != "" {
			t.Fatal("stale-session original HTTP metadata recovery", status, history.Error)
		}
	}
	status, again := invoke("/v1/otp/email-change-request", request, "original-http-change", nil)
	if status != 202 || again.CommandID != sent.CommandID || again.Changed {
		t.Fatal("terminal original HTTP Send lost custody", status, again.Error)
	}
	var primaries, retained, notices, used, failed int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND is_primary`, otpTenant, string(user)).Scan(&primaries); err != nil || primaries != 1 {
		t.Fatal("HTTP change ambiguous primary", err)
	}
	retainedVersion := oldVersion
	if !options.initialPrimary {
		retainedVersion++
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND verified AND NOT is_primary AND verified_at=$6`, otpTenant, string(user), oldID, retainedVersion, oldVerification, oldVerified).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("HTTP change rewrote old verification history", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 2 || failed != 1 {
		t.Fatal("HTTP recovery repeated attempt debit", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != beforeNotices+1 {
		t.Fatal("HTTP change/recovery duplicated notice", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-messages:
		if body != emailChangeNotice {
			t.Fatal("old notice disclosed code/link")
		}
	case <-ctx.Done():
		t.Fatal("old notice missing")
	}
	select {
	case recipient := <-options.recipients:
		if recipient != oldAddress {
			t.Fatal("HTTP change notified substituted recipient")
		}
	case <-ctx.Done():
		t.Fatal("old recipient absent")
	}
}
