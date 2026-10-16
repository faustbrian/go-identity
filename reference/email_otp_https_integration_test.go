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
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

type emailOTPHTTPSSelection struct {
	client       *http.Client
	base, origin string
	server       *reference.Server
}

func proveReferenceEmailOTPHTTPS(t *testing.T, ctx context.Context, f liveStores, owner *reference.EmailOTPVerificationService, workers reference.WorkerSet, messages <-chan string, user identity.UserID, pending identity.IdentifierID, cookies []*http.Cookie, readSession func([]*http.Cookie) bool, config reference.StoreConfiguration, csrf, sessionID string, selected ...emailOTPHTTPSSelection) {
	t.Helper()
	if len(selected) > 1 {
		t.Fatal("mixed HTTP fixture ownership")
	}
	var client *http.Client
	var base, origin string
	if len(selected) == 1 {
		h := selected[0]
		if h.client == nil || h.server == nil || h.base == "" || h.origin == "" {
			t.Fatal("selected reference HTTP fixture missing")
		}
		client, base, origin = h.client, h.base, h.origin
		document := string(h.server.OpenAPI().JSON())
		for _, path := range []string{"/v1/otp/send", "/v1/otp/email-verify", "/v1/otp/email-verify/recover"} {
			if !strings.Contains(document, path) {
				t.Fatal("selected reference OTP route missing from OpenAPI")
			}
		}
		if strings.Contains(document, "/v1/otp/signin") {
			t.Fatal("verification selected unwanted OTP signin HTTP")
		}
	} else {
		server := httptest.NewUnstartedServer(nil)
		t.Cleanup(server.Close)
		origin = "https://" + server.Listener.Addr().String()
		backend, err := ratepg.NewStrict(f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		// These handlers are public consumers of existing native rate storage. The
		// full reference selection below must supply this optional owner's migration.
		var atomicSchema bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT to_regclass('public.rate_limit_atomic_commands') IS NOT NULL`).Scan(&atomicSchema); err != nil {
			t.Fatal(err)
		}
		if !atomicSchema {
			if _, err := f.pool.Raw().Exec(ctx, ratepg.AtomicSchemaMigration().Up); err != nil {
				t.Fatal("selected native atomic rate history", err)
			}
		}
		delivery, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "reference-email-otp-http", IdentifierKey: [32]byte{91}, Now: time.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := delivery.Close(); err != nil {
				t.Error("delivery limiter cleanup", err)
			}
		})
		verification, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "reference-email-otp-http", Key: [32]byte{91}, Now: time.Now, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := verification.Close(); err != nil {
				t.Error("verification limiter cleanup", err)
			}
		})
		if config.HTTPPreAuth == nil || config.HTTPPreAuth.Device == nil || config.Session == nil {
			t.Fatal("actual selected session/device configuration missing")
		}
		c := otphttp.EmailVerificationConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}, Service: owner, Source: owner, DeliveryRate: delivery, VerificationRate: verification, Cookie: config.Session.Native.Cookie, Origin: identityhttp.Origin(origin), CSRFKeys: config.Session.CSRFKeys, Device: *config.HTTPPreAuth.Device, PolicyRevision: 9, Now: time.Now, MaximumDuration: 4 * time.Second}
		start, err := otphttp.NewEmailVerificationSendHandler(c)
		if err != nil {
			t.Fatal("selected send handler", err)
		}
		finish, err := otphttp.NewEmailVerifyHandler(c)
		if err != nil {
			t.Fatal("selected verification handler", err)
		}
		recover, err := otphttp.NewEmailVerifyRecoveryHandler(c)
		if err != nil {
			t.Fatal("selected recovery handler", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/v1/otp/send", start)
		mux.Handle("/v1/otp/email-verify", finish)
		mux.Handle("/v1/otp/email-verify/recover", recover)
		server.Config.Handler = mux
		server.StartTLS()
		client, base = server.Client(), server.URL
	}
	devices, err := session.NewBrowserDeviceCodec(*config.HTTPPreAuth.Device)
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
	invoke := func(path string, body any, key string, modify func(*http.Request)) (int, otphttp.EmailVerificationResponse) {
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
			t.Fatal("actual HTTPS request", err)
		}
		defer response.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(bodyBytes) > 16384 {
			t.Fatal("unbounded response")
		}
		var out otphttp.EmailVerificationResponse
		if len(selected) == 1 && response.StatusCode == 403 && response.Header.Get("Content-Type") == "text/plain; charset=utf-8" && string(bodyBytes) == "identity.http.origin_denied\n" {
			// The existing outer CORS owner rejects foreign Origin before the
			// feature's JSON pipeline. Preserve that stricter, fixed denial.
			out.CommitOutcome, out.Error = "none", "origin_or_csrf_denied"
		} else if json.Unmarshal(bodyBytes, &out) != nil {
			t.Fatal("invalid private-safe response", path, response.StatusCode, response.Header.Get("Content-Type"), len(bodyBytes))
		}
		if len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("verification transport leaked credentials or caching")
		}
		return response.StatusCode, out
	}
	sendBody := map[string]any{"flowID": sessionID, "addressID": pending, "addressVersion": 1}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"flowID":null,"addressID":"pending","addressVersion":1}`, `{"flowID":"a","flowID":"b","addressID":"pending","addressVersion":1}`, `{"flowID":"a","addressID":"pending","addressVersion":1,"userID":"override"}`, `{"flowID":"a","addressID":"pending","addressVersion":"1"}`, `{"flowID":`} {
		status, out := invoke("/v1/otp/send", sendBody, "http-original-send", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		})
		if status != 400 || out.Accepted || out.Verified || out.CommandID != "" {
			t.Fatal("hostile Send body reached native issuance", status)
		}
	}
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.example") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") }} {
		status, out := invoke("/v1/otp/send", sendBody, "http-original-send", mutate)
		if status != 403 || out.Accepted || out.Verified {
			t.Fatal("send escaped original session CSRF/origin")
		}
	}
	status, sent := invoke("/v1/otp/send", sendBody, "http-original-send", nil)
	if status != 202 || !sent.Accepted || sent.Verified || sent.CommitOutcome != "committed" || sent.CommandID == "" {
		t.Fatal("actual HTTP OTP send", status)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("actual HTTP-issued code missing")
	}
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	verifyBody := map[string]any{"flowID": sessionID, "sendCommandID": sent.CommandID, "code": wrong}
	status, denied := invoke("/v1/otp/email-verify", verifyBody, "", nil)
	if status != 403 || denied.Verified || denied.CommitOutcome != "not_committed" || denied.Recovery == nil {
		t.Fatal("wrong HTTP code lost counted denial", status)
	}
	status, history := invoke("/v1/otp/email-verify/recover", map[string]any{"flowID": sessionID, "recovery": denied.Recovery}, "", nil)
	if status != 200 || history.CommitOutcome != "not_committed" || history.Verified || history.AddressID != "" {
		t.Fatal("original denied HTTP recovery", status)
	}
	status, extra := invoke("/v1/otp/email-verify/recover", map[string]any{"flowID": sessionID, "recovery": denied.Recovery, "code": code}, "", nil)
	if status != 400 || extra.Verified || extra.CommandID != "" {
		t.Fatal("metadata recovery accepted a code-bearing alternative", status)
	}
	verifyBody["code"] = code
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") }, func(r *http.Request) { r.Header.Set("Authorization", "Bearer forbidden") }} {
		status, out := invoke("/v1/otp/email-verify", verifyBody, "", mutate)
		if status != 400 || out.Verified {
			t.Fatal("verification accepted alternate custody or key", status)
		}
	}
	status, verified := invoke("/v1/otp/email-verify", verifyBody, "", nil)
	if status != 200 || !verified.Verified || verified.Accepted || verified.AddressID != pending || verified.AddressVersion != 2 || verified.CommitOutcome != "committed" || verified.Recovery == nil {
		t.Fatal("actual delivered-code HTTP verification", status)
	}
	if readSession(cookies) {
		t.Fatal("HTTP verified mutation preserved stale session authority")
	}
	status, history = invoke("/v1/otp/email-verify/recover", map[string]any{"flowID": sessionID, "recovery": verified.Recovery}, "", nil)
	if status != 200 || history.CommitOutcome != "committed" || history.Verified || history.AddressID != "" || history.CommandID != verified.CommandID {
		t.Fatal("committed HTTP recovery required executable session or re-executed", status)
	}
	status, replay := invoke("/v1/otp/send", sendBody, "http-original-send", nil)
	if status != 202 || replay.CommandID != sent.CommandID || !replay.Accepted || replay.Verified {
		t.Fatal("HTTP send retry retargeted mutable address", status)
	}
	var used, failed int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 2 || failed != 1 {
		t.Fatal("HTTP/recovery repeated or omitted code charges", err)
	}
}

var _ otp.EmailVerificationService = (*reference.EmailOTPVerificationService)(nil)
