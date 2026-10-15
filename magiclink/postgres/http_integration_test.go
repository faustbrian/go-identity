//go:build integration

package magiclinkpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	magiclinkhttp "github.com/faustbrian/go-identity/http/magiclink"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This extends the native journey with the real selected router, decoder,
// PostgreSQL strict rate owner, encrypted delivery and current session reader.
// Configured risk signal callbacks remain the suite's explicit input boundary;
// no native domain store or consuming workflow is replaced here.
func exerciseMagicLinkHTTPPostgres(t *testing.T, ctx context.Context, pool *database.Pool, requestOwner *RequestService, consumeOwner *ConsumeService, config RequestConfig, crypto *envelope.Service, original session.PreAuthBinding, flowKey, lookup session.DigestKey, cookiePolicy session.CookiePolicy) {
	t.Helper()
	var rateInstalled bool
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('public.rate_limit_states') IS NOT NULL`).Scan(&rateInstalled); err != nil {
		t.Fatal(err)
	}
	if !rateInstalled {
		if _, err := pool.Raw().Exec(ctx, ratepg.SchemaMigration().Up); err != nil {
			t.Fatal("strict HTTP rate history", err)
		}
		if _, err := pool.Raw().Exec(ctx, ratepg.AtomicSchemaMigration().Up); err != nil {
			t.Fatal("atomic HTTP rate history", err)
		}
	}
	backend, err := ratepg.NewStrict(pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 250 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: 250 * time.Millisecond})
	if err != nil {
		t.Fatal("strict HTTP rate owner", err)
	}
	requestRate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "magic-http", IdentifierKey: [32]byte{107}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer requestRate.Close()
	consumeRate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "magic-http", Key: [32]byte{108}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer consumeRate.Close()
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 8192, MaximumDecodedBytes: 8192, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "app.test", TenantID: requestTestTenant}}}
	deviceKey, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{112}, 32))
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	deviceConfig := session.BrowserDeviceConfig{Namespace: "magic-http-device", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	deviceCodec, _ := session.NewBrowserDeviceCodec(deviceConfig)
	device, err := deviceCodec.Issue(ctx, time.Now(), requestTestTenant, "https://app.test")
	if err != nil {
		t.Fatal(err)
	}
	deviceResponse := &http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	feature, err := magiclinkhttp.NewFeature(magiclinkhttp.FeatureConfig{
		Request: &magiclinkhttp.RequestConfig{Network: network, Service: requestOwner, Rate: requestRate, Origin: "https://app.test", CallbackURL: "https://app.test/login", ActorID: "ingress", PolicyRevision: 3, Device: deviceConfig, Now: time.Now, MaximumDuration: 3 * time.Second},
		Consume: &magiclinkhttp.ConsumeConfig{Network: network, Service: consumeOwner, Rate: consumeRate, Origin: "https://app.test", CallbackURL: "https://app.test/login", SessionCookie: cookiePolicy, Device: deviceConfig, ActorID: "ingress", PolicyRevision: 3, Audience: "identity", Now: time.Now, MaximumDuration: 3 * time.Second, MFAContinuation: consumeOwner.config.MFA != nil},
	})
	if err != nil {
		t.Fatal("actual selected feature", err)
	}
	handler, document, err := identityhttp.NewDocumentedHandler(ctx, identityhttp.DocumentConfig{Title: "Native magic-link", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(document.Operations()) != 2 {
		t.Fatal("actual router/document", err)
	}
	flowID, _ := identity.NewPreAuthTransactionID()
	flow := original
	flow.ID = flowID
	flow.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	flow.ExpiresAt = flow.IssuedAt.Add(5 * time.Minute)
	flow.Intent.Nonce = [32]byte{109}
	cookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{110}, 32))
	cookieToken, _ := session.ParseToken(cookie)
	digest, _ := cookieToken.PreAuthDigest(flowKey, flow)
	preauth, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: flow, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, requestTestTx{pool}, config.Session, preauth) != nil {
		t.Fatal("original HTTP browser fixture", err)
	}
	requestID, _ := identity.NewCommandID()
	requestJSON, _ := json.Marshal(map[string]string{"commandID": string(requestID), "preAuthID": string(flowID), "email": "person@example.test", "intent": "signin-only", "callbackURL": "https://app.test/login"})
	call := func(path string, body []byte, key string, cookieValue string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://app.test"+path, bytes.NewReader(body)).WithContext(ctx)
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://app.test")
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: cookieValue})
		r.AddCookie(deviceResponse.Cookies()[0])
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	ack := call("/v1/magic-link/request", requestJSON, string(requestID), cookie)
	var acknowledged magiclinkhttp.RequestResponse
	if json.Unmarshal(ack.Body.Bytes(), &acknowledged) != nil || ack.Code != 200 || !acknowledged.Accepted || acknowledged.CommitOutcome != "committed" || len(ack.Result().Cookies()) != 0 || strings.Contains(ack.Body.String(), "person@example.test") {
		t.Fatal("native HTTP request failed or leaked recipient", ack.Code)
	}
	proof := captureMagicLinkDelivery(t, ctx, pool, config, crypto, true)
	var wire string
	if err := proof.Transfer(ctx, func(_ context.Context, material []byte) error { wire = string(material); return nil }); err != nil {
		t.Fatal("captured HTTP delivery custody", err)
	}
	oldWire := wire
	resendID, _ := identity.NewCommandID()
	resendJSON, _ := json.Marshal(map[string]string{"commandID": string(resendID), "preAuthID": string(flowID), "email": "person@example.test", "intent": "signin-only", "callbackURL": "https://app.test/login"})
	resent := call("/v1/magic-link/request", resendJSON, string(resendID), cookie)
	var replacement magiclinkhttp.RequestResponse
	if json.Unmarshal(resent.Body.Bytes(), &replacement) != nil || resent.Code != 200 || !replacement.Accepted || replacement.CommitOutcome != "committed" {
		t.Fatal("native resend request failed", resent.Code)
	}
	replacementProof := captureMagicLinkDelivery(t, ctx, pool, config, crypto, true)
	if err := replacementProof.Transfer(ctx, func(_ context.Context, material []byte) error { wire = string(material); return nil }); err != nil {
		t.Fatal("resend delivery custody", err)
	}
	oldConsumeID, _ := identity.NewCommandID()
	oldJSON, _ := json.Marshal(map[string]string{"commandID": string(oldConsumeID), "preAuthID": string(flowID), "token": oldWire, "callbackURL": "https://app.test/login"})
	var beforeSuperseded int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM magic_sessions.sessions`).Scan(&beforeSuperseded); err != nil {
		t.Fatal(err)
	}
	oldResult := call("/v1/magic-link/consume", oldJSON, "", cookie)
	var oldResponse magiclinkhttp.ConsumeResponse
	if json.Unmarshal(oldResult.Body.Bytes(), &oldResponse) != nil || oldResult.Code != http.StatusConflict || oldResponse.Error != "superseded" || oldResponse.SignedIn || len(oldResult.Result().Cookies()) != 0 || oldResult.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("superseded original HTTP link delivered credentials", oldResult.Code)
	}
	var afterSuperseded, oldUses int
	var supersededBy string
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_sessions.sessions),uses,superseded_by_command_id FROM capability_identity_one_use WHERE origin_command_id=$1`, string(acknowledged.CommandID)).Scan(&afterSuperseded, &oldUses, &supersededBy); err != nil || afterSuperseded != beforeSuperseded || oldUses != 0 || supersededBy != string(replacement.CommandID) {
		t.Fatal("superseded HTTP attempt changed atomic state or lost original provenance", err)
	}
	acknowledged = replacement
	consumeID, _ := identity.NewCommandID()
	consumeJSON, _ := json.Marshal(map[string]string{"commandID": string(consumeID), "preAuthID": string(flowID), "token": wire, "callbackURL": "https://app.test/login"})
	var before int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM magic_sessions.sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	denied := call("/v1/magic-link/consume", consumeJSON, "", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{111}, 32)))
	if denied.Code == 200 || len(denied.Result().Cookies()) != 0 || denied.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("foreign HTTP browser logged in", denied.Code)
	}
	var after, remaining int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_sessions.sessions),max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(acknowledged.CommandID)).Scan(&after, &remaining); err != nil || after != before || remaining != 1 {
		t.Fatal("foreign HTTP browser mutated native effects", err)
	}
	result := call("/v1/magic-link/consume", consumeJSON, "", cookie)
	var signedIn magiclinkhttp.ConsumeResponse
	if consumeOwner.config.MFA != nil {
		if json.Unmarshal(result.Body.Bytes(), &signedIn) != nil || result.Code != http.StatusOK || signedIn.SignedIn || !signedIn.ChallengeRequired || signedIn.ChallengeMethod != "totp" || signedIn.CommitOutcome != "committed" || len(result.Result().Cookies()) != 0 || result.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("native HTTP MFA primary authenticated or failed", result.Code)
		}
		childWire := result.Header().Get("X-MFA-Token")
		childProof, err := capability.ParseProof(childWire, capability.DefaultLimits())
		if err != nil || strings.Contains(result.Body.String(), childWire) || strings.Contains(result.Body.String(), requestTestUser) {
			t.Fatal("native HTTP MFA proof custody", err)
		}
		defer func() {
			_ = childProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		}()
		verifier, err := capability.NewService(config.Issuer.Crypto)
		if err != nil {
			t.Fatal(err)
		}
		child, err := verifier.Verify(ctx, childProof, "identity.mfa.complete", config.Issuer.Audience)
		if err != nil || child.Payload().ID != string(signedIn.ChallengeID) {
			t.Fatal("HTTP child is not native signed continuation", err)
		}
		replay := call("/v1/magic-link/consume", consumeJSON, "", cookie)
		if replay.Code != http.StatusConflict || replay.Header().Get("X-MFA-Token") != "" || len(replay.Result().Cookies()) != 0 || replay.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP challenge retry delivered credentials", replay.Code)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_sessions.sessions),max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(acknowledged.CommandID)).Scan(&after, &remaining); err != nil || after != before || remaining != 0 {
			t.Fatal("HTTP challenge changed session or one-use effects", err)
		}
		return
	}
	if json.Unmarshal(result.Body.Bytes(), &signedIn) != nil || result.Code != 200 || !signedIn.SignedIn || signedIn.CommitOutcome != "committed" || len(result.Result().Cookies()) != 1 {
		t.Fatal("native HTTP consumption failed", result.Code, result.Body.String())
	}
	delivered := result.Result().Cookies()[0]
	if delivered.Name != "__Host-magic" || !delivered.Secure || !delivered.HttpOnly || delivered.Path != "/" || delivered.Domain != "" || strings.Contains(result.Body.String(), delivered.Value) || strings.Contains(result.Body.String(), requestTestUser) {
		t.Fatal("native HTTP bearer delivery scope")
	}
	if _, err := session.ParseCSRFToken(result.Header().Get("X-CSRF-Token")); err != nil {
		t.Fatal("native synchronizer delivery", err)
	}
	bearer, err := session.ParseToken(delivered.Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, bearer)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewMagicLinkSessionService(pool, sessionpg.MagicLinkSessionServiceConfig{Repository: config.Session, Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: "magic-deployment", PolicyNamespace: "users", Audience: "identity"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity", Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if err != nil {
		t.Fatal(err)
	}
	live, err := reader.Get(ctx, session.GetRequest{TenantID: requestTestTenant, Credential: credential})
	if err != nil || !live.Authenticated {
		t.Fatal("HTTP-delivered cookie cannot authenticate natively", err)
	}
	storedCSRF, err := live.Session.CSRFState().Bindings()
	csrfToken, parseErr := session.ParseCSRFToken(result.Header().Get("X-CSRF-Token"))
	computedCSRF, digestErr := csrfToken.Digest(consumeOwner.config.CSRF, storedCSRF.Binding)
	computed, bindingErr := computedCSRF.Bindings()
	if err != nil || parseErr != nil || digestErr != nil || bindingErr != nil || storedCSRF != computed {
		t.Fatal("HTTP synchronizer is not bound to the authenticated native session")
	}
	replay := call("/v1/magic-link/consume", consumeJSON, "", cookie)
	var replayed magiclinkhttp.ConsumeResponse
	if json.Unmarshal(replay.Body.Bytes(), &replayed) != nil || replay.Code != 409 || replayed.SignedIn || replayed.CommitOutcome != "committed" || replayed.Error != "replay" || len(replay.Result().Cookies()) != 0 || replay.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("HTTP replay redelivered credentials", replay.Code)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM magic_sessions.sessions),max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(acknowledged.CommandID)).Scan(&after, &remaining); err != nil || after != before+1 || remaining != 0 {
		t.Fatal("HTTP consumption/replay changed atomic one-use/session effects", err)
	}
}
