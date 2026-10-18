//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	magichttp "github.com/faustbrian/go-identity/http/magiclink"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// Reuse real public registration/confirmation to create account, identifier,
// factor and policy authority. No fixture inserts an account or original flow,
// substitutes risk signals, or bypasses the selected reference transport.
func TestReferenceServerNativeMagicLink(t *testing.T) {
	proveReferenceSignupGraph(t, false, false, true)
}

func TestReferenceServerNativeMagicLinkTOTP(t *testing.T) {
	proveReferenceSignupGraph(t, false, false, true, true)
}

func TestReferenceServerHTTPMagicLinkTOTP(t *testing.T) {
	proveReferenceSignupGraph(t, false, false, true, true, true)
}

func TestReferenceServerHTTPMagicLinkSignup(t *testing.T) {
	proveReferenceSignupGraph(t, false, false, true, false, false, true)
}

func TestReferenceServerHTTPMagicLinkSignupExisting(t *testing.T) {
	proveReferenceSignupGraph(t, false, false, true, false, false, true, true)
}

func TestReferenceServerHTTPMagicLinkSignupExistingTOTP(t *testing.T) {
	proveReferenceSignupGraph(t, false, false, true, true, true, true, true)
}

func configureReferenceMagicLink(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	key := bytes.Repeat([]byte{181}, 32)
	signer, err := capability.NewHMACSHA256Signer("reference-magic", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "reference-magic", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	query := c.OTP.RequestKeys.Policy
	requestKeys, err := kernel.NewRequestKeyConfig("reference-magic", [32]byte{182}, query)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := c.OTP.Signin.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	callback := origin + "/magic/complete"
	address, err := email.NewAddressParser(c.PasswordSignin.Native.Address)
	if err != nil {
		t.Fatal(err)
	}
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "magic-link", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096})
	c.MagicLink = &reference.MagicLinkConfiguration{
		Request: magicpg.RequestConfig{MaximumDuration: c.OTP.Timeout, ConfigurationID: "reference-magic-v1", PolicyID: "magic-login", GlobalAuthorityID: c.OTP.Store.GlobalAuthorityID, IssuerURL: origin, Origins: []string{origin}, Callbacks: []string{callback}, Lifetime: time.Minute, Address: address,
			Coordinator: coordinator, RequestKeys: requestKeys,
			Issuer:          issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: c.OTP.Signin.Profile.Audience, CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {183}}, PreparationTimeout: time.Second},
			IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "reference-magic", ActiveEnvelopeKey: "magic-issuer", EnvelopeKeys: map[string][]byte{"magic-issuer": bytes.Repeat([]byte{184}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "reference-magic", HMAC: key}}, Clock: time.Now},
			Risk:            risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-magic-v1", Keys: c.OTP.RiskKeys}, Session: c.OTP.Signin.Session, CookieKeys: map[uint32]session.DigestKey{3: c.PasswordSignin.Native.FlowKeys[0]}, IntentKey: [32]byte{185}, ActiveEnvelopeKeyID: "issue-envelope",
			Delivery: magicpg.RequestDeliveryConfig{Endpoint: origin + "/magic", TemplateID: "magic-link", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{186}, Timeout: time.Second}},
		Consume: &magicpg.ConsumeConfig{ConfigurationID: "reference-magic-session-v1", PolicyNamespace: c.OTP.Signin.Profile.PolicyNamespace, Issuer: c.OTP.Signin.Issuer, CSRF: c.OTP.Signin.CSRFKey},
		PreAuth: &reference.MagicLinkPreAuthConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", Origin: origin, CallbackURL: callback, LookupKeyVersion: 3, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: c.OTP.PreAuth.Cookie},
	}
	c.HTTPMagicLink = &reference.HTTPMagicLinkConfiguration{Request: true, Consume: true, ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9, VerificationNamespace: "reference-magic", VerificationKey: [32]byte{187}}
}

func proveReferenceMagicLink(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, config reference.StoreConfiguration, deps reference.ReferenceDependencies, existingSignup ...bool) {
	t.Helper()
	if config.MagicLink.TOTP != nil {
		seedReferenceTOTPEnrollment(t, ctx, f, deps)
	}
	invoke := func(path string, body any, cookies []*http.Cookie, key string) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded/cacheable magic-link response")
		}
		return response, payload
	}
	r, payload := invoke("/v1/session/preauth-issue", map[string]string{"method": "magic-link"}, nil, "")
	var flow sessionhttp.PreAuthResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &flow) != nil || !flow.Issued {
		t.Fatal("original magic-link browser initiation", r.StatusCode)
	}
	browser := r.Cookies()
	id, _ := identity.NewCommandID()
	callback := origin + "/magic/complete"
	address, intent := "registered@example.invalid", "signin-only"
	prospective := config.MagicLink.Request.Signup != nil && (len(existingSignup) == 0 || !existingSignup[0])
	if config.MagicLink.Request.Signup != nil {
		intent = "signup-if-allowed"
		if prospective {
			address = "passwordless-new@example.invalid"
		}
	}
	accountCount := func() int {
		var count int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND kind='email' AND canonical_value=$2`, otpTenant, address).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	accounts := accountCount()
	if prospective && accounts != 0 {
		t.Fatal("prospective mailbox already has an account")
	}
	r, payload = invoke("/v1/magic-link/request", map[string]string{"commandID": string(id), "preAuthID": string(flow.FlowID), "email": address, "intent": intent, "callbackURL": callback}, browser, "reference-magic-original")
	var ack magichttp.RequestResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &ack) != nil || !ack.Accepted || ack.CommitOutcome != "committed" || len(r.Cookies()) != 0 || bytes.Contains(payload, []byte(address)) {
		t.Fatal("reference magic-link request", r.StatusCode, ack.Error, ack.CommitOutcome)
	}
	if config.MagicLink.Request.Signup != nil {
		r, payload = invoke("/v1/magic-link/request", map[string]string{"commandID": string(id), "preAuthID": string(flow.FlowID), "email": address, "intent": intent, "callbackURL": callback}, browser, "reference-magic-original")
		var retry magichttp.RequestResponse
		if r.StatusCode != 200 || json.Unmarshal(payload, &retry) != nil || !retry.Accepted || retry.CommandID != ack.CommandID || retry.CommitOutcome != "committed" || len(r.Cookies()) != 0 || bytes.Contains(payload, []byte(address)) {
			t.Fatal("public signup request retry lost original neutral outcome", r.StatusCode)
		}
		var grants int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$1`, string(ack.CommandID)).Scan(&grants); err != nil || grants != 1 || accountCount() != accounts {
			t.Fatal("signup request retry regenerated issuance or created an account", err)
		}
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("reference encrypted magic-link delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("magic-link delivery absent")
	}
	u, err := url.Parse(link)
	if err != nil || u.RawQuery != "" || !strings.HasPrefix(u.Fragment, "token=") || u.Scheme != "https" {
		t.Fatal("magic-link landing custody")
	}
	token := strings.TrimPrefix(u.Fragment, "token=")
	before := func() (int, int) {
		var sessions, remaining int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),max_uses-uses FROM capability_identity_one_use WHERE origin_command_id=$1`, string(ack.CommandID)).Scan(&sessions, &remaining); err != nil {
			t.Fatal("original capability/session effects", err)
		}
		return sessions, remaining
	}
	sessions, remaining := before()
	if remaining != 1 || accountCount() != accounts {
		t.Fatal("delivery consumed the grant")
	}
	// A scanner's landing request cannot consume: the bearer stays in a fragment
	// and the reference backend only exposes explicit POST consumption.
	scanner, err := client.Get(base + u.EscapedPath())
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(scanner.Body, 16385))
	closeErr := scanner.Body.Close()
	if readErr != nil || closeErr != nil || scanner.StatusCode != 404 || len(scanner.Cookies()) != 0 {
		t.Fatal("scanner landing unexpectedly authenticated")
	}
	if count, left := before(); count != sessions || left != 1 {
		t.Fatal("scanner changed grant/session effects")
	}
	oldToken, oldOrigin := token, ack.CommandID
	resendID, _ := identity.NewCommandID()
	r, payload = invoke("/v1/magic-link/request", map[string]string{"commandID": string(resendID), "preAuthID": string(flow.FlowID), "email": address, "intent": intent, "callbackURL": callback}, browser, "reference-magic-resend")
	if r.StatusCode != 200 || json.Unmarshal(payload, &ack) != nil || !ack.Accepted || ack.CommitOutcome != "committed" {
		t.Fatal("reference magic-link resend", r.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("reference replacement delivery", err)
	}
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("replacement delivery absent")
	}
	u, err = url.Parse(link)
	if err != nil || u.RawQuery != "" || !strings.HasPrefix(u.Fragment, "token=") || u.Scheme != "https" {
		t.Fatal("replacement custody")
	}
	token = strings.TrimPrefix(u.Fragment, "token=")
	oldConsumeID, _ := identity.NewCommandID()
	r, payload = invoke("/v1/magic-link/consume", map[string]string{"commandID": string(oldConsumeID), "preAuthID": string(flow.FlowID), "token": oldToken, "callbackURL": callback}, browser, "")
	var superseded magichttp.ConsumeResponse
	decodeSuperseded := json.Unmarshal(payload, &superseded)
	if r.StatusCode != http.StatusConflict || decodeSuperseded != nil || superseded.Error != "superseded" || superseded.SignedIn || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("reference old link not superseded", r.StatusCode, superseded.Error)
	}
	var oldUses int
	var replacement string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT uses,superseded_by_command_id FROM capability_identity_one_use WHERE origin_command_id=$1`, string(oldOrigin)).Scan(&oldUses, &replacement); err != nil || oldUses != 0 || replacement != string(ack.CommandID) {
		t.Fatal("reference original provenance", err)
	}
	if count, left := before(); count != sessions || left != 1 {
		t.Fatal("reference supersession mutated session/use")
	}
	consumeID, _ := identity.NewCommandID()
	body := map[string]string{"commandID": string(consumeID), "preAuthID": string(flow.FlowID), "token": token, "callbackURL": callback}
	r, payload = invoke("/v1/magic-link/consume", body, nil, "")
	if r.StatusCode == 200 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("foreign browser authenticated")
	}
	if count, left := before(); count != sessions || left != 1 {
		t.Fatal("foreign browser mutated protected effects")
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	r, payload = invoke("/v1/magic-link/consume", body, browser, "")
	var result magichttp.ConsumeResponse
	if f.completionFault != nil {
		// The existing loopback-driver fault drops only the final COMMIT ack.
		// Actual identity/capability/session writes still reach PostgreSQL.
		if r.StatusCode != http.StatusServiceUnavailable || json.Unmarshal(payload, &result) != nil || result.CommitOutcome != "unknown" || result.SignedIn || result.SessionID != "" || result.ChallengeRequired || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || !f.completionFault.hit.Load() {
			t.Fatal("ambiguous magic-link commit redelivered credentials or hid outcome", r.StatusCode)
		}
		if count, left := before(); count != sessions+1 || left != 0 {
			t.Fatal("lost commit acknowledgement split magic-link use/session effects")
		}
		wantAccounts := accounts
		if prospective {
			wantAccounts++
		}
		if accountCount() != wantAccounts {
			t.Fatal("ambiguous signup created missing or duplicate accounts")
		}
		owner, err := features.MagicLinkConsume()
		if err != nil {
			t.Fatal(err)
		}
		query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: consumeID, AnonymousFlowID: string(flow.FlowID), ActorID: config.HTTPMagicLink.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.magic-link.consume"}
		caller := authorization.DecisionContext{PolicyRevision: config.HTTPMagicLink.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(otpTenant), Subject: authorization.Subject{Kind: query.ActorKind, ID: authorization.SubjectID(query.ActorID)}, Action: "identity.magic-link.consume", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.FlowID)}}}
		history, err := owner.RecoverConsume(ctx, query, caller)
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Session.CommandID != consumeID || !history.Session.Replayed || history.Session.Token != (session.Token{}) || history.Session.Cookie.Name != "" || history.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("magic-link unknown recovery lost original metadata or redelivered custody", err)
		}
		r, payload = invoke("/v1/magic-link/consume", body, browser, "")
		var retry magichttp.ConsumeResponse
		if r.StatusCode != http.StatusConflict || json.Unmarshal(payload, &retry) != nil || retry.CommitOutcome != "committed" || retry.SignedIn || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("ambiguous magic-link retry regenerated credentials", r.StatusCode)
		}
		if count, left := before(); count != sessions+1 || left != 0 || accountCount() != wantAccounts {
			t.Fatal("magic-link recovery/retry repeated account, session or use effects")
		}
		return
	}
	if config.MagicLink.TOTP != nil {
		if r.StatusCode != http.StatusOK || json.Unmarshal(payload, &result) != nil || result.SignedIn || !result.ChallengeRequired || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("reference enrolled primary did not return challenge only", r.StatusCode, result.Error, "signed-in", result.SignedIn, "challenge", result.ChallengeRequired, "cookies", len(r.Cookies()), "csrf-present", r.Header.Get("X-CSRF-Token") != "")
		}
		proveReferenceTOTPCompletion(t, ctx, f, features, config, deps, flow.FlowID, browser, origin, callback, result, r.Header.Get("X-MFA-Token"), client, base)
		return
	}
	if r.StatusCode != 200 || json.Unmarshal(payload, &result) != nil || !result.SignedIn || result.CommitOutcome != "committed" || len(r.Cookies()) != 1 || result.SessionID == "" {
		t.Fatal("reference magic-link consumption", r.StatusCode, result.Error, result.CommitOutcome)
	}
	cookies, csrf := r.Cookies(), r.Header.Get("X-CSRF-Token")
	if !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || bytes.Contains(payload, []byte(cookies[0].Value)) {
		t.Fatal("reference bearer custody leaked")
	}
	r, payload = invoke("/v1/magic-link/consume", body, browser, "")
	var replay magichttp.ConsumeResponse
	if r.StatusCode != 409 || json.Unmarshal(payload, &replay) != nil || replay.SignedIn || replay.CommitOutcome != "committed" || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("reference replay redelivered credentials", r.StatusCode)
	}
	if count, left := before(); count != sessions+1 || left != 0 {
		t.Fatal("consumption/replay did not retain exactly one session/use")
	}
	wantAccounts := accounts
	if prospective {
		wantAccounts++
	}
	if accountCount() != wantAccounts {
		t.Fatal("signup/replay did not create exactly one intended account")
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, cookies, csrf, result.SessionID, f, features)
}
