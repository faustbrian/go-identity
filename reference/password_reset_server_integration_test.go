//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	email "github.com/faustbrian/go-identity/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
)

type referenceResetPolicy struct{}

func (referenceResetPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && (c.Request.Action == "identity.password.reset-request" || c.Request.Action == "identity.password.reset-complete" || c.Request.Action == "identity.password.signin" || c.Request.Action == "identity.password.signin.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (otpReferenceSigninPolicy{}).Decide(ctx, c)
}

func configureReferencePasswordReset(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	query := kernel.CommandQueryPolicy{Authorization: referenceResetPolicy{}, Clock: clock.System{}, PolicyVersion: 9}
	c.OTP.RequestKeys.Policy = query
	c.OTP.Signin.Coordinator.QueryPolicy = &query
	coordinator := c.OTP.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	policy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2}})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := primitive.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := crypto.Hash(t.Context(), []byte("synthetic-reference-reset-dummy"))
	if err != nil {
		t.Fatal(err)
	}
	// Only provider IO is substituted; the owned HIBP client derives exact-byte
	// prefixes, parses responses and supplies caller-bound neutral evidence.
	riskConfig := risk.PolicyConfig{Version: 3, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	screeningPolicy, err := risk.NewPolicy(riskConfig)
	if err != nil {
		t.Fatal(err)
	}
	riskConfig.HIBP = risk.HIBPPolicy{}
	c.Velocity.Native.Policy, err = risk.NewPolicy(riskConfig)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("reference-reset", bytes.Repeat([]byte{93}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{93}, 32))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{ID: "reference-reset", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "reference-reset-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	address, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-reset", [32]byte{108}, query)
	if err != nil {
		t.Fatal(err)
	}
	callback := origin + "/reset"
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "password-reset", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096})
	c.PasswordReset = &reference.PasswordResetConfiguration{Native: passwordpg.ResetConfig{
		Repository: passwordpg.Config{MaximumDuration: 3 * time.Second, HashPolicy: policy}, ConfigurationID: "reference-reset-v1", PolicyID: "reset", GlobalAuthorityID: "deployment", AuthorizationNamespace: "users", Origins: []string{origin}, ActiveEnvelopeKeyID: "issue-envelope", IdentifierKey: [32]byte{97}, Session: c.OTP.Signin.Session, Coordinator: coordinator,
		Profile:   password.ResetProfileConfig{Issuer: origin, Audience: "reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {95}}},
		Issuer:    issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "reset", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {94}}, PreparationTimeout: time.Second},
		Screening: password.HashPreparationConfig{Primitive: crypto, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Policy: screeningPolicy, Now: time.Now, Collect: referenceHIBPScreening(t, screeningPolicy)},
		Risk:      risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-reset-v1", Keys: c.OTP.RiskKeys},
		Request:   &passwordpg.ResetRequestConfig{Address: address, RequestKeys: requestKeys, Lifetime: time.Minute, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "deployment", ActiveEnvelopeKey: "reset-issuer", EnvelopeKeys: map[string][]byte{"reset-issuer": bytes.Repeat([]byte{104}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "reference-reset", HMAC: bytes.Repeat([]byte{93}, 32)}}, Clock: time.Now}, Delivery: passwordpg.SignupDeliveryConfig{Resolver: resolver, Endpoint: origin + "/password/reset", TemplateID: "password-reset", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{105}, Timeout: time.Second}},
	}}
	c.HTTPPasswordReset = &reference.HTTPPasswordResetConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9, CallbackURL: callback, VerificationNamespace: "reference-reset", VerificationKey: [32]byte{112}}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{113}, 32))
	loginSigner, err := passwordpg.NewSigninSigningKey("reference-password", private)
	if err != nil {
		t.Fatal(err)
	}
	flowKey, err := session.NewDigestKey(c.OTP.PreAuth.LookupKeyVersion, c.OTP.Store.PreAuthCookieKeys[c.OTP.PreAuth.LookupKeyVersion])
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordSignin = &reference.PasswordSigninConfiguration{Native: passwordpg.SigninConfig{
		Repository: c.PasswordReset.Native.Repository,
		Verifier:   password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Now: time.Now},
		Session:    c.OTP.Signin.Session,
		Profile:    sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"},
		Address:    email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization},
		FlowKeys:   []session.DigestKey{flowKey}, Issuance: c.OTP.Signin.Issuer, CSRFKey: c.OTP.Signin.CSRFKey,
		Risk:        risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-password-v1", Keys: c.OTP.RiskKeys},
		Coordinator: coordinator, SigningKey: loginSigner, VerificationKeys: map[string]ed25519.PublicKey{"reference-password": private.Public().(ed25519.PublicKey)},
		Issuer: origin, Environment: "test", PolicyID: "password-login", ProofTTL: time.Minute, IdentifierKey: bytes.Repeat([]byte{114}, 32), Origins: []string{origin}, CallbackURLs: []string{callback},
	}}
}

func proveNativeServerPasswordReset(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, baseURL, origin string, cookies []*http.Cookie, messages <-chan string, native passwordpg.ResetConfig, signin passwordpg.SigninConfig) {
	t.Helper()
	// The preexisting account has no password/factor authority yet: enumeration
	// suppression must still produce a committed, replay-stable public response
	// through the actual graph, without generating or delivering a grant.
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"commandID": string(command), "identifier": "recipient@example.invalid", "callbackURL": origin + "/reset"})
	if err != nil {
		t.Fatal(err)
	}
	key := "reference-reset-001"
	invoke := func(path, key string, body []byte) ([]byte, int) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(wire) > 16384 || len(response.Cookies()) != 0 {
			t.Fatal("reference reset response custody", response.StatusCode)
		}
		return wire, response.StatusCode
	}
	call := func() ([]byte, passwordhttp.ResetRequestResponse) {
		t.Helper()
		wire, status := invoke("/v1/password/reset-request", key, body)
		var out passwordhttp.ResetRequestResponse
		if status != http.StatusOK || json.Unmarshal(wire, &out) != nil || !out.Accepted || out.CommitOutcome != "committed" {
			t.Fatal("reference native reset request", status, out.Error)
		}
		return wire, out
	}
	first, acknowledgement := call()
	repeated, replay := call()
	if !bytes.Equal(first, repeated) || acknowledgement.CommandID != replay.CommandID {
		t.Fatal("reference reset replay changed original response")
	}
	var grants, intents int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM capability_identity_one_use),(SELECT count(*) FROM identity.delivery_intents)`).Scan(&grants, &intents); err != nil || grants != 0 || intents != 0 {
		t.Fatal("suppressed reference reset issued delivery", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-messages:
		t.Fatal("suppressed reset sent a message")
	default:
	}
	// Explicit preexisting-account fixture: authoritative known-empty factor
	// state and password material are installed together. This is not proof of
	// signup; it must never be inferred from the preceding missing authority.
	seed, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	seedBytes, err := base64.RawURLEncoding.DecodeString(string(seed))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := native.Screening.Primitive.Hash(ctx, []byte("synthetic-reference-old-password"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.password.signup',$3,1,$4)`, []any{seedBytes, otpTenant, bytes.Repeat([]byte{1}, 32), []byte{1}}},
		{`INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.password.signup')`, []any{seedBytes, otpTenant}},
		{`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'AAAAAAAAAAAAAAAAAAAAAg','password',1,'identity/password',1,true)`, []any{otpTenant}},
		{`INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES($1,'AAAAAAAAAAAAAAAAAAAAAg','password',1,'argon2id',$2)`, []any{otpTenant, hash.String()}},
		{`INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,'AAAAAAAAAAAAAAAAAAAAAg',1,0,$2,'identity.password.signup')`, []any{otpTenant, seedBytes}},
	} {
		if _, err := f.pool.Raw().Exec(ctx, row.sql, row.args...); err != nil {
			t.Fatal("preexisting password/factor fixture", err)
		}
	}
	login, err := features.PasswordSignin()
	if err != nil {
		t.Fatal("selected reference password login", err)
	}
	before := referencePasswordLogin(t, ctx, f, login, signin, "synthetic-reference-old-password")
	if before.Validate() != nil || before.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || before.SessionID == "" {
		t.Fatal("predecessor reference password login did not commit")
	}
	credential, err := session.NewCredential(session.CredentialBearer, before.Issuance.Token)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := sessionpg.NewSessionService(f.pool, sessionpg.SessionServiceConfig{
		Repository: signin.Session, Profile: signin.Profile,
		Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: signin.Profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{signin.Issuance.LookupKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	get := session.GetRequest{TenantID: otpTenant, Credential: credential}
	if current, err := validation.Get(ctx, get); err != nil || !current.Authenticated {
		t.Fatal("predecessor reference session not usable", err)
	}
	command, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(map[string]string{"commandID": string(command), "identifier": "recipient@example.invalid", "callbackURL": origin + "/reset"})
	if err != nil {
		t.Fatal(err)
	}
	key = "reference-reset-eligible-001"
	first, _ = call()
	repeated, _ = call()
	if !bytes.Equal(first, repeated) {
		t.Fatal("eligible reference reset replay changed bytes")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("reference reset delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("reference reset delivery missing")
	}
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme != "https" || parsed.Host != mustResetHost(t, origin) || parsed.Path != "/password/reset" || parsed.Query().Get("token") == "" {
		t.Fatal("reference reset delivery lost original link")
	}
	completion, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	// The original grant must survive provider denial, and neither credential
	// replacement nor predecessor-session revocation may precede screening.
	for _, candidate := range []string{"synthetic-reference-breached-password", "synthetic-reference-malformed-password", "synthetic-reference-outage-password", "synthetic-reference-redirect-password"} {
		denied, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		deniedBody, err := json.Marshal(map[string]string{"commandID": string(denied), "token": parsed.Query().Get("token"), "newPassword": candidate})
		if err != nil {
			t.Fatal(err)
		}
		wire, status := invoke("/v1/password/reset-complete", "", deniedBody)
		clear(deniedBody)
		var result passwordhttp.ResetCompleteResponse
		if json.Unmarshal(wire, &result) != nil || status == http.StatusOK || result.Completed || result.SessionsRevoked || result.CredentialVersion != 0 {
			t.Fatal("provider-denied password mutated reference account", status)
		}
		var version, resets, consumed int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT version FROM identity_password.credentials WHERE tenant_id=$1 AND user_id='AAAAAAAAAAAAAAAAAAAAAg'),(SELECT count(*) FROM session_store.password_resets),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use)`, otpTenant).Scan(&version, &resets, &consumed); err != nil || version != 1 || resets != 0 || consumed != 0 {
			t.Fatal("provider denial escaped protected mutation", err)
		}
		if current, err := validation.Get(ctx, get); err != nil || !current.Authenticated {
			t.Fatal("provider denial revoked predecessor session", err)
		}
	}
	body, err = json.Marshal(map[string]string{"commandID": string(completion), "token": parsed.Query().Get("token"), "newPassword": "synthetic-reference-new-password"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	first, status := invoke("/v1/password/reset-complete", "", body)
	var complete passwordhttp.ResetCompleteResponse
	if status != http.StatusOK || json.Unmarshal(first, &complete) != nil || !complete.Completed || complete.CommitOutcome != "committed" || !complete.SessionsRevoked || complete.CredentialVersion != 2 {
		t.Fatal("reference reset completion", status, complete.Error)
	}
	repeated, status = invoke("/v1/password/reset-complete", "", body)
	if status != http.StatusOK || !bytes.Equal(first, repeated) {
		t.Fatal("reference reset completion replay changed original result")
	}
	var effects int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM capability_identity_one_use),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM session_store.password_resets)`).Scan(&grants, &intents, &effects); err != nil || grants != 1 || intents != 1 || effects != 1 {
		t.Fatal("reference reset retry duplicated issuance, delivery or effects", err)
	}
	repository, err := passwordpg.NewRepository(f.pool, native.Repository)
	if err != nil {
		t.Fatal(err)
	}
	material, err := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: otpTenant, SubjectID: "AAAAAAAAAAAAAAAAAAAAAg"})
	if err != nil {
		t.Fatal("reference reset material", err)
	}
	old, err := native.Screening.Primitive.Verify(ctx, []byte("synthetic-reference-old-password"), material.EncodedHash().String())
	if !errors.Is(err, primitive.ErrMismatch) || old.Match() {
		t.Fatal("old password accepted after reference reset", err)
	}
	current, err := native.Screening.Primitive.Verify(ctx, []byte("synthetic-reference-new-password"), material.EncodedHash().String())
	if err != nil || !current.Match() {
		t.Fatal("new password rejected after reference reset", err)
	}
	if current, err := validation.Get(ctx, get); err != nil || current.Authenticated {
		t.Fatal("reset retained usable predecessor credential", err)
	}
	sessionRepository, err := sessionpg.NewRepository(f.pool, signin.Session)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := sessionRepository.Get(ctx, otpTenant, before.SessionID)
	if err != nil || !stored.Revoked {
		t.Fatal("reset did not persist predecessor session revocation", err)
	}
	var revoked int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT revoked_count FROM session_store.password_resets").Scan(&revoked); err != nil || revoked != 1 {
		t.Fatal("reset receipt omitted original live session", err)
	}
	rejected := referencePasswordLogin(t, ctx, f, login, signin, "synthetic-reference-old-password")
	if rejected.Validate() != nil || rejected.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || rejected.SessionID != "" {
		t.Fatal("old password obtained a reference session after reset")
	}
	accepted := referencePasswordLogin(t, ctx, f, login, signin, "synthetic-reference-new-password")
	if accepted.Validate() != nil || accepted.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || accepted.SessionID == "" || accepted.SessionID == before.SessionID {
		t.Fatal("replacement password failed reference login")
	}
	newCredential, err := session.NewCredential(session.CredentialBearer, accepted.Issuance.Token)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := validation.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: newCredential}); err != nil || !current.Authenticated {
		t.Fatal("replacement-password session not usable", err)
	}
}

func mustResetHost(t *testing.T, origin string) string {
	t.Helper()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
