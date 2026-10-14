//go:build integration

package reference_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

func TestReferenceNativeTOTPEnrollmentFromRealRegistration(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true}, true)
}

type enrollmentHTTPObservation struct {
	Enabled, Active bool
	CommitOutcome   string
	CommandID       identity.CommandID
	EnrollmentID    mfa.EnrollmentID
	FactorMethod    string
	ExpiresAt       time.Time
	Version         uint64
	RecoveryCodes   []string
	Error           string
}

func configureReferenceMFAEnrollment(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	if c.PasswordVerification == nil {
		t.Fatal("enrollment requires real verification selection")
	}
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "reference-mfa-enable"})
	requestKeys, err := kernel.NewRequestKeyConfig("reference-mfa-enable", [32]byte{180}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	n, err := mfapg.NewTOTPEnrollmentConfig(requestKeys, [32]byte{181}, [32]byte{182}, 1, "issue-envelope")
	if err != nil {
		t.Fatal(err)
	}
	n.ConfigurationID, n.PolicyID = "reference-mfa-enable-v1", "mfa-enable"
	n.MaximumDuration, n.TTL = 3*time.Second, 2*time.Minute
	n.Profile = mfa.TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, AllowedSkewSteps: 1, Issuer: "Example"}
	n.Coordinator = c.PasswordSignin.Native.Coordinator
	n.Risk = risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: n.ConfigurationID, Keys: c.OTP.RiskKeys}
	n.Counters = c.PasswordSignup.Counters
	counters := *n.Counters.CommandCounters
	counters.Policy, counters.Keys = c.Velocity.Native.Policy, c.Velocity.Native.Keys
	admitted, err := counters.Policy.Admit("identity.mfa.enable")
	if err != nil {
		t.Fatal(err)
	}
	n.Counters.PolicyVersion = admitted.PolicyVersion
	n.Counters.CommandCounters = &counters
	n.Counters.EnforceLockouts = true
	c.MFAEnrollment = &reference.MFAEnrollmentConfiguration{Native: n, Primary: passwordpg.MFAEnablePrimaryConfig{Audience: "reference-mfa-enable", MaximumAge: 2 * time.Minute, PrimaryFreshFor: 5 * time.Minute}, CSRFKeys: c.PasswordVerification.CSRFKeys, AllowedOrigins: []string{origin}, ComparisonKey: [32]byte{183}, ComparisonKeyVersion: 1}
	c.HTTPMFAEnrollment = &reference.HTTPMFAEnrollmentConfiguration{ProvisioningURI: true, Confirmation: true, VerificationNamespace: "reference-mfa-confirm-http", VerificationKey: [32]byte{185}, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "reference-mfa-enable-http", RateKey: [32]byte{184}}
}

// Account, verified identifier, password, empty factor authority, original
// primary session and proof are created through public workflows, not fixtures.
func proveReferenceMFAEnrollment(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, cookies []*http.Cookie, csrfWire, sessionID string, passwordMFA bool, recovery ...bool) {
	t.Helper()
	if len(cookies) != 1 {
		t.Fatal("original primary session cookie unavailable")
	}
	if f.mfaListing {
		proveReferenceMFAListing(t, ctx, features, cookies[0].Value, "", 0)
		if f.mfaListHTTP {
			proveReferenceMFAListingHTTP(t, ctx, client, base, cookies[0], "", 0)
		}
	}
	if len(cookies) != 1 {
		t.Fatal("original primary session cookie unavailable")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("original session custody malformed")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	original, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !original.Authenticated {
		t.Fatal("real registration session unavailable")
	}
	spec, err := original.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	verifier, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	proof, err := verifier.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: auth.NewBearerCredential(cookies[0].Value), Password: candidate, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "reference-mfa-enable"}, Caller: caller, Network: "127.0.0.1", Device: "reference-enrollment-device"}, CSRFToken: csrf})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatalf("native enrollment verification failed: outcome=%d error=%T", proof.Outcome, err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("reference-native-mfa-enable"))
	caller.Request.Action = "identity.mfa.enable"
	enable := mfa.EnableRequest{TenantID: otpTenant, PrimaryProof: spec.Authentication.Proof, Reauthentication: proof.Proof, Session: auth.NewBearerCredential(cookies[0].Value), Caller: caller, IdempotencyKey: key, Network: "127.0.0.1", FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: 10}, CSRFToken: csrf}
	body, _ := json.Marshal(map[string]any{"proofID": proof.Proof.Proof.ID})
	requestEnable := func(csrfToken string) (int, enrollmentHTTPObservation) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/enable", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrfToken)
		r.Header.Set("Idempotency-Key", "reference-native-mfa-enable")
		r.AddCookie(cookies[0])
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("enrollment transport unavailable")
		}
		defer response.Body.Close()
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("X-CSRF-Token") != "" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("enrollment leaked a new session or cacheable response")
		}
		var out enrollmentHTTPObservation
		if json.NewDecoder(io.LimitReader(response.Body, 32769)).Decode(&out) != nil {
			t.Fatal("enrollment response malformed")
		}
		return response.StatusCode, out
	}
	badStatus, bad := requestEnable(strings.Repeat("A", 43))
	defer clear(bad.RecoveryCodes)
	// Keyed preparation intentionally conceals callback rejection details as
	// unavailable. That observation is not enrollment, proof use or rollback.
	if badStatus != http.StatusServiceUnavailable || bad.Error != "unavailable" || bad.Enabled || bad.CommandID != "" || len(bad.RecoveryCodes) != 0 {
		t.Fatal("wrong original synchronizer response", badStatus, "code", bad.Error, "outcome", bad.CommitOutcome, "has-command", bad.CommandID != "")
	}
	var factors, proofUses int64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(spec.UserID)).Scan(&factors); err != nil || factors != 0 {
		t.Fatal("wrong synchronizer created a pending factor")
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL`, string(proof.Proof.Proof.ID)).Scan(&proofUses); err != nil || proofUses != 0 {
		t.Fatal("wrong synchronizer consumed reauthentication")
	}
	if f.disableAll || f.disablePending {
		// Both records must come from actual public enrollment, not injected
		// factor material. All-target disable must retire an unconfirmed sibling
		// as well as the subsequently activated original factor.
		verifyCaller := caller.Clone()
		verifyCaller.Request.Action = "identity.password.verify"
		extraProof, err := verifier.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: auth.NewBearerCredential(cookies[0].Value), Password: candidate, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "reference-mfa-enable"}, Caller: verifyCaller, Network: "127.0.0.1", Device: "reference-enrollment-device"}, CSRFToken: csrf})
		if err != nil {
			t.Fatal("extra public pending enrollment proof unavailable", err)
		}
		enrollment, err := features.MFAEnrollment()
		if err != nil {
			t.Fatal(err)
		}
		extra := enable
		extra.Reauthentication = extraProof.Proof
		extra.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("disable-all-extra-pending"))
		pendingOther, err := enrollment.Enable(ctx, extra)
		for _, code := range pendingOther.RecoveryMaterial.Codes {
			code.Destroy()
		}
		clear(pendingOther.RecoveryMaterial.Codes)
		if err != nil || pendingOther.Outcome != identity.CommitOutcomeCommitted || pendingOther.Enrollment.ID == "" {
			t.Fatal("second genuine pending enrollment unavailable", err)
		}
		f.pendingDisableFactor = string(pendingOther.Enrollment.ID)
	}
	status, out := requestEnable(csrfWire)
	defer clear(out.RecoveryCodes)
	if status != http.StatusOK || !out.Enabled || out.Active || out.CommitOutcome != "committed" || len(out.RecoveryCodes) != 10 {
		t.Fatal("live HTTP pending enrollment failed", status)
	}
	pending := mfa.EnableResult{CommandID: out.CommandID, Outcome: identity.CommitOutcomeCommitted, Enrollment: mfa.Enrollment{ID: out.EnrollmentID, FactorMethod: out.FactorMethod, ExpiresAt: out.ExpiresAt, Version: out.Version}}
	status, replayed := requestEnable(csrfWire)
	defer clear(replayed.RecoveryCodes)
	if status != http.StatusOK || !replayed.Enabled || replayed.Active || replayed.CommandID != out.CommandID || replayed.EnrollmentID != out.EnrollmentID || len(replayed.RecoveryCodes) != 0 {
		t.Fatal("HTTP retry changed enrollment or redelivered codes", status)
	}
	uriOwner, err := features.MFAProvisioningURI()
	if err != nil {
		t.Fatal(err)
	}
	var verifiedEmails, primaryEmails int64
	if f.pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE is_primary) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND verified AND kind='email'`, otpTenant, string(spec.UserID)).Scan(&verifiedEmails, &primaryEmails) != nil || verifiedEmails != 1 || primaryEmails != 0 {
		t.Fatal("registration did not retain its sole verified non-primary address")
	}
	command, _ := identity.NewCommandID()
	caller.Request.Action = "identity.mfa.totp-uri"
	r := mfa.TotpUriRequest{TenantID: otpTenant, CommandID: command, EnrollmentID: pending.Enrollment.ID, Session: enable.Session, CSRFToken: csrf, Caller: caller, Origin: origin, Network: enable.Network}
	// These temporary directory fixtures isolate label policy only. They neither
	// create an account nor substitute for registration/verification authority.
	var identifier string
	var verifiedAt time.Time
	if f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND verified AND kind='email'`, otpTenant, string(spec.UserID)).Scan(&identifier, &verifiedAt) != nil {
		t.Fatal("original label state unavailable")
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(spec.UserID), identifier); err != nil {
		t.Fatal("unverified label fixture unavailable")
	}
	noLabel := r
	noLabel.CommandID, _ = identity.NewCommandID()
	denied, denyErr := uriOwner.TotpUri(ctx, noLabel)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(spec.UserID), identifier, verifiedAt); err != nil {
		t.Fatal("original label restore failed")
	}
	if denyErr == nil || denied.URI.URI != "" {
		t.Fatal("unverified identifier labeled disclosed factor")
	}
	other, _ := identity.NewSubjectID()
	if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,$3,'email','other-label@example.invalid',true,false,1,2,1,clock_timestamp())`, otpTenant, string(spec.UserID), string(other)); err != nil {
		t.Fatal("ambiguous label fixture unavailable")
	}
	ambiguous := r
	ambiguous.CommandID, _ = identity.NewCommandID()
	denied, denyErr = uriOwner.TotpUri(ctx, ambiguous)
	if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(spec.UserID), string(other)); err != nil {
		t.Fatal("ambiguous label fixture cleanup failed")
	}
	if denyErr == nil || denied.URI.URI != "" {
		t.Fatal("ambiguous non-primary identifiers labeled disclosed factor")
	}
	source, ok := uriOwner.(interface {
		TotpUriRateSource(context.Context, mfa.TotpUriRequest) (time.Duration, time.Time, error)
	})
	if !ok {
		t.Fatal("native URI quota source missing")
	}
	lifetime, until, err := source.TotpUriRateSource(ctx, r)
	if err != nil || lifetime != 2*time.Minute || !time.Now().Before(until) || until.After(pending.Enrollment.ExpiresAt) {
		t.Fatal("source did not preserve original enrollment interval/deadline")
	}
	var consumed, hasCommand bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT reveal_consumed,reveal_command_id IS NOT NULL FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(spec.UserID), string(r.EnrollmentID)).Scan(&consumed, &hasCommand); err != nil || consumed || hasCommand {
		t.Fatal("read-only quota source consumed URI revelation")
	}
	uriBody, _ := json.Marshal(map[string]any{"commandID": r.CommandID, "enrollmentID": r.EnrollmentID})
	requestURI := func() (int, string, string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/totp-uri", strings.NewReader(string(uriBody)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", csrfWire)
		request.AddCookie(cookies[0])
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("URI transport unavailable")
		}
		defer response.Body.Close()
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
			t.Fatal("URI response delivery policy escaped")
		}
		var out struct {
			Disclosed          bool
			URI, CommitOutcome string
			CommandID          identity.CommandID
			EnrollmentID       mfa.EnrollmentID
		}
		if json.NewDecoder(io.LimitReader(response.Body, 16385)).Decode(&out) != nil {
			t.Fatal("URI response malformed")
		}
		if out.CommandID != r.CommandID || out.CommitOutcome != "committed" || out.Disclosed != (out.URI != "") {
			t.Fatal("original reveal observation lost")
		}
		if out.URI != "" && out.EnrollmentID != r.EnrollmentID {
			t.Fatal("foreign enrollment disclosed")
		}
		return response.StatusCode, out.URI, out.CommitOutcome
	}
	uriStatus, uri, uriOutcome := requestURI()
	if uriStatus != 200 || uri == "" || uriOutcome != "committed" {
		t.Fatal("live HTTP URI disclosure failed", uriStatus)
	}
	retryStatus, retryURI, retryOutcome := requestURI()
	if retryStatus != 409 || retryURI != "" || retryOutcome != "committed" {
		t.Fatal("HTTP URI retry redelivered secret", retryStatus)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal("bounded native URI malformed")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	if err != nil || len(secret) != 32 {
		t.Fatal("native factor material malformed")
	}
	defer clear(secret)
	var now time.Time
	if f.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		t.Fatal("native comparison time unavailable")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 15
	code := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
	command, _ = identity.NewCommandID()
	confirmBody, _ := json.Marshal(map[string]any{"commandID": command, "factorID": pending.Enrollment.ID, "code": code})
	defer clear(confirmBody)
	requestConfirmation := func(variant, token string) (int, bool, uint64, string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/totp-verify", strings.NewReader(string(confirmBody)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", token)
		if variant != "" {
			request.Header.Set("X-MFA-Variant", variant)
		}
		request.AddCookie(cookies[0])
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("confirmation transport unavailable")
		}
		defer response.Body.Close()
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("confirmation silently issued a session")
		}
		var out struct {
			Activated     bool
			Version       uint64
			CommitOutcome string
			CommandID     identity.CommandID
			FactorID      mfa.FactorID
			Error         string
		}
		if json.NewDecoder(io.LimitReader(response.Body, 16385)).Decode(&out) != nil {
			t.Fatal("activation response malformed")
		}
		if out.Activated && (out.CommandID != command || out.FactorID != mfa.FactorID(pending.Enrollment.ID) || out.CommitOutcome != "committed") {
			t.Fatal("foreign activation response")
		}
		return response.StatusCode, out.Activated, out.Version, out.CommitOutcome
	}
	status, activated, _, _ := requestConfirmation("", csrfWire)
	if status != 400 || activated {
		t.Fatal("unselected login fallback acquired enrollment custody", status)
	}
	status, activated, _, _ = requestConfirmation("enrollment", strings.Repeat("A", 43))
	if status != 403 || activated {
		t.Fatal("wrong confirmation synchronizer admitted activation", status)
	}
	var factorState int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT state FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(spec.UserID), string(pending.Enrollment.ID)).Scan(&factorState); err != nil || factorState != 1 {
		t.Fatal("denied confirmation activated factor")
	}
	status, activated, version, confirmedOutcome := requestConfirmation("enrollment", csrfWire)
	if status != 200 || !activated || version == 0 || confirmedOutcome != "committed" {
		t.Fatal("live HTTP activation failed", status)
	}
	status, activated, replayVersion, replayOutcome := requestConfirmation("enrollment", csrfWire)
	if status != 200 || !activated || replayVersion != version || replayOutcome != "committed" {
		t.Fatal("HTTP activation replay changed original outcome", status)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("activation destroyed original SFA session")
	}
	if _, err := current.Session.MFAAuthentication().Bindings(); err == nil {
		t.Fatal("activation silently promoted original session")
	}
	if f.mfaListing {
		proveReferenceMFAListing(t, ctx, features, cookies[0].Value, string(pending.Enrollment.ID), 10)
		if f.mfaListHTTP {
			proveReferenceMFAListingHTTP(t, ctx, client, base, cookies[0], string(pending.Enrollment.ID), 10)
		}
	}
	if f.mfaListDenials {
		proveReferenceMFAListDenials(t, ctx, f, features, cookies[0].Value)
		return
	}
	if f.mfaListRecheck {
		proveReferenceMFAListRecheck(t, ctx, f, features, cookies[0].Value)
		return
	}
	if f.mfaListStandalone {
		return
	}
	if f.activeStepUp {
		if f.replacementContinuationDenial == "begin-version-exhaustion" || f.replacementContinuationDenial == "begin-last-finishable-version" {
			version := "18446744073709551613"
			if f.replacementContinuationDenial == "begin-last-finishable-version" {
				version = "18446744073709551612"
			}
			if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET row_version=$3::numeric WHERE tenant_id=$1 AND factor_id=$2 AND state=2`, otpTenant, string(pending.Enrollment.ID), version); err != nil {
				t.Fatal("owned near-exhaustion factor fixture failed", err)
			}
		}
		if f.replacementSourceMethod != "" {
			var sourceBearer, sourceCSRF string
			if f.replacementSourceMethod == "totp" {
				_, sourceBearer, sourceCSRF = proveReplacementPasswordLogin(t, ctx, f, features, client, base, origin, mfa.FactorID(pending.Enrollment.ID), secret)
				// Login used the next admissible replay step. Obtain a genuinely
				// later step for fresh management proof, not a rewritten counter.
				timer := time.NewTimer(31 * time.Second)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					t.Fatal("MFA-origin fixture did not reach a fresh TOTP period")
				}
				timer.Stop()
				if _, err := f.stores.RecoverVelocity(ctx, otpTenant); err != nil {
					t.Fatal("native velocity recovery after MFA-origin wait failed", err)
				}
			} else {
				_, sourceBearer, sourceCSRF = proveReplacementRecoveryLogin(t, ctx, features, client, base, origin, out.RecoveryCodes[0], true)
			}
			cookies = []*http.Cookie{{Name: cookies[0].Name, Value: sourceBearer}}
			csrfWire = sourceCSRF
		}
		proof := proveReferenceActiveStepUp(t, ctx, f, features, cookies[0].Value, csrfWire, origin, mfa.FactorID(pending.Enrollment.ID), secret, client, base, cookies[0].Name)
		if f.disable {
			proveReferenceDisable(t, ctx, f, features, cookies[0].Value, csrfWire, origin, mfa.FactorID(pending.Enrollment.ID), proof, client, base, cookies[0].Name)
			return
		}
		if f.factorManagement {
			if f.factorReplacement {
				proveReferenceFactorReplacementBegin(t, ctx, f, features, cookies[0].Value, csrfWire, origin, mfa.FactorID(pending.Enrollment.ID), secret, out.RecoveryCodes, proof, client, base, cookies[0].Name)
				return
			}
			proveReferenceFactorRename(t, ctx, f, features, cookies[0].Value, csrfWire, origin, mfa.FactorID(pending.Enrollment.ID), proof, client, base, cookies[0].Name)
			return
		}
		if f.regeneration {
			code := proveReferenceRecoveryRegeneration(t, ctx, f, features, cookies[0].Value, csrfWire, origin, proof, client, base, cookies[0].Name)
			if code != "" {
				proveReferencePasswordRecoveryHTTP(t, ctx, f, features, client, base, origin, code, out.RecoveryCodes[0])
			}
			return
		}
	}
	if passwordMFA {
		proveReferencePasswordMFAHTTP(t, ctx, f, features, client, base, origin, mfa.FactorID(pending.Enrollment.ID), secret)
	}
	if len(recovery) > 0 && recovery[0] {
		proveReferencePasswordRecoveryHTTP(t, ctx, f, features, client, base, origin, out.RecoveryCodes[0])
		if f.mfaListing {
			proveReferenceMFAListing(t, ctx, features, cookies[0].Value, string(pending.Enrollment.ID), 9)
			if f.mfaListHTTP {
				proveReferenceMFAListingHTTP(t, ctx, client, base, cookies[0], string(pending.Enrollment.ID), 9)
			}
		}
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, cookies, csrfWire, sessionID, f, features)
}
