//go:build integration

package reference_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	magichttp "github.com/faustbrian/go-identity/http/magiclink"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

const referenceTOTPFactor = "AgICAgICAgICAgICAgICAg"

// Enrollment is an explicit pre-existing authority fixture, not a claim of
// public enrollment delivery. Registration, primary login and completion use
// real public owners. Plaintext is encrypted under the native factor snapshot's
// authenticated context before any completion request.
func seedReferenceTOTPEnrollment(t *testing.T, ctx context.Context, f liveStores, deps reference.ReferenceDependencies) {
	t.Helper()
	var user string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT u.user_id FROM identity.users u JOIN identity.identifiers i USING(tenant_id,user_id) WHERE u.tenant_id=$1 AND u.status='active' AND i.kind='email' AND i.canonical_value='registered@example.invalid' AND i.verified`, otpTenant).Scan(&user); err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	idBytes, _ := base64.RawURLEncoding.DecodeString(string(id))
	crypto, err := envelope.NewService(deps.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	placeholderContext, err := envelope.NewContext(map[string]string{"fixture": "unverified-enrollment-placeholder"})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := crypto.Encrypt(ctx, envelope.EncryptRequest{KeyReference: "issue-envelope", Context: placeholderContext, Plaintext: []byte("unverified fixture placeholder")})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := placeholder.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.mfa.enable',decode(repeat('02',32),'hex'),1,decode('01','hex'))`, idBytes, otpTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.mfa.enable')`, idBytes, otpTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES($1,$2,$3,2,1,1,'SHA1',6,30,1,'reference-fixture',$5,$4,'identity.mfa.enable',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',clock_timestamp())`, otpTenant, user, referenceTOTPFactor, idBytes, encoded); err != nil {
		t.Fatal(err)
	}
}

func proveReferenceTOTPCompletion(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, config reference.StoreConfiguration, deps reference.ReferenceDependencies, flow identity.PreAuthTransactionID, cookies []*http.Cookie, origin, callback string, challenge magichttp.ConsumeResponse, wire string, client *http.Client, base string) {
	t.Helper()
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal("challenge wire absent", err)
	}
	defer func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
	verifier, err := capability.NewService(config.MagicLink.Request.Issuer.Crypto)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := verifier.Verify(ctx, proof, "identity.mfa.complete", config.MagicLink.Request.Issuer.Audience)
	if err != nil {
		t.Fatal("native child signature", err)
	}
	factors, err := mfapg.NewTOTPFactorReader(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := factors.Read(ctx, grant, origin, referenceTOTPFactor)
	if err != nil {
		t.Fatal("owned enrollment snapshot", err)
	}
	binding, err := snapshot.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(deps.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	// RFC6238 Appendix B's SHA-1 test key; only this disposable fixture owns it.
	secret := []byte("12345678901234567890")
	defer clear(secret)
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{KeyReference: "issue-envelope", Context: binding, Plaintext: secret})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ciphertext)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET encrypted_secret=$1 WHERE tenant_id=$2 AND factor_id=$3`, ciphertext, otpTenant, referenceTOTPFactor); err != nil {
		t.Fatal(err)
	}
	owner, err := features.MagicLinkTOTP()
	if err != nil {
		t.Fatal("public TOTP owner not selected", err)
	}
	id, _ := identity.NewCommandID()
	var cookie string
	for _, c := range cookies {
		if c.Name == "__Host-identity_flow" {
			cookie = c.Value
		}
	}
	var codeWire string
	code := func() auth.OneTimeCode {
		var step [8]byte
		binary.BigEndian.PutUint64(step[:], uint64(time.Now().Unix()/30))
		h := hmac.New(sha1.New, secret)
		_, _ = h.Write(step[:])
		digest := h.Sum(nil)
		offset := int(digest[len(digest)-1] & 15)
		value := (binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff) % 1000000
		clear(digest)
		codeWire = fmt.Sprintf("%06d", value)
		out, err := auth.NewOneTimeCode(codeWire)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	request := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: id, ChallengeID: mfa.ChallengeID(challenge.ChallengeID), FactorID: referenceTOTPFactor, Proof: proof, Code: code(), PreAuthID: flow, Cookie: auth.NewBearerCredential(cookie), Origin: origin, Callback: callback, Network: "127.0.0.1", Caller: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(challenge.ChallengeID)}}}}
	if config.HTTPMFA != nil {
		devices, err := session.NewBrowserDeviceCodec(*config.HTTPPreAuth.Device)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range cookies {
			if cookie.Name == "__Host-identity_device" {
				device, err := devices.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
				if err != nil {
					t.Fatal(err)
				}
				request.Device = device.DeviceID()
			}
		}
		if request.Device == "" {
			t.Fatal("HTTP completion device absent")
		}
	}
	source, ok := owner.(interface {
		TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
	})
	if !ok {
		t.Fatal("selected native TOTP lacks owned HTTP rate source")
	}
	readSource := func(r mfa.TotpVerifyRequest) {
		t.Helper()
		user, child, lifetime, err := source.TotpVerificationRateSource(ctx, r)
		p := grant.Payload()
		if err != nil || string(user) != p.Subject || child != p.ID || lifetime != p.ExpiresAt.Sub(p.IssuedAt) {
			t.Fatal("TOTP rate source changed original subject/child/lifetime", err)
		}
	}
	effects := func() (int, int, int, int) {
		var attempts, charges, uses, sessions int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT c.attempts_remaining,(SELECT count(*) FROM risk_store.counter_charges WHERE operation='identity.mfa.totp-verify'),(SELECT uses FROM capability_identity_one_use WHERE capability_id=$2),(SELECT count(*) FROM session_store.session_issuances WHERE purpose='identity.mfa.totp-verify') FROM identity_mfa.continuations c WHERE c.tenant_id=$1 AND c.continuation_id=$2`, otpTenant, string(challenge.ChallengeID)).Scan(&attempts, &charges, &uses, &sessions); err != nil {
			t.Fatal(err)
		}
		return attempts, charges, uses, sessions
	}
	if a, c, u, s := effects(); a != 3 || c != 0 || u != 0 || s != 0 {
		t.Fatal("primary challenge spent MFA budget or created session")
	}
	readSource(request)
	// HTTP quota source must not decrypt or interpret selected factor custody;
	// actual native completion independently requires the valid encrypted factor.
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET encrypted_secret=decode('01','hex') WHERE tenant_id=$1 AND factor_id=$2`, otpTenant, referenceTOTPFactor); err != nil {
		t.Fatal(err)
	}
	readSource(request)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET encrypted_secret=$1 WHERE tenant_id=$2 AND factor_id=$3`, ciphertext, otpTenant, referenceTOTPFactor); err != nil {
		t.Fatal(err)
	}
	if a, c, u, s := effects(); a != 3 || c != 0 || u != 0 || s != 0 {
		t.Fatal("rate source charged native budget or issued")
	}
	foreign := request
	foreign.CommandID, _ = identity.NewCommandID()
	foreign.Caller = request.Caller.Clone()
	foreign.Caller.CorrelationID = string(foreign.CommandID)
	foreign.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if user, child, lifetime, err := source.TotpVerificationRateSource(ctx, foreign); err == nil || user != "" || child != "" || lifetime != 0 {
		t.Fatal("foreign browser acquired subject rate source")
	}
	if denied, err := owner.TotpVerify(ctx, foreign); err == nil || denied.Session.Token != (session.Token{}) {
		t.Fatal("foreign browser completed TOTP")
	}
	if a, c, u, s := effects(); a != 3 || c != 0 || u != 0 || s != 0 {
		t.Fatal("foreign browser charged another account's shared factor budget")
	}
	wrong := request
	missing := request
	missing.CommandID, _ = identity.NewCommandID()
	missing.Caller = request.Caller.Clone()
	missing.Caller.CorrelationID = string(missing.CommandID)
	missing.FactorID = "BwcHBwcHBwcHBwcHBwcHBw"
	for range 2 {
		if denied, err := owner.TotpVerify(ctx, missing); err == nil || denied.Session.Token != (session.Token{}) || denied.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("missing factor completed or delivered")
		}
		if a, c, u, s := effects(); a != 2 || c != 1 || u != 0 || s != 0 {
			t.Fatal("missing factor/retry did not charge exactly one shared denial", a, c, u, s)
		}
	}
	wrong.CommandID, _ = identity.NewCommandID()
	wrong.Caller = request.Caller.Clone()
	wrong.Caller.CorrelationID = string(wrong.CommandID)
	wrong.Code, err = auth.NewOneTimeCode("0000") // Valid opaque input, impossible six-digit TOTP.
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if denied, err := owner.TotpVerify(ctx, wrong); err == nil || denied.Session.Token != (session.Token{}) || denied.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("malformed TOTP completed or delivered")
		}
		if a, c, u, s := effects(); a != 1 || c != 2 || u != 0 || s != 0 {
			t.Fatal("wrong code/retry did not retain exactly one shared denial charge", a, c, u, s)
		}
		readSource(wrong)
	}
	type attempt struct {
		result mfa.TotpVerifyResult
		err    error
	}
	var result mfa.TotpVerifyResult
	if config.HTTPMFA != nil {
		payload, err := json.Marshal(map[string]any{"commandID": string(request.CommandID), "preAuthID": string(request.PreAuthID), "challengeID": string(request.ChallengeID), "factorID": string(request.FactorID), "token": wire, "code": codeWire, "callbackURL": callback, "trustDevice": false})
		if err != nil {
			t.Fatal(err)
		}
		invoke := func() (*http.Response, mfahttp.TOTPVerifyResponse) {
			t.Helper()
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/totp-verify", strings.NewReader(string(payload)))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
			for _, cookie := range cookies {
				r.AddCookie(cookie)
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
			closeErr := response.Body.Close()
			var decoded mfahttp.TOTPVerifyResponse
			if err != nil || closeErr != nil || len(body) > 16384 || response.Header.Get("Cache-Control") != "no-store" || json.Unmarshal(body, &decoded) != nil {
				t.Fatal("invalid/unbounded/cacheable MFA HTTP response")
			}
			return response, decoded
		}
		response, decoded := invoke()
		if response.StatusCode != 200 || !decoded.SignedIn || decoded.CommitOutcome != "committed" || decoded.CommandID != id || len(response.Cookies()) != 1 || response.Header.Get("X-CSRF-Token") == "" {
			t.Fatal("HTTP TOTP did not deliver original session", response.StatusCode, decoded.Error, decoded.CommitOutcome)
		}
		cookie := *response.Cookies()[0]
		token, err := session.ParseToken(cookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := features.Sessions()
		if err != nil {
			t.Fatal(err)
		}
		observed, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !observed.Authenticated {
			t.Fatal("HTTP MFA bearer not readable", err)
		}
		stored, _ := observed.Session.Bindings()
		if stored.SessionID != decoded.SessionID {
			t.Fatal("HTTP metadata did not match persisted session")
		}
		csrf, err := session.ParseCSRFToken(response.Header.Get("X-CSRF-Token"))
		if err != nil {
			t.Fatal(err)
		}
		cookie.Value = ""
		result = mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted, Session: session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeCommitted, Session: observed.Session, Token: token, Cookie: cookie}, CSRFToken: csrf}
		retry, replayed := invoke()
		if retry.StatusCode != 409 || replayed.SignedIn || replayed.CommitOutcome != "committed" || replayed.Error != "replay" || len(retry.Cookies()) != 0 || retry.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP exact retry redelivered or lost original outcome", retry.StatusCode, replayed.Error)
		}
	} else {
		start, results := make(chan struct{}), make(chan attempt, 2)
		for range 2 {
			go func() { <-start; result, err := owner.TotpVerify(ctx, request); results <- attempt{result, err} }()
		}
		close(start)
		deliveries := 0
		for range 2 {
			actual := <-results
			if actual.err != nil || actual.result.Outcome != identity.CommitOutcomeCommitted && actual.result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("competing public TOTP completion failed outside bounded original outcome", actual.err)
			}
			if actual.result.Session.Token != (session.Token{}) {
				result = actual.result
				deliveries++
			}
		}
		if deliveries != 1 || result.Outcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
			t.Fatal("competing TOTP completion did not deliver exactly one original session")
		}
	}
	readSource(request)
	changed := request
	changed.FactorID = "CQkJCQkJCQkJCQkJCQkJCQ"
	if user, child, lifetime, err := source.TotpVerificationRateSource(ctx, changed); err == nil || user != "" || child != "" || lifetime != 0 {
		t.Fatal("conflicting retained intent acquired rate source")
	}
	token, err := result.Session.Token.Reveal()
	if err != nil {
		t.Fatal("new TOTP session custody absent", err)
	}
	csrfWire, err := result.CSRFToken.Reveal()
	if err != nil {
		t.Fatal("new TOTP session synchronizer absent", err)
	}
	profile := sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: config.MagicLink.Request.GlobalAuthorityID, PolicyNamespace: config.MagicLink.Consume.PolicyNamespace, Audience: config.MagicLink.Request.Issuer.Audience}
	validation := config.Session.Native.Validation
	validation.Clock = clock.System{}
	reader, err := sessionpg.NewMFAMagicLinkSessionService(f.pool, sessionpg.MFAMagicLinkSessionServiceConfig{Repository: config.MagicLink.Request.Session, Profile: profile, Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || !current.Authenticated {
		t.Fatal("TOTP-delivered session cannot authenticate", err)
	}
	combined, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if current, err := combined.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || !current.Authenticated || current.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
		t.Fatal("selected graph lost MFA session", err)
	}
	if retry, err := owner.TotpVerify(ctx, request); err != nil || retry.Outcome != identity.CommitOutcomeCommitted || !retry.Session.Replayed || retry.Session.Token != (session.Token{}) || retry.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("TOTP retry delivered again", err)
	}
	query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: id, AnonymousFlowID: string(flow), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.totp-verify"}
	if recovered, err := owner.RecoverTotpVerify(ctx, query, request.Caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) {
		t.Fatal("TOTP recovery redelivered or lost outcome", err)
	}
	if a, c, u, s := effects(); a != 0 || c != 3 || u != 1 || s != 1 {
		t.Fatal("completion/retry/recovery lost atomic shared budget/child/session effects", a, c, u, s)
	}
	var state int
	var replayed bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT c.state,t.last_step IS NOT NULL FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t USING(tenant_id,user_id) WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND t.factor_id=$3`, otpTenant, string(challenge.ChallengeID), referenceTOTPFactor).Scan(&state, &replayed); err != nil || state != int(mfa.Completed) || !replayed {
		t.Fatal("completion did not atomically retain factor replay and terminal continuation", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, grant.Payload().Subject); err != nil {
		t.Fatal(err)
	}
	if current, err := reader.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || current.Authenticated || current.Session != (session.Session{}) || current.ValidateAt(time.Now()) == nil {
		t.Fatal("changed factor epoch still authenticated TOTP session")
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version-1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, grant.Payload().Subject); err != nil {
		t.Fatal(err)
	}
	// Restore only this deliberate fixture mutation, then exercise the existing
	// public read/CSRF/rollback/recovery/logout journey on the real MFA session.
	issuedCookie := result.Session.Cookie
	issuedCookie.Value = token
	issued, err := result.Session.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, []*http.Cookie{&issuedCookie}, csrfWire, issued.SessionID, f, features)
}
