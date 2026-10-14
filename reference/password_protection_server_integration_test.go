//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func configureReferencePasswordProtection(t *testing.T, c *reference.StoreConfiguration, origin string) *atomic.Int32 {
	t.Helper()
	p := c.PasswordSignin.Native
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{169}, 32))
	signing, err := passwordpg.NewReauthenticationSigningKey("reference-reauthentication", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier := p.Verifier
	verifier.Now = nil
	c.PasswordVerification = &reference.PasswordVerificationConfiguration{Native: passwordpg.ReauthenticationConfig{Repository: p.Repository, Verifier: verifier, Session: p.Session, Profile: p.Profile, LookupKeys: []session.DigestKey{p.Issuance.LookupKey}, Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-reauthentication", Keys: c.OTP.RiskKeys}, Coordinator: p.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"reference-reauthentication": private.Public().(ed25519.PublicKey)}, Issuer: p.Issuer, Environment: p.Environment, Targets: []passwordpg.ReauthenticationTarget{{Purpose: "identity.password.verify", Action: "identity.password.change", Audience: "reference-password-change"}}, TTL: 2 * time.Minute, IdentifierKey: bytes.Repeat([]byte{170}, 32)}, CSRFKeys: []session.CSRFKey{p.CSRFKey}}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-password-change", [32]byte{171}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := passwordpg.NewKeyedPasswordChangeConfig(requestKeys, [32]byte{172}, "issue-envelope")
	if err != nil {
		t.Fatal(err)
	}
	screening := c.PasswordSignup.Native.Screening
	screening.Now = nil
	var calls *atomic.Int32
	screening.Collect, calls = registrationScreening(t, screening.Policy, "identity.password.change")
	c.PasswordChange = &reference.PasswordChangeConfiguration{Native: passwordpg.PasswordChangeConfig{Audience: "reference-password-change", MaximumAge: 2 * time.Minute, Screening: screening}, Keyed: keyed, Counters: c.PasswordSignup.Counters}
	c.HTTPPasswordVerification = &reference.HTTPPasswordProtectionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "reference-password-verification", RateKey: [32]byte{173}}
	c.HTTPPasswordChange = &reference.HTTPPasswordProtectionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "reference-password-change", RateKey: [32]byte{174}}
	return calls
}

func TestReferenceServerPasswordProtection(t *testing.T) {
	proveReferenceSignupGraph(t, false, true)
}

// Registration, encrypted delivery, confirmation and first login all precede
// this helper through real public routes. No account/password/proof/session
// rows are fabricated. Only external HIBP response IO and failure triggers are
// synthetic; primary authority and all protected effects remain native.
func proveReferencePasswordProtection(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, cookies []*http.Cookie, csrf string, screens *atomic.Int32) {
	t.Helper()
	call := func(path string, body any, key, token string) (*http.Response, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(data)
		r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" || path != "/v1/session/preauth-issue" && len(response.Cookies()) != 0 {
			t.Fatal("protected operation leaked/cacheable/unbounded custody")
		}
		return response, payload
	}
	verification := map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": "identity.password.change", "audience": "reference-password-change"}
	r, p := call("/v1/password/verify", verification, "", "")
	if r.StatusCode != 403 {
		t.Fatal("verification bypassed CSRF", r.StatusCode)
	}
	r, p = call("/v1/password/verify", verification, "", csrf)
	var verified passwordhttp.VerificationResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &verified) != nil || !verified.Verified || verified.Proof == nil || verified.Proof.ProofID == "" || verified.CommitOutcome != "committed" {
		t.Fatal("public native password verification failed", r.StatusCode, verified.Error)
	}
	change := map[string]string{"proofID": verified.Proof.ProofID, "newPassword": "synthetic-changed-password"}
	r, _ = call("/v1/password/change", change, "password-change-missing-csrf", "")
	if r.StatusCode != 403 || screens.Load() != 0 {
		t.Fatal("change bypassed CSRF or screened before admission", r.StatusCode)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION password_change_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic password change rollback'; END $$;
CREATE TRIGGER password_change_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION password_change_fixture_fail()`); err != nil {
		t.Fatal("change failure fixture", err)
	}
	r, p = call("/v1/password/change", change, "password-change-rollback", csrf)
	var failed passwordhttp.ChangeResponse
	if json.Unmarshal(p, &failed) != nil || r.StatusCode == 200 || failed.Changed || failed.CommitOutcome != "not_committed" || failed.CommandID == "" {
		t.Fatal("failed change fabricated success or lost original outcome", r.StatusCode, failed.CommitOutcome, failed.Error, "screening calls", screens.Load())
	}
	var replacements, sessionEffects, consumed int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.credential_replacements),(SELECT count(*) FROM session_store.password_changes),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id IS NOT NULL)`).Scan(&replacements, &sessionEffects, &consumed); err != nil || replacements != 0 || sessionEffects != 0 || consumed != 0 {
		t.Fatal("change rollback leaked protected effects", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER password_change_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION password_change_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	r, p = call("/v1/password/change", change, "password-change-committed", csrf)
	var changed passwordhttp.ChangeResponse
	if json.Unmarshal(p, &changed) != nil || r.StatusCode != 200 || !changed.Changed || changed.CommitOutcome != "committed" || changed.CredentialVersion != 2 || !changed.AuthorityInvalidated || changed.Recovery == nil {
		t.Fatal("public native password change failed", r.StatusCode, changed.CommitOutcome, changed.Error)
	}
	// Revocation closes the authenticated HTTP boundary, including same-key
	// retries. Authorized historical recovery uses the separate native port below;
	// a retained command must not turn the revoked cookie into authentication.
	count := screens.Load()
	r, p = call("/v1/password/change", change, "password-change-committed", csrf)
	var replay passwordhttp.ChangeResponse
	if json.Unmarshal(p, &replay) != nil || r.StatusCode != http.StatusUnauthorized || replay.Changed || replay.CredentialVersion != 0 || screens.Load() != count {
		t.Fatal("revoked source regained change authority or repeated screening", r.StatusCode, replay.Error)
	}
	owner, err := features.CookiePasswordChange()
	if err != nil {
		t.Fatal(err)
	}
	q := *changed.Recovery
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Tenant: authorization.TenantID(q.TenantID), Action: "identity.password.change", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
	historical, err := owner.Recover(ctx, q, caller)
	if err != nil || historical.CommandID != changed.CommandID || historical.Outcome != identity.CommitOutcomeCommitted || historical.CredentialVersion != 2 {
		t.Fatal("native change recovery lost committed history", err)
	}
	foreign := q
	foreign.TenantID = "foreign"
	if _, err := owner.Recover(ctx, foreign, caller); err == nil {
		t.Fatal("foreign scope disclosed change history")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/session/get", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		request.AddCookie(c)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var read sessionhttp.GetResponse
	decode := json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&read)
	closeErr := response.Body.Close()
	if decode != nil || closeErr != nil || response.StatusCode != 200 || read.Authenticated {
		t.Fatal("password change did not revoke original session")
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.credential_replacements),(SELECT count(*) FROM session_store.password_changes),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id IS NOT NULL)`).Scan(&replacements, &sessionEffects, &consumed); err != nil || replacements != 1 || sessionEffects != 1 || consumed != 1 {
		t.Fatal("successful change duplicated or omitted atomic effects", err)
	}
	login := func(candidate string) passwordhttp.SigninResponse {
		t.Helper()
		r, p := call("/v1/session/preauth-issue", map[string]string{"method": "password"}, "", "")
		var flow sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(p, &flow) != nil || !flow.Issued {
			t.Fatal("change successor login initiation", r.StatusCode)
		}
		original := cookies
		cookies = r.Cookies()
		for _, c := range original {
			if c.Name == "__Host-identity_device" {
				present := false
				for _, current := range cookies {
					present = present || current.Name == c.Name
				}
				if !present {
					cookies = append(cookies, c)
				}
			}
		}
		// Signin legitimately delivers a new session cookie. Use its actual public
		// route directly rather than the no-cookie protected-operation helper.
		data, _ := json.Marshal(map[string]string{"flowID": string(flow.FlowID), "identifier": "registered@example.invalid", "password": candidate, "callbackURL": origin + "/reset"})
		defer clear(data)
		req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/password/signin", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		cookies = original
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out passwordhttp.SigninResponse
		err = json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(&out)
		closed := res.Body.Close()
		if err != nil || closed != nil {
			t.Fatal("successor login response")
		}
		if candidate == "synthetic-changed-password" && (res.StatusCode != 200 || out.SessionID == "" || len(res.Cookies()) != 1) {
			t.Fatal("new password could not log in", res.StatusCode, out.Error)
		}
		if candidate == "synthetic-registration-password" && (res.StatusCode == 200 || len(res.Cookies()) != 0) {
			t.Fatal("old password still authenticated")
		}
		return out
	}
	login("synthetic-registration-password")
	login("synthetic-changed-password")
}
