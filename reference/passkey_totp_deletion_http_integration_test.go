//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passkeyhttp "github.com/faustbrian/go-identity/http/passkey"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
)

func proveReferencePasskeyTOTPHTTPDeletion(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, c reference.StoreConfiguration, handler http.Handler, user identity.UserID, first crypto.Signer, firstID, handle []byte, second crypto.Signer, secondID []byte, original, additional passkeyhttp.CredentialMetadata, factor mfa.FactorID, secret []byte, issued passkeyTOTPHTTPObservation, discoverable bool, request func(string, map[string]any, []*http.Cookie, string, string, string, ...string) passkeyTOTPHTTPObservation) {
	t.Helper()
	origin := c.Passkey.Flow.Origin
	call := func(path string, body any, key string, cookies []*http.Cookie, csrf, trusted string) passkeyDeletionHTTPObservation {
		t.Helper()
		input, ok := body.(map[string]any)
		if !ok {
			t.Fatal("HTTP removal fixture has no closed request")
		}
		// Anonymous browser signin rejects a CSRF header even when empty;
		// preserve absence, as the original ordinary HTTP caller does.
		var out passkeyTOTPHTTPObservation
		if csrf == "" {
			out = request(path, input, cookies, "", key, trusted)
		} else {
			out = request(path, input, cookies, "", key, trusted, csrf)
		}
		return passkeyDeletionHTTPObservation{out.status, out.header, out.body, out.cookies}
	}
	flow := func(method string) (string, []*http.Cookie) {
		t.Helper()
		out := request("/v1/session/preauth-issue", map[string]any{"method": method, "remember": false}, nil, "", "", origin)
		var result struct {
			Issued bool   `json:"issued"`
			FlowID string `json:"flowID"`
		}
		if out.status != 200 || json.Unmarshal(out.body, &result) != nil || !result.Issued || result.FlowID == "" || len(out.cookies) != 2 {
			t.Fatal("HTTP removal genuine browser custody absent", out.status)
		}
		return result.FlowID, out.cookies
	}
	// Withdrawal is injected into this genuinely confirmed enrollment only;
	// restoration checks its exact previous version and never resets OTP replay.
	var version string
	if err := f.pool.Raw().QueryRow(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=enrollment_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 RETURNING (enrollment_version-1)::text`, otpTenant, string(user), string(factor)).Scan(&version); err != nil {
		t.Fatal(err)
	}
	denied := call("/v1/passkey/delete", map[string]any{"phase": "options", "referenceID": original.ReferenceID, "expectedVersion": original.Version}, "mfa-http-removal-withdrawn", issued.cookies, issued.header.Get("X-CSRF-Token"), origin)
	tag, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=$4::numeric WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND enrollment_version=$4::numeric+1`, otpTenant, string(user), string(factor), version)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("restore original removal factor authority", err)
	}
	if denied.code < 400 || len(denied.cookies) != 0 || denied.header.Get("X-CSRF-Token") != "" {
		t.Fatal("withdrawn enrolled factor retained HTTP removal authority", denied.code)
	}
	completion := removalHTTPSessionCompletion{discoverable: discoverable, beforeSignin: func() {
		waitReferenceRemovalTOTPStep(t, ctx, f, user, factor)
	}, finish: func(primary passkeyDeletionHTTPObservation, flowID string, cookies []*http.Cookie) passkeyDeletionHTTPObservation {
		t.Helper()
		var child struct {
			SignedIn bool   `json:"signedIn"`
			Required bool   `json:"challengeRequired"`
			ID       string `json:"challengeID"`
			Method   string `json:"challengeMethod"`
		}
		proof := primary.header.Get("X-MFA-Token")
		if primary.code != 200 || json.Unmarshal(primary.body, &child) != nil || child.SignedIn || !child.Required || child.ID == "" || child.Method != "totp" || proof == "" || len(primary.cookies) != 0 || primary.header.Get("X-CSRF-Token") != "" || bytes.Contains(primary.body, []byte(proof)) {
			t.Fatal("surviving HTTP key bypassed original TOTP", primary.code)
		}
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"commandID": command, "preAuthID": flowID, "challengeID": child.ID, "factorID": factor, "token": proof, "code": passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)), "callbackURL": c.Passkey.Flow.CallbackURL, "trustDevice": false}
		out := request("/v1/mfa/totp-verify", body, cookies, "passkey", "", origin)
		var result struct {
			SignedIn  bool   `json:"signedIn"`
			SessionID string `json:"sessionID"`
			Outcome   string `json:"commitOutcome"`
		}
		if out.status != 200 || json.Unmarshal(out.body, &result) != nil || !result.SignedIn || result.SessionID == "" || result.Outcome != "committed" || len(out.cookies) != 1 || out.header.Get("X-CSRF-Token") == "" {
			t.Fatal("HTTP surviving-key TOTP did not issue genuine session", out.status)
		}
		retry := request("/v1/mfa/totp-verify", body, cookies, "passkey", "", origin)
		if retry.status != 409 || len(retry.cookies) != 0 || retry.header.Get("X-CSRF-Token") != "" {
			t.Fatal("HTTP surviving-key TOTP retry redisclosed credentials", retry.status)
		}
		return passkeyDeletionHTTPObservation{out.status, out.header, out.body, out.cookies}
	}}
	proveReferenceHTTPSessionDeletion(t, ctx, features, c, handler, user, issued.cookies, issued.header.Get("X-CSRF-Token"), first, firstID, handle, 2, original, additional, second, secondID, call, flow, completion)
}
