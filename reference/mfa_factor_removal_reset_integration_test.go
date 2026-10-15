//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// The account, password, email, factor and sessions all came from preceding
// public operations. Only provider IO and the bounded mail sender are synthetic.
func proveReferenceEmailResetAfterRemoval(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, browser []*http.Cookie, messages <-chan string, user identity.UserID) {
	t.Helper()
	owner, err := features.PasswordReset()
	if err != nil {
		t.Fatal("selected native recovery owner unavailable", err)
	}
	command, _ := identity.NewCommandID()
	key, _ := identity.NewIdempotencyKey([]byte("factor-removal-email-reset"))
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(command), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.password.reset-request", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.reset-request"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	request := password.ResetRequestRequest{TenantID: otpTenant, CommandID: command, Identifier: identifier.Input("registered@example.invalid"), CallbackURL: origin + "/reset", IdempotencyKey: key, Caller: caller, Origin: origin, Network: "127.0.0.1", Device: "reference-removal-reset"}
	invoke := func(path, key string, body any) []byte {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range browser {
			if cookie.Name == "__Host-identity_device" {
				r.AddCookie(cookie)
			}
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("public post-removal recovery request failed")
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(payload) > 16384 || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("post-removal recovery lost public response custody", response.StatusCode)
		}
		return payload
	}
	var accepted password.ResetRequestResult
	if f.factorRemovalResetHTTP {
		body := map[string]string{"commandID": string(command), "identifier": string(request.Identifier), "callbackURL": request.CallbackURL}
		first := invoke("/v1/password/reset-request", "factor-removal-email-reset", body)
		var result passwordhttp.ResetRequestResponse
		if json.Unmarshal(first, &result) != nil || !result.Accepted || result.CommitOutcome != "committed" {
			t.Fatal("HTTP reset did not accept post-removal account")
		}
		if again := invoke("/v1/password/reset-request", "factor-removal-email-reset", body); !bytes.Equal(first, again) {
			t.Fatal("HTTP recovery request replay changed outcome")
		}
		accepted = password.ResetRequestResult{CommandID: result.CommandID, Outcome: identity.CommitOutcomeCommitted, Accepted: true}
	} else {
		accepted, err = owner.ResetRequest(ctx, request)
		if err != nil || !accepted.Accepted || accepted.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("native reset did not accept post-removal account", err)
		}
		if again, err := owner.ResetRequest(ctx, request); err != nil || again != accepted {
			t.Fatal("native recovery request replay changed outcome", err)
		}
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("post-removal reset delivery failed", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("selected recovery did not deliver a post-removal reset")
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host != mustResetHost(t, origin) || u.Path != "/password/reset" || u.Query().Get("token") == "" {
		t.Fatal("post-removal reset lost selected delivery scope")
	}
	proof, err := capability.ParseProof(u.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("delivered post-removal reset proof malformed")
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	secret, err := primitive.NewSecret([]byte("synthetic-reference-new-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	completion, _ := identity.NewCommandID()
	caller.Request.Action = "identity.password.reset-complete"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	caller.CorrelationID = string(completion)
	complete := password.ResetCompleteRequest{TenantID: otpTenant, CommandID: completion, Token: proof, NewPassword: secret, Caller: caller, Origin: origin, Network: request.Network, Device: request.Device}
	if f.factorRemovalResetHTTP {
		body := map[string]string{"commandID": string(completion), "token": u.Query().Get("token"), "newPassword": "synthetic-reference-new-password"}
		first := invoke("/v1/password/reset-complete", "", body)
		var result passwordhttp.ResetCompleteResponse
		if json.Unmarshal(first, &result) != nil || !result.Completed || !result.SessionsRevoked || result.CommitOutcome != "committed" || result.CredentialVersion != 2 {
			t.Fatal("HTTP reset could not complete after factor removal")
		}
		if again := invoke("/v1/password/reset-complete", "", body); !bytes.Equal(first, again) {
			t.Fatal("HTTP reset completion replay changed outcome")
		}
	} else {
		out, err := owner.ResetComplete(ctx, complete)
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || !out.SessionsRevoked || out.CredentialVersion != 2 {
			t.Fatal("native reset could not complete after factor removal", err)
		}
		if again, err := owner.ResetComplete(ctx, complete); err != nil || again != out {
			t.Fatal("native reset completion replay changed outcome", err)
		}
	}
	proveResetHIBPEvents(t, ctx, f, completion, "AAAAAAAAAAAAAAAAAAAACQ", "synthetic-reference-new-password")
	var effects, removed, activeCodes, activeFactors int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM session_store.password_resets WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=3 AND encrypted_secret IS NULL AND last_step IS NULL),
(SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state IN(1,2)),
(SELECT active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2)`, otpTenant, string(user)).Scan(&effects, &removed, &activeCodes, &activeFactors); err != nil || effects != 1 || removed != 1 || activeCodes != 0 || activeFactors != 0 {
		t.Fatal("post-removal reset repeated effects or resurrected factor authority", err)
	}
	old, _ := referencePasswordLogin(t, ctx, f, client, base, origin, browser, f.removalSignin, "synthetic-registration-password", "registered@example.invalid")
	if old.SignedIn {
		t.Fatal("old password obtained a session after post-removal reset")
	}
	current, token := referencePasswordLogin(t, ctx, f, client, base, origin, browser, f.removalSignin, "synthetic-reference-new-password", "registered@example.invalid")
	if !current.SignedIn {
		t.Fatal("selected recovery did not restore usable password login")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	if got, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || !got.Authenticated {
		t.Fatal("recovered password did not produce a usable session", err)
	}
}
