//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresVerificationMFASigninHTTPS(t *testing.T) {
	for _, profile := range []string{"totp-browser-http", "totp-persistent-http", "totp-exhausted-http"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: profile, mfaEnrollment: true}, true)
		})
	}
}

func proveReferenceVerificationMFAHTTPS(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, request email.VerificationSigninRequest, cookies []*http.Cookie, proof string, client *http.Client, base, origin, profile string) {
	t.Helper()
	type response struct {
		status  int
		header  http.Header
		cookies []*http.Cookie
		body    []byte
		err     error
	}
	invoke := func(method, path string, body any, cookies []*http.Cookie, variant, csrf string) response {
		wire, err := json.Marshal(body)
		if err != nil {
			return response{err: err}
		}
		defer clear(wire)
		var payload io.Reader
		if method != http.MethodGet {
			payload = bytes.NewReader(wire)
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, payload)
		if err != nil {
			return response{err: err}
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if variant != "" {
			r.Header.Set("X-MFA-Variant", variant)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		raw, err := client.Do(r)
		if err != nil {
			return response{err: err}
		}
		defer raw.Body.Close()
		data, err := io.ReadAll(io.LimitReader(raw.Body, 16385))
		if len(data) > 16384 {
			return response{err: io.ErrShortBuffer}
		}
		return response{status: raw.StatusCode, header: raw.Header.Clone(), cookies: raw.Cookies(), body: data, err: err}
	}
	hook := f.verificationMFAHook
	if hook == nil {
		t.Fatal("genuine HTTP enrollment window unavailable")
	}
	done := make(chan response, 1)
	body := map[string]any{"commandID": request.Confirmation.CommandID, "token": proof, "callback": request.Confirmation.Callback.String()}
	hook.armed.Store(true)
	go func() { done <- invoke("POST", "/v1/email/verification-confirm", body, cookies, "", ""); close(done) }()
	defer func() {
		hook.armed.Store(false)
		select {
		case <-hook.proceed:
		default:
			close(hook.proceed)
		}
		for range done {
		}
	}()
	select {
	case <-hook.entered:
	case r := <-done:
		t.Fatal("HTTP confirmation never reached actual enrolled-factor read", r.status, r.err)
	case <-ctx.Done():
		t.Fatal("HTTP enrollment window expired")
	}
	factor, secret := enrollVerificationMFATOTP(t, ctx, features, client, base, origin)
	defer clear(secret)
	close(hook.proceed)
	r := <-done
	var confirmation struct {
		Confirmed     bool
		CommitOutcome string
		Signin        *struct {
			SignedIn, ChallengeRequired bool
			CommandID, ChallengeID      string
			Method                      string    `json:"challengeMethod"`
			ExpiresAt                   time.Time `json:"challengeExpiresAt"`
		}
	}
	if r.err != nil || r.status != 200 || json.Unmarshal(r.body, &confirmation) != nil || !confirmation.Confirmed || confirmation.CommitOutcome != "committed" || confirmation.Signin == nil || confirmation.Signin.SignedIn || !confirmation.Signin.ChallengeRequired || confirmation.Signin.ChallengeID == "" || confirmation.Signin.Method != "totp" || r.header.Get("X-MFA-Token") == "" || len(r.cookies) != 0 || r.header.Get("X-CSRF-Token") != "" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatal("HTTPS verification did not deliver pending-only original MFA child", r.status, r.err)
	}
	child, err := capability.ParseProof(r.header.Get("X-MFA-Token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("HTTP child proof malformed")
	}
	issuer, err := issuerpg.NewIssuer(f.config.PasswordSignup.VerificationSignin.TOTP.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	grant, primary, _, err := issuer.ReadIssuanceOrigin(ctx, f.pool, child, "identity.mfa.complete")
	if err != nil || string(primary) != confirmation.Signin.CommandID {
		t.Fatal("HTTP child original issuance mismatch", err)
	}
	reader, err := mfapg.NewContinuationReader(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := reader.Read(ctx, grant, origin)
	if err != nil {
		t.Fatal("HTTP native continuation unreadable", err)
	}
	scope, err := continuation.Bindings()
	if err != nil || scope.VerificationCommandID != request.Confirmation.CommandID || string(scope.ID) != confirmation.Signin.ChallengeID || !scope.ExpiresAt.Equal(confirmation.Signin.ExpiresAt) {
		t.Fatal("HTTP continuation lost original confirmation/scope", err)
	}
	id, _ := identity.NewCommandID()
	completion := map[string]any{"commandID": id, "preAuthID": scope.SourcePreAuthID, "challengeID": scope.ID, "factorID": factor, "token": r.header.Get("X-MFA-Token"), "code": passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)), "callbackURL": request.Confirmation.Callback.String(), "trustDevice": false}
	assertNoDelivery := func(r response) {
		t.Helper()
		if r.err != nil || r.status == http.StatusOK || len(r.cookies) != 0 || r.header.Get("X-CSRF-Token") != "" || r.header.Get("X-MFA-Token") != "" {
			t.Fatal("rejected HTTP MFA request delivered credentials", r.status, r.err)
		}
	}
	// The new owner is never an absent-header or password-origin fallback.
	for _, variant := range []string{"", "password", "unknown"} {
		assertNoDelivery(invoke("POST", "/v1/mfa/totp-verify", completion, cookies, variant, ""))
	}
	foreign := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		copy := *cookie
		if copy.Name == "__Host-identity_flow" {
			copy.Value = strings.Repeat("A", 43)
		}
		foreign = append(foreign, &copy)
	}
	assertNoDelivery(invoke("POST", "/v1/mfa/totp-verify", completion, foreign, "verification", ""))
	wrong := make(map[string]any, len(completion))
	for key, value := range completion {
		wrong[key] = value
	}
	wrongID, _ := identity.NewCommandID()
	wrong["commandID"] = wrongID
	for _, candidate := range []string{"000000", "000001", "000002", "000003"} {
		at := time.Now()
		if candidate != passwordMFAFixtureCode(secret, at.Add(-30*time.Second)) && candidate != passwordMFAFixtureCode(secret, at) && candidate != passwordMFAFixtureCode(secret, at.Add(30*time.Second)) {
			wrong["code"] = candidate
			break
		}
	}
	assertNoDelivery(invoke("POST", "/v1/mfa/totp-verify", wrong, cookies, "verification", ""))
	var remaining int
	if e := f.pool.Raw().QueryRow(ctx, `SELECT attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, string(scope.TenantID), string(scope.ID)).Scan(&remaining); e != nil || remaining != 2 {
		t.Fatal("HTTP invalid variants/browser spent an attempt or wrong code escaped shared budget", e)
	}
	if profile == "totp-exhausted-http" {
		for range 2 {
			next, _ := identity.NewCommandID()
			wrong["commandID"] = next
			assertNoDelivery(invoke("POST", "/v1/mfa/totp-verify", wrong, cookies, "verification", ""))
		}
		assertNoDelivery(invoke("POST", "/v1/mfa/totp-verify", completion, cookies, "verification", ""))
		var state, sessions, uses int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT c.attempts_remaining,c.state,(SELECT count(*) FROM session_store.sessions),k.uses FROM identity_mfa.continuations c JOIN capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$2`, string(scope.TenantID), string(scope.ID)).Scan(&remaining, &state, &sessions, &uses); e != nil || remaining != 0 || mfa.ContinuationState(state) != mfa.Revoked || sessions != 1 || uses != 0 {
			t.Fatal("exhausted shared budget renewed, consumed child or created a session", e, remaining, state, sessions, uses)
		}
		return
	}
	r = invoke("POST", "/v1/mfa/totp-verify", completion, cookies, "verification", "")
	var finished struct {
		SignedIn      bool
		CommitOutcome string
		SessionID     string
	}
	if r.err != nil || r.status != 200 || json.Unmarshal(r.body, &finished) != nil || !finished.SignedIn || finished.CommitOutcome != "committed" || finished.SessionID == "" || len(r.cookies) != 1 || r.header.Get("X-CSRF-Token") == "" {
		t.Fatal("HTTPS verification-origin TOTP did not issue session", r.status, r.err)
	}
	if (r.cookies[0].MaxAge > 0) != strings.Contains(profile, "persistent") {
		t.Fatal("HTTPS TOTP changed original remember policy")
	}
	issued, csrf := r.cookies, r.header.Get("X-CSRF-Token")
	replay := invoke("POST", "/v1/mfa/totp-verify", completion, cookies, "verification", "")
	var replayed struct {
		SignedIn      bool
		CommitOutcome string
	}
	if replay.err != nil || json.Unmarshal(replay.body, &replayed) != nil || replayed.SignedIn || len(replay.cookies) != 0 || replay.header.Get("X-CSRF-Token") != "" || replay.header.Get("X-MFA-Token") != "" {
		t.Fatal("HTTP completed continuation replay disclosed credentials", replay.status, replay.err)
	}
	r = invoke("GET", "/v1/session/get", nil, issued, "", "")
	var current struct{ Authenticated bool }
	if r.err != nil || r.status != 200 || json.Unmarshal(r.body, &current) != nil || !current.Authenticated {
		t.Fatal("HTTPS completed verification session unreadable", r.status, r.err)
	}
	r = invoke("POST", "/v1/session/signout", map[string]any{}, issued, "", csrf)
	var logout struct {
		SignedOut     bool
		CommitOutcome string
	}
	if r.err != nil || r.status != 200 || json.Unmarshal(r.body, &logout) != nil || !logout.SignedOut || logout.CommitOutcome != "committed" {
		t.Fatal("HTTPS completed verification session cannot logout", r.status, r.err)
	}
	r = invoke("GET", "/v1/session/get", nil, issued, "", "")
	current.Authenticated = false
	if r.err != nil || json.Unmarshal(r.body, &current) != nil || current.Authenticated {
		t.Fatal("HTTPS verification MFA session survived logout", r.status, r.err)
	}
}
