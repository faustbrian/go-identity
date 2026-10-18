//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	database "github.com/faustbrian/go-postgres"
)

// Registration, verification, original browsers, delivered challenges and
// sessions all come from the public graph; no domain state is seeded here.
func TestReferencePostgresEmailOTPSigninHTTPS(t *testing.T) {
	for _, mode := range []string{"browser", "persistent", "unknown", "enrolled", "missing", "changed"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailSignin: mode, completionCommitFault: mode == "unknown", mfaEnrollment: mode == "enrolled"}, mode == "enrolled")
		})
	}
}

// Change the actual generation after native signin's preliminary read, during
// its bounded policy callback. Source discovery is the first policy visit;
// consuming admission is the second. Neither callback supplies factor proof.
type otpSigninFactorChangePolicy struct {
	pool   *database.Pool
	visits atomic.Int32
}

func (p *otpSigninFactorChangePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.otp.signin" && c.Request.Resource.Type == "identity.user" && p.visits.Add(1) == 2 {
		if _, err := p.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(c.Request.Tenant), string(c.Request.Resource.ID)); err != nil {
			return authorization.Decision{}, err
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func proveReferenceEmailOTPSignin(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, mode string) {
	t.Helper()
	invoke := func(method, path string, body any, cookies []*http.Cookie, key, requestOrigin string) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal("OTP request serialization")
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", requestOrigin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("OTP consumer request failed")
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded/cacheable OTP response")
		}
		return response, payload
	}
	issue := func() (sessionhttp.PreAuthResponse, []*http.Cookie) {
		r, payload := invoke(http.MethodPost, "/v1/session/preauth-issue", map[string]bool{"remember": mode == "persistent"}, nil, "", origin)
		var flow sessionhttp.PreAuthResponse
		if r.StatusCode != http.StatusOK || json.Unmarshal(payload, &flow) != nil || !flow.Issued || len(r.Cookies()) != 2 {
			t.Fatal("original email OTP browser not issued", r.StatusCode)
		}
		return flow, r.Cookies()
	}
	flow, browser := issue()
	sendBody := map[string]any{"flowID": flow.FlowID, "email": "registered@example.invalid"}
	r, payload := invoke(http.MethodPost, "/v1/otp/send", sendBody, browser, "consumer-email-otp-send", origin)
	var sent otphttp.SendResponse
	if r.StatusCode != http.StatusAccepted || json.Unmarshal(payload, &sent) != nil || !sent.Accepted || sent.CommitOutcome != "committed" || sent.CommandID == "" || len(r.Cookies()) != 0 || bytes.Contains(payload, []byte("registered@example.invalid")) {
		t.Fatal("enumeration-safe OTP Send failed", r.StatusCode)
	}
	facts := func() [4]int {
		t.Helper()
		var out [4]int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM session_store.session_issuances),(SELECT count(*) FROM otp_store.challenges WHERE state='finalized') FROM otp_store.challenges WHERE challenge_id=$1`, string(sent.CommandID)).Scan(&out[0], &out[1], &out[2], &out[3]); err != nil {
			t.Fatal("OTP durable effects unavailable", err)
		}
		return out
	}
	initial := facts()
	r, payload = invoke(http.MethodPost, "/v1/otp/send", sendBody, browser, "consumer-email-otp-send", origin)
	var replay otphttp.SendResponse
	if r.StatusCode != http.StatusAccepted || json.Unmarshal(payload, &replay) != nil || replay != sent || facts() != initial {
		t.Fatal("original OTP Send retry changed challenge or session")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("OTP encrypted delivery failed", err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("actual OTP sender never received code")
	}
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		t.Fatal("selected code profile not delivered")
	}
	body := map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": code}
	if mode == "missing" {
		if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities f USING identity.identifiers i WHERE f.tenant_id=i.tenant_id AND f.user_id=i.user_id AND i.tenant_id=$1 AND i.canonical_value='registered@example.invalid'`, otpTenant); err != nil {
			t.Fatal("factor authority withdrawal failed", err)
		}
	}
	if mode == "enrolled" || mode == "missing" || mode == "changed" {
		r, _ = invoke(http.MethodPost, "/v1/otp/signin", body, browser, "", origin)
		if r.StatusCode == http.StatusOK || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || facts() != initial {
			t.Fatal("email OTP bypassed enrolled, missing or changed factor authority", r.StatusCode)
		}
		return
	}
	_, foreignBrowser := issue()
	for _, denial := range []struct {
		method, origin string
		browser        []*http.Cookie
	}{{http.MethodGet, origin, browser}, {http.MethodPost, "https://foreign.example", browser}, {http.MethodPost, origin, foreignBrowser}} {
		r, _ = invoke(denial.method, "/v1/otp/signin", body, denial.browser, "", denial.origin)
		if r.StatusCode == http.StatusOK || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || facts() != initial {
			t.Fatal("foreign/scanner OTP attempt mutated protected state", r.StatusCode)
		}
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	r, _ = invoke(http.MethodPost, "/v1/otp/signin", map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": wrong}, browser, "", origin)
	afterWrong := facts()
	if r.StatusCode == http.StatusOK || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || afterWrong != [4]int{initial[0] + 1, initial[1] + 1, initial[2], initial[3]} {
		t.Fatal("wrong OTP was not counted exactly once without session effects", r.StatusCode)
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	r, payload = invoke(http.MethodPost, "/v1/otp/signin", body, browser, "", origin)
	var signed otphttp.SigninResponse
	if json.Unmarshal(payload, &signed) != nil || signed.Recovery == nil {
		t.Fatal("OTP completion lost original recovery correlation", r.StatusCode)
	}
	if mode == "unknown" {
		if r.StatusCode != http.StatusServiceUnavailable || signed.CommitOutcome != "unknown" || signed.SignedIn || signed.SessionID != "" || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || !f.completionFault.hit.Load() {
			t.Fatal("ambiguous OTP commit exposed credentials or hid commitment", r.StatusCode)
		}
	} else {
		if r.StatusCode != http.StatusOK || !signed.SignedIn || signed.CommitOutcome != "committed" || signed.SessionID == "" || len(r.Cookies()) != 1 || r.Header.Get("X-CSRF-Token") == "" {
			t.Fatal("OTP did not issue the committed session", r.StatusCode)
		}
		cookie := r.Cookies()[0]
		if cookie.Name != "__Host-session" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || (cookie.MaxAge > 0) != (mode == "persistent") || cookie.Expires.IsZero() != (mode != "persistent") || bytes.Contains(payload, []byte(cookie.Value)) || bytes.Contains(payload, []byte(code)) || bytes.Contains(payload, []byte(r.Header.Get("X-CSRF-Token"))) {
			t.Fatal("OTP lost remember policy or exposed credential material")
		}
	}
	committed := facts()
	if committed != [4]int{initial[0] + 2, initial[1] + 1, initial[2] + 1, initial[3] + 1} {
		t.Fatal("OTP use and session issuance did not commit exactly once")
	}
	for range 2 {
		recoveryResponse, recoveryPayload := invoke(http.MethodPost, "/v1/otp/signin/recover", map[string]any{"flowID": flow.FlowID, "recovery": signed.Recovery}, browser, "", origin)
		var history otphttp.SigninResponse
		if recoveryResponse.StatusCode != http.StatusOK || json.Unmarshal(recoveryPayload, &history) != nil || history.CommitOutcome != "committed" || history.SignedIn || history.SessionID == "" || signed.SessionID != "" && history.SessionID != signed.SessionID || len(recoveryResponse.Cookies()) != 0 || recoveryResponse.Header.Get("X-CSRF-Token") != "" || facts() != committed {
			t.Fatal("code-free OTP recovery changed original outcome or redelivered custody", recoveryResponse.StatusCode)
		}
	}
	repeated, _ := invoke(http.MethodPost, "/v1/otp/signin", body, browser, "", origin)
	if repeated.StatusCode == http.StatusOK || len(repeated.Cookies()) != 0 || repeated.Header.Get("X-CSRF-Token") != "" || facts() != committed {
		t.Fatal("replayed OTP issued or charged another attempt")
	}
	if mode != "unknown" {
		proveRegistrationSessionLogout(t, ctx, client, base, origin, r.Cookies(), r.Header.Get("X-CSRF-Token"), signed.SessionID, f, features)
	}
}
