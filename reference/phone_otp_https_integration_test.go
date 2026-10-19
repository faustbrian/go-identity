//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresPhoneOTPSigninHTTPS(t *testing.T) {
	for _, mode := range []string{"browser", "persistent"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phoneOTP: mode}, true)
		})
	}
}

func TestReferencePostgresPhoneOTPPasswordUsernameCoexistenceHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, phoneEnrollment: true, phoneOTP: "browser", phonePassword: true, username: true})
}

func configureReferencePhoneOTPSignin(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	keys, err := kernel.NewRequestKeyConfig("reference-phone-otp-signin", [32]byte{235}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.PhoneOTPSignin = &reference.PhoneOTPSigninConfiguration{Policy: c.Phone.Policy, CodePolicy: policy, RequestKeys: keys, TemplateID: "phone-code", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}}
	c.HTTPPhoneOTPSignin = &reference.HTTPPhoneOTPSigninConfiguration{ActorID: c.HTTPPasswordSignin.ActorID, PolicyRevision: 9}
}

// This begins only after public registration/email confirmation/password proof
// and real SMS phone enrollment. No phone, account or factor eligibility is
// seeded to make login pass. Capture replaces only the external sender seam.
func proveReferencePhoneOTPHTTPS(t *testing.T, ctx context.Context, f liveStores, workers reference.WorkerSet, messages <-chan string, client *http.Client, base, origin string, user identity.UserID, readSession func([]*http.Cookie) bool, remember bool) {
	t.Helper()
	call := func(path string, body any, cookies []*http.Cookie, key, requestOrigin, csrf string) (*http.Response, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("phone OTP HTTPS request", err)
		}
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if err != nil || closed != nil || len(wire) > 16384 || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(wire, []byte("+12025550123")) {
			t.Fatal("phone OTP response bounds, cleanup or redaction")
		}
		return response, wire
	}
	issue := func() (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, wire := call("/v1/session/preauth-issue", map[string]any{"method": "phone-otp", "identifier": "+12025550123", "remember": remember}, nil, "", origin, "")
		var flow sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(wire, &flow) != nil || !flow.Issued || len(r.Cookies()) != 2 {
			t.Fatal("original phone OTP initiation failed", r.StatusCode)
		}
		return flow, r.Cookies()
	}
	flow, browser := issue()
	_, foreign := issue()
	send := map[string]any{"flowID": flow.FlowID, "number": "+12025550123"}
	for index, denial := range []struct {
		origin  string
		browser []*http.Cookie
	}{{"", browser}, {"https://foreign.invalid", browser}, {origin, nil}, {origin, foreign}} {
		r, _ := call("/v1/phone/send-signin", send, denial.browser, "phone-otp-denial-"+strconv.Itoa(index), denial.origin, "")
		if r.StatusCode == 202 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("foreign phone OTP send custody admitted", r.StatusCode)
		}
	}
	send["number"] = "+12025550124"
	r, _ := call("/v1/phone/send-signin", send, browser, "phone-otp-retarget", origin, "")
	// The existing send pipeline maps failed native preparation to unavailable,
	// not a recipient-dependent status. No accepted send or credential escapes.
	if r.StatusCode != 503 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("phone OTP original target denial changed", r.StatusCode)
	}
	send["number"] = "+12025550123"
	r, wire := call("/v1/phone/send-signin", send, browser, "phone-otp-original", origin, "")
	var sent otphttp.SendResponse
	decodeErr := json.Unmarshal(wire, &sent)
	if r.StatusCode != 202 || decodeErr != nil || !sent.Accepted || sent.CommandID == "" || sent.CommitOutcome != "committed" || len(r.Cookies()) != 0 {
		t.Fatal("phone OTP native send failed", r.StatusCode, sent.Error, "outcome", sent.CommitOutcome)
	}
	r, wire = call("/v1/phone/send-signin", send, browser, "phone-otp-original", origin, "")
	var replay otphttp.SendResponse
	if r.StatusCode != 202 || json.Unmarshal(wire, &replay) != nil || replay != sent {
		t.Fatal("phone OTP send did not preserve original command")
	}
	if out, err := workers.ProcessDeliveryOne(ctx, 1); err != nil || !out.Claimed {
		t.Fatal("real encrypted SMS delivery failed", err)
	}
	var code string
	select {
	case code = <-messages:
	case <-ctx.Done():
		t.Fatal("phone OTP SMS not delivered")
	}
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		t.Fatal("invalid delivered phone code")
	}
	facts := func() [3]int {
		t.Helper()
		var out [3]int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM session_store.session_issuances) FROM otp_store.challenges WHERE challenge_id=$1`, string(sent.CommandID)).Scan(&out[0], &out[1], &out[2]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	initial := facts()
	bad := map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": code, "password": "synthetic-password"}
	r, _ = call("/v1/phone/signin", bad, browser, "", origin, "")
	if r.StatusCode != 400 || facts() != initial {
		t.Fatal("phone OTP accepted password override or charged it")
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	body := map[string]any{"flowID": flow.FlowID, "sendCommandID": sent.CommandID, "code": wrong}
	r, wire = call("/v1/phone/signin", body, browser, "", origin, "")
	var denied otphttp.SigninResponse
	if err := json.Unmarshal(wire, &denied); err != nil {
		t.Fatal("phone OTP denial response", err)
	}
	// The retained OTP HTTP contract uses 503 for generic native denials;
	// the authoritative noncommit and exact counted debit distinguish this
	// response from an unobserved failure without disclosing recipient state.
	if r.StatusCode != 503 || denied.SignedIn || denied.CommitOutcome != "not_committed" || denied.Recovery == nil || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || facts() != [3]int{initial[0] + 1, initial[1] + 1, initial[2]} {
		t.Fatal("phone OTP wrong-code denial not counted exactly once", r.StatusCode, denied.Error, denied.CommitOutcome, "facts", facts(), "initial", initial)
	}
	deniedFacts := facts()
	r, wire = call("/v1/phone/signin/recover", map[string]any{"flowID": flow.FlowID, "recovery": denied.Recovery}, browser, "", origin, "")
	var denialHistory otphttp.SigninResponse
	if r.StatusCode != 503 || json.Unmarshal(wire, &denialHistory) != nil || denialHistory.SignedIn || denialHistory.SessionID != "" || denialHistory.CommitOutcome != "not_committed" || denialHistory.CommandID != denied.CommandID || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || facts() != deniedFacts {
		t.Fatal("phone OTP denied history recharged or disclosed credentials", r.StatusCode)
	}
	body["code"] = code
	r, wire = call("/v1/phone/signin", body, browser, "", origin, "")
	var signed otphttp.SigninResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || signed.Recovery == nil || len(r.Cookies()) != 1 || r.Header.Get("X-CSRF-Token") == "" {
		t.Fatal("phone OTP did not issue its native session", r.StatusCode, signed.Error)
	}
	cookies, csrf := r.Cookies(), r.Header.Get("X-CSRF-Token")
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || (cookie.MaxAge > 0) != remember || cookie.Expires.IsZero() != !remember || !readSession(cookies) || bytes.Contains(wire, []byte(cookie.Value)) || bytes.Contains(wire, []byte(code)) || bytes.Contains(wire, []byte(csrf)) {
		t.Fatal("phone OTP session lost read/cookie policy or leaked secrets")
	}
	var purpose, subject string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT purpose,user_id FROM session_store.session_issuances WHERE session_id=$1`, signed.SessionID).Scan(&purpose, &subject); err != nil || purpose != "identity.phone.signin" || subject != string(user) {
		t.Fatal("phone OTP lost native issuance provenance", err)
	}
	committed := facts()
	if committed != [3]int{initial[0] + 2, initial[1] + 1, initial[2] + 1} {
		t.Fatal("phone OTP consumption and session did not commit together")
	}
	for range 2 {
		h, wire := call("/v1/phone/signin/recover", map[string]any{"flowID": flow.FlowID, "recovery": signed.Recovery}, browser, "", origin, "")
		var history otphttp.SigninResponse
		if h.StatusCode != 200 || json.Unmarshal(wire, &history) != nil || history.SignedIn || history.SessionID != signed.SessionID || history.CommitOutcome != "committed" || len(h.Cookies()) != 0 || h.Header.Get("X-CSRF-Token") != "" || facts() != committed {
			t.Fatal("phone OTP history changed outcome or redelivered credentials", h.StatusCode)
		}
	}
	r, _ = call("/v1/phone/signin", body, browser, "", origin, "")
	if r.StatusCode == 200 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || facts() != committed {
		t.Fatal("phone OTP replay reissued or recharged")
	}
	r, _ = call("/v1/session/signout", map[string]any{}, cookies, "", origin, csrf)
	if r.StatusCode != 200 || readSession(cookies) {
		t.Fatal("phone OTP session survived logout", r.StatusCode)
	}
}
