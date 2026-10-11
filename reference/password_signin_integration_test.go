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

	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// The browser obtains original password intent through the actual HTTP issuer;
// no fixture writes a flow or manufactures its cookie.
func referencePasswordLogin(t *testing.T, ctx context.Context, f liveStores, client *http.Client, baseURL, origin string, browser []*http.Cookie, c passwordpg.SigninConfig, raw string) (passwordhttp.SigninResponse, session.Token) {
	t.Helper()
	call := func(path string, body any, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("bounded password HTTP response")
		}
		return response, payload
	}
	var device []*http.Cookie
	for _, cookie := range browser {
		if cookie.Name == "__Host-identity_device" {
			device = append(device, cookie)
		}
	}
	response, wire := call("/v1/session/preauth-issue", map[string]string{"method": "password"}, device)
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != http.StatusOK || json.Unmarshal(wire, &flow) != nil || !flow.Issued || flow.CommitOutcome != "committed" || flow.FlowID == "" {
		t.Fatal("native HTTP password initiation", response.StatusCode, flow.Error, flow.CommitOutcome, "prepared", flow.FlowID != "")
	}
	var flowCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || strings.Contains(string(wire), cookie.Value) {
			t.Fatal("password original cookie custody")
		}
		if cookie.Name == "__Host-identity_flow" {
			flowCookie = cookie
		} else {
			t.Fatal("unexpected password original cookie")
		}
	}
	if flowCookie == nil || len(response.Cookies()) != 1 || len(device) != 1 {
		t.Fatal("password original/device custody")
	}
	original, err := sessionpg.ReadPreAuth(ctx, referenceOriginalFlowReader{pool: f.pool}, c.Session, otpTenant, flow.FlowID)
	if err != nil {
		t.Fatal("native original password flow read", err)
	}
	spec, err := original.Bindings()
	binding := spec.Binding
	if err != nil || binding.Intent.Action != "identity.password.signin" || binding.Intent.TenantID != otpTenant || binding.Intent.Origin != origin || binding.Intent.CallbackURL != c.CallbackURLs[0] || binding.Intent.PolicyID != c.PolicyID || binding.Intent.PolicyVersion != 9 || !binding.IssuedAt.Equal(flow.IssuedAt) || !binding.ExpiresAt.Equal(flow.ExpiresAt) {
		t.Fatal("password original authority differs from issued response", err)
	}
	request := map[string]string{"flowID": string(flow.FlowID), "identifier": "recipient@example.invalid", "password": raw, "callbackURL": c.CallbackURLs[0]}
	response, wire = call("/v1/password/signin", request, append(device, flowCookie))
	var out passwordhttp.SigninResponse
	if json.Unmarshal(wire, &out) != nil || strings.Contains(string(wire), raw) || strings.Contains(string(wire), "recipient@example.invalid") {
		t.Fatal("password signin disclosure")
	}
	if !out.SignedIn {
		if response.StatusCode != http.StatusForbidden || out.CommitOutcome != "not_committed" || out.SessionID != "" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("password denial custody", response.StatusCode, out.CommitOutcome)
		}
		return out, session.Token{}
	}
	issued := response.Cookies()
	csrf := response.Header.Get("X-CSRF-Token")
	if response.StatusCode != http.StatusOK || out.CommitOutcome != "committed" || out.SessionID == "" || len(issued) != 1 || issued[0].Name != "__Host-session" || !issued[0].Secure || !issued[0].HttpOnly || issued[0].Path != "/" || issued[0].Domain != "" || issued[0].MaxAge != 0 || !issued[0].Expires.IsZero() || csrf == "" || strings.Contains(string(wire), issued[0].Value) || strings.Contains(string(wire), csrf) {
		t.Fatal("password session/CSRF custody", response.StatusCode)
	}
	token, err := session.ParseToken(issued[0].Value)
	if err != nil {
		t.Fatal("password session token invalid")
	}
	var consumed int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2 AND state='consumed'", otpTenant, string(flow.FlowID)).Scan(&consumed); err != nil || consumed != 1 {
		t.Fatal("password original flow not atomically consumed", err)
	}
	response, replay := call("/v1/password/signin", request, append(device, flowCookie))
	if response.StatusCode == http.StatusOK || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" || bytes.Contains(replay, []byte(issued[0].Value)) {
		t.Fatal("password original replay reissued credential")
	}
	return out, token
}

type referenceOriginalFlowReader struct{ pool *database.Pool }

func (f referenceOriginalFlowReader) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return f.pool.Raw().Query(ctx, sql, args...)
}
