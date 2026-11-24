//go:build integration

package reference_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-sso/saml"
)

func proveReferenceSAMLSPLogout(t *testing.T, ctx context.Context, base *http.Client,
	origin, providerPath, idpOrigin, redirectEndpoint, finalRedirect, csrf string,
	browser *http.Client, spKey *rsa.PublicKey, idp referenceSAMLIdPFixture) {
	t.Helper()
	appURL, err := url.Parse(origin)
	if err != nil || browser.Jar == nil || csrf == "" {
		t.Fatal("SP logout requires the original authenticated browser and synchronizer")
	}
	originalCookies := browser.Jar.Cookies(appURL)
	if len(originalCookies) != 2 {
		t.Fatal("SP logout requires the two original session and CSRF cookies")
	}
	var sessionCookieName string
	var csrfCookiePresent bool
	for _, cookie := range originalCookies {
		if cookie.Name == "__Host-identity_csrf" {
			if cookie.Value != csrf {
				t.Fatal("SP logout synchronizer does not match the issued CSRF cookie")
			}
			csrfCookiePresent = true
			continue
		}
		sessionCookieName = cookie.Name
	}
	if sessionCookieName == "" || !csrfCookiePresent {
		t.Fatal("SP logout has no original session and CSRF cookie pair")
	}
	client := *base
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	do := func(method, path, body string, cookies []*http.Cookie, decorate func(*http.Request)) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, origin+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		if decorate != nil {
			decorate(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("Reference HTTPS SP logout request failed", err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	readOriginalSession := func(want bool) sessionhttp.GetResponse {
		t.Helper()
		response := do(http.MethodGet, "/v1/session/get", "", originalCookies, nil)
		defer response.Body.Close()
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&result) != nil || result.Authenticated != want {
			t.Fatal("original browser cookie did not report the expected SP logout state", response.StatusCode, want)
		}
		if want && (result.Session == nil || result.Principal == nil) {
			t.Fatal("SP logout prerequisite has no authenticated session and principal")
		}
		return result
	}
	body, err := json.Marshal(map[string]string{"finalRedirect": finalRedirect})
	if err != nil {
		t.Fatal(err)
	}
	startHeaders := func(request *http.Request) {
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		request.Header.Set("Idempotency-Key", "reference-saml-sp-logout")
	}
	foreign := do(http.MethodPost, providerPath+"/logout", string(body), originalCookies, func(request *http.Request) {
		startHeaders(request)
		request.Header.Set("Origin", "https://unconfigured.example")
	})
	if foreign.StatusCode != http.StatusForbidden || foreign.Header.Get("Location") != "" || len(foreign.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("foreign origin reached SP logout or changed browser authority", foreign.StatusCode)
	}
	_ = foreign.Body.Close()
	initial := readOriginalSession(true)

	started := do(http.MethodPost, providerPath+"/logout", string(body), originalCookies, startHeaders)
	defer started.Body.Close()
	wantStatus, wantOutcome := http.StatusSeeOther, "redirect"
	if redirectEndpoint == "" {
		wantStatus, wantOutcome = http.StatusOK, "local-only"
	}
	if started.StatusCode != wantStatus || started.Header.Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(started.Header.Get("Content-Type"), "application/json") || started.Header.Get("Access-Control-Allow-Origin") != "" ||
		started.Header.Get("Access-Control-Allow-Credentials") != "" {
		var diagnostic struct {
			Error   string `json:"error"`
			Outcome string `json:"outcome"`
			Local   *struct {
				Committed bool `json:"committed"`
				Reconcile bool `json:"reconciliationRequired"`
			} `json:"localRevocation"`
		}
		_ = json.NewDecoder(io.LimitReader(started.Body, 32<<10)).Decode(&diagnostic)
		t.Fatalf("SP logout did not return its private committed local result: status=%d error=%q outcome=%q local=%+v",
			started.StatusCode, diagnostic.Error, diagnostic.Outcome, diagnostic.Local)
	}
	var result struct {
		Outcome string `json:"outcome"`
		Local   struct {
			SessionID              string `json:"sessionId"`
			Version                uint64 `json:"version"`
			Committed              *bool  `json:"committed"`
			ReconciliationRequired *bool  `json:"reconciliationRequired"`
		} `json:"localRevocation"`
	}
	decoder := json.NewDecoder(io.LimitReader(started.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.Outcome != wantOutcome || result.Local.SessionID != initial.Session.ID ||
		result.Local.Version == 0 || result.Local.Committed == nil || !*result.Local.Committed ||
		result.Local.ReconciliationRequired == nil || *result.Local.ReconciliationRequired {
		t.Fatal("SP logout omitted the original session's committed revocation", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("SP logout returned more than one local-result document", err)
	}
	deletions := started.Cookies()
	if len(started.Header.Values("Set-Cookie")) != 2 || len(deletions) != 2 {
		t.Fatal("SP logout did not delete exactly the two delivered cookies")
	}
	seen := make(map[string]bool, 2)
	for _, deletion := range deletions {
		if seen[deletion.Name] || deletion.Name != sessionCookieName && deletion.Name != "__Host-identity_csrf" ||
			deletion.Value != "" || deletion.Path != "/" || deletion.Domain != "" || deletion.MaxAge >= 0 || !deletion.Secure ||
			deletion.HttpOnly != (deletion.Name == sessionCookieName) || deletion.SameSite != http.SameSiteLaxMode {
			t.Fatal("SP logout changed or duplicated an issued cookie's deletion policy")
		}
		seen[deletion.Name] = true
	}
	readOriginalSession(false)
	location := started.Header.Get("Location")
	if redirectEndpoint == "" {
		if location != "" {
			t.Fatal("local-only SP logout disclosed a provider navigation")
		}
		return
	}
	requestID := originalReferenceSAMLLogoutRequest(t, location, redirectEndpoint, origin+providerPath+"/metadata", spKey)
	response := idp.signedReferenceSPLogoutResponse(t, origin+providerPath+"/slo", requestID, time.Now().UTC())
	responseBody := url.Values{"SAMLResponse": {response}}.Encode()
	responseHeaders := func(request *http.Request) {
		request.Header.Set("Origin", idpOrigin)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	settled := do(http.MethodPost, providerPath+"/slo", responseBody, nil, responseHeaders)
	defer settled.Body.Close()
	if settled.StatusCode != http.StatusSeeOther || settled.Header.Get("Location") != finalRedirect ||
		len(settled.Header.Values("Set-Cookie")) != 0 || settled.Header.Get("Cache-Control") != "no-store" ||
		settled.Header.Get("Access-Control-Allow-Origin") != "" || settled.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("cookie-free signed IdP response did not select only the approved final redirect", settled.StatusCode)
	}
	replay := do(http.MethodPost, providerPath+"/slo", responseBody, nil, responseHeaders)
	defer replay.Body.Close()
	replayBody, err := io.ReadAll(io.LimitReader(replay.Body, 1024))
	if err != nil || replay.StatusCode != http.StatusNoContent || len(replayBody) != 0 || replay.Header.Get("Location") != "" ||
		len(replay.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("settled SP logout replay disclosed another continuation or browser authority", replay.StatusCode, err)
	}
	readOriginalSession(false)
}

func originalReferenceSAMLLogoutRequest(t *testing.T, location, endpoint, entity string, key *rsa.PublicKey) string {
	t.Helper()
	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatal("SP logout returned an invalid redirect", err)
	}
	approved, err := url.Parse(endpoint)
	if err != nil || approved.RawQuery != "" {
		t.Fatal("SP logout fixture requires the exact query-free approved IdP endpoint", err)
	}
	target := *redirect
	target.RawQuery = ""
	if target != *approved {
		t.Fatal("SP logout redirected outside the installed IdP endpoint")
	}
	query := redirect.Query()
	if len(query) != 3 || len(query["SAMLRequest"]) != 1 || len(query["SigAlg"]) != 1 || len(query["Signature"]) != 1 ||
		query.Get("SigAlg") != saml.SignatureAlgorithmRSAPSSSHA256 || query.Get("Signature") == "" {
		t.Fatal("SP logout did not contain exactly one signed Redirect request")
	}
	verifyReferenceSAMLRedirectSignature(t, key, location)
	compressed, err := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
	if err != nil {
		t.Fatal("decode original signed LogoutRequest", err)
	}
	inflated := flate.NewReader(bytes.NewReader(compressed))
	defer inflated.Close()
	var request struct {
		XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
		ID          string   `xml:"ID,attr"`
		Destination string   `xml:"Destination,attr"`
		Version     string   `xml:"Version,attr"`
		Issuers     []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Names       []struct {
			Value           string `xml:",chardata"`
			Format          string `xml:"Format,attr"`
			NameQualifier   string `xml:"NameQualifier,attr"`
			SPNameQualifier string `xml:"SPNameQualifier,attr"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
		Indexes []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
	}
	if err := xml.NewDecoder(io.LimitReader(inflated, 16<<10)).Decode(&request); err != nil || request.ID == "" ||
		request.Destination != endpoint || request.Version != "2.0" || len(request.Issuers) != 1 || request.Issuers[0] != entity ||
		len(request.Names) != 1 || len(request.Indexes) != 1 || request.Indexes[0] != "_reference_assertion" {
		t.Fatal("signed LogoutRequest did not bind the exact SP, IdP and original assertion index", err)
	}
	name := request.Names[0]
	if name.Value != enterpriseProviderSubject || name.Format != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" ||
		name.NameQualifier != "" || name.SPNameQualifier != "" {
		t.Fatal("signed LogoutRequest changed the issued assertion's exact NameID")
	}
	return request.ID
}

func (f referenceSAMLIdPFixture) signedReferenceSPLogoutResponse(t *testing.T, destination, requestID string, now time.Time) string {
	t.Helper()
	escape := func(value string) string {
		var out bytes.Buffer
		if err := xml.EscapeText(&out, []byte(value)); err != nil {
			t.Fatal("escape IdP logout response fixture value", err)
		}
		return out.String()
	}
	const responseID = "_reference_sp_logout_response"
	open := fmt.Sprintf(`<p:LogoutResponse xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" ID="%s" InResponseTo="%s" IssueInstant="%s" Version="2.0">`,
		escape(destination), responseID, escape(requestID), now.UTC().Format(time.RFC3339Nano))
	issuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + escape(referenceSAMLIdPEntity) + `</a:Issuer>`
	content := `<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status></p:LogoutResponse>`
	signature := f.signXML(t, responseID, open+issuer+content)
	return base64.StdEncoding.EncodeToString([]byte(open + issuer + signature + content))
}
