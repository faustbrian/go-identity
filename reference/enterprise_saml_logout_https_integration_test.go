//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/x509"
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

func proveReferenceEnterpriseSAMLIDPLogout(t *testing.T, ctx context.Context, base *http.Client,
	origin, providerPath, idpOrigin, responseEndpoint, assertionID string, browser *http.Client, idp referenceSAMLIdPFixture) {
	t.Helper()
	appURL, err := url.Parse(origin)
	if err != nil || browser.Jar == nil {
		t.Fatal("IdP logout requires the original authenticated browser")
	}
	originalCookies := browser.Jar.Cookies(appURL)
	if len(originalCookies) == 0 {
		t.Fatal("IdP logout requires the original browser cookie")
	}
	client := *base
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	do := func(method, path, body, requestOrigin string, cookies []*http.Cookie) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, origin+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if requestOrigin != "" {
			request.Header.Set("Origin", requestOrigin)
		}
		if method == http.MethodPost {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("Reference HTTPS IdP logout request failed", err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	readOriginalSession := func(want bool) {
		t.Helper()
		response := do(http.MethodGet, "/v1/session/get", "", "", originalCookies)
		defer response.Body.Close()
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&result) != nil || result.Authenticated != want {
			t.Fatal("original browser cookie did not report the expected IdP logout state", response.StatusCode, want)
		}
		if want && (result.Session == nil || result.Principal == nil) {
			t.Fatal("IdP logout prerequisite has no authenticated session and principal")
		}
	}
	readOriginalSession(true)

	metadataPath, logoutPath := providerPath+"/metadata", providerPath+"/slo"
	metadata := do(http.MethodGet, metadataPath, "", "", nil)
	spCertificate := referenceSAMLLogoutMetadataCertificate(t, metadata, origin+metadataPath, origin+logoutPath, idp.certificateDER)
	const requestID = "_reference_idp_logout_request"
	wire := idp.signedReferenceLogoutRequest(t, origin+logoutPath, requestID, assertionID, time.Now().UTC())
	body := url.Values{"SAMLRequest": {wire}}.Encode()
	foreign := do(http.MethodPost, logoutPath, body, "https://unconfigured.example", nil)
	if foreign.StatusCode != http.StatusForbidden || foreign.Header.Get("Location") != "" || len(foreign.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("unconfigured IdP origin did not deny the signed logout request", foreign.StatusCode)
	}
	_ = foreign.Body.Close()
	readOriginalSession(true)

	response := do(http.MethodPost, logoutPath, body, idpOrigin, nil)
	if response.StatusCode != http.StatusOK || response.Header.Get("Location") != "" || len(response.Header.Values("Set-Cookie")) != 0 ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") || response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("signed IdP logout did not return only a private POST response document", response.StatusCode)
	}
	encodedResponse := readReferenceSAMLLogoutForm(t, response.Body, responseEndpoint)
	unselectedSettlement := do(http.MethodPost, logoutPath, url.Values{"SAMLResponse": {encodedResponse}}.Encode(), idpOrigin, nil)
	if unselectedSettlement.StatusCode != http.StatusBadRequest || unselectedSettlement.Header.Get("Location") != "" {
		t.Fatal("request-only Reference accepted an inbound response form", unselectedSettlement.StatusCode)
	}
	_ = unselectedSettlement.Body.Close()
	// LogoutResponse has no audience. The wire verifier's local-entity
	// configuration requires HTTPS; the signed issuer is still the exact SP.
	verifier, err := saml.NewLogoutPOSTProfile(saml.LogoutPOSTConfig{
		SPEntityID: idpOrigin + "/metadata", IdentityProviderEntityID: origin + metadataPath,
		SingleLogoutURL: responseEndpoint, SigningCertificates: [][]byte{spCertificate}, MaximumAge: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal("configure the independent IdP receiver for the published SP certificate", err)
	}
	verified, err := verifier.Validate(ctx, saml.LogoutPOSTInput{SAMLResponse: []string{encodedResponse}, Now: time.Now().UTC()})
	if err != nil {
		t.Fatal("logout response did not authenticate the published SP and exact IdP destination", err)
	}
	acknowledgement, err := verified.Response()
	if err != nil || acknowledgement.InResponseTo != requestID || acknowledgement.Status != (saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess}) {
		t.Fatal("signed logout response did not acknowledge the original installed IdP request", err)
	}
	readOriginalSession(false)

	replay := do(http.MethodPost, logoutPath, body, idpOrigin, nil)
	defer replay.Body.Close()
	replayBody, err := io.ReadAll(io.LimitReader(replay.Body, 1024))
	if err != nil || replay.StatusCode != http.StatusNoContent || len(replayBody) != 0 || replay.Header.Get("Location") != "" || len(replay.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("settled IdP logout replay disclosed another response or browser authority", replay.StatusCode, err)
	}
	readOriginalSession(false)
}

// The login fixture signs a persistent NameID without qualifiers and uses the
// assertion ID as SessionIndex; the logout must preserve that exact subject.
func (f referenceSAMLIdPFixture) signedReferenceLogoutRequest(t *testing.T, destination, id, assertionID string, now time.Time) string {
	t.Helper()
	escape := func(value string) string {
		var out bytes.Buffer
		if err := xml.EscapeText(&out, []byte(value)); err != nil {
			t.Fatal("escape IdP logout fixture value", err)
		}
		return out.String()
	}
	open := fmt.Sprintf(`<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" ID="%s" IssueInstant="%s" NotOnOrAfter="%s" Version="2.0">`,
		escape(destination), escape(id), now.UTC().Format(time.RFC3339Nano), now.Add(2*time.Minute).UTC().Format(time.RFC3339Nano))
	issuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + escape(referenceSAMLIdPEntity) + `</a:Issuer>`
	content := `<a:NameID xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` +
		escape(enterpriseProviderSubject) + `</a:NameID><p:SessionIndex>` + escape(assertionID) + `</p:SessionIndex></p:LogoutRequest>`
	signature := f.signXML(t, id, open+issuer+content)
	return base64.StdEncoding.EncodeToString([]byte(open + issuer + signature + content))
}

func referenceSAMLLogoutMetadataCertificate(t *testing.T, response *http.Response, entity, logout string, idpCertificate []byte) []byte {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/samlmetadata+xml" ||
		response.Header.Get("Cache-Control") != "no-store" || len(response.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("IdP logout metadata was not uncached and cookie-free", response.StatusCode)
	}
	var document struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		Entity  string   `xml:"entityID,attr"`
		SP      []struct {
			Keys []struct {
				Use string `xml:"use,attr"`
				DER string `xml:"KeyInfo>X509Data>X509Certificate"`
			} `xml:"KeyDescriptor"`
			Logout []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
			} `xml:"SingleLogoutService"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	}
	if err := xml.NewDecoder(io.LimitReader(response.Body, 96<<10)).Decode(&document); err != nil || document.Entity != entity || len(document.SP) != 1 {
		t.Fatal("IdP logout metadata has the wrong SP entity", err)
	}
	profile := document.SP[0]
	if len(profile.Keys) != 1 || profile.Keys[0].Use != "signing" || len(profile.Logout) != 1 ||
		profile.Logout[0].Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" || profile.Logout[0].Location != logout {
		t.Fatal("SP metadata did not advertise its exact selected POST logout service and signing key")
	}
	der, err := base64.StdEncoding.DecodeString(profile.Keys[0].DER)
	if err != nil || bytes.Equal(der, idpCertificate) {
		t.Fatal("logout metadata exposed missing or IdP signing material")
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatal("logout metadata exposed an invalid SP certificate", err)
	}
	return der
}

func readReferenceSAMLLogoutForm(t *testing.T, body io.ReadCloser, destination string) string {
	t.Helper()
	defer body.Close()
	decoder := xml.NewDecoder(io.LimitReader(body, 96<<10))
	decoder.Strict, decoder.AutoClose, decoder.Entity = false, xml.HTMLAutoClose, xml.HTMLEntity
	var forms, inputs, buttons int
	var inForm bool
	var response string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("read signed IdP logout response form", err)
		}
		if end, ok := token.(xml.EndElement); ok && end.Name.Local == "form" {
			inForm = false
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		attrs := make(map[string]string, len(element.Attr))
		for _, attr := range element.Attr {
			name := strings.ToLower(attr.Name.Local)
			if strings.HasPrefix(name, "on") || name == "http-equiv" || name == "autofocus" {
				t.Fatal("logout response document included automatic browser behavior")
			}
			attrs[name] = attr.Value
		}
		switch strings.ToLower(element.Name.Local) {
		case "script", "iframe", "object", "embed":
			t.Fatal("logout response document included active content")
		case "form":
			forms++
			inForm = true
			if attrs["method"] != "post" || attrs["action"] != destination {
				t.Fatal("logout response form did not select the exact installed IdP endpoint")
			}
		case "input":
			inputs++
			if !inForm || attrs["type"] != "hidden" || attrs["name"] != "SAMLResponse" || attrs["value"] == "" {
				t.Fatal("logout response document did not contain only its signed response field")
			}
			response = attrs["value"]
		case "button":
			buttons++
			if !inForm || attrs["type"] != "submit" || attrs["name"] != "" || attrs["formaction"] != "" {
				t.Fatal("logout response did not require explicit submission to its selected form")
			}
		}
	}
	if forms != 1 || inputs != 1 || buttons != 1 || response == "" {
		t.Fatal("logout response did not contain exactly one explicit signed POST form")
	}
	return response
}
