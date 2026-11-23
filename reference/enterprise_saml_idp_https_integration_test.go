//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresEnterpriseSAMLIDPJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, enterpriseSAML: true, enterpriseSAMLIDP: true})
}

func proveReferenceEnterpriseSAMLIDPJourney(t *testing.T, ctx context.Context, base *http.Client, origin string, features reference.FeatureSet,
	selection *reference.HTTPEnterpriseSAMLConfiguration, selected enterpriseProvisioned, idp referenceSAMLIdPFixture) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *base
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	providerPath := "/saml2/" + string(selected.provider)
	path := providerPath + "/idp-init"
	do := func(client *http.Client, method, route, body, requestOrigin, contentType, csrf string) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, origin+route, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if requestOrigin != "" {
			request.Header.Set("Origin", requestOrigin)
		}
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("Reference HTTPS request failed", err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	metadata := do(&client, http.MethodGet, providerPath+"/metadata", "", "", "", "")
	checkReferenceSAMLIDPMetadata(t, metadata, origin+providerPath+"/metadata", origin+providerPath+"/acs", origin+path)
	readSession := func(b *http.Client, want bool) sessionhttp.GetResponse {
		t.Helper()
		response := do(b, http.MethodGet, "/v1/session/get", "", "", "", "")
		defer response.Body.Close()
		var out sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&out) != nil || out.Authenticated != want {
			t.Fatal("unexpected session availability", response.StatusCode, want)
		}
		if want && (out.Session == nil || out.Principal == nil || out.Principal.UserID != selected.user || out.Principal.TenantID != otpTenant) {
			t.Fatal("IdP confirmation did not authenticate the linked tenant user")
		}
		return out
	}
	assertion := idp.signedUnsolicitedPOSTResponse(t, referenceSAMLResponseInput{
		Issuer: referenceSAMLIdPEntity, Audience: origin + providerPath + "/metadata", ACS: origin + path,
		NameID: enterpriseProviderSubject, ResponseID: "_reference_browser_idp_response", AssertionID: "_reference_browser_idp_assertion", Now: time.Now().UTC(),
	})
	const encodedForm = "application/x-www-form-urlencoded"
	assertionBody := url.Values{"SAMLResponse": {assertion}}.Encode()
	arrival := do(&client, http.MethodPost, path, assertionBody, string(selection.IdentityProviderOrigin), encodedForm, "")
	arrivalCookies := arrival.Cookies()
	if arrival.StatusCode != http.StatusOK || arrival.Header.Get("Location") != "" || len(arrivalCookies) != 1 ||
		!arrivalCookies[0].HttpOnly || !arrivalCookies[0].Secure || arrivalCookies[0].Path != path {
		t.Fatal("signed unsolicited arrival did not stop at browser confirmation", arrival.StatusCode)
	}
	confirmation := readReferenceSAMLConfirmation(t, arrival.Body, path)
	readSession(&client, false)
	foreign := do(base, http.MethodPost, path, confirmation.Encode(), origin, encodedForm, "")
	if foreign.StatusCode != http.StatusForbidden || len(foreign.Cookies()) != 0 {
		t.Fatal("confirmation without the original browser cookie was not denied", foreign.StatusCode)
	}
	confirmed := do(&client, http.MethodPost, path, confirmation.Encode(), origin, encodedForm, "")
	if confirmed.StatusCode != http.StatusSeeOther || confirmed.Header.Get("Location") != selection.SuccessCallback || len(confirmed.Cookies()) != 3 {
		t.Fatal("same-origin confirmation did not return a normal session", confirmed.StatusCode)
	}
	var sessionCookie *http.Cookie
	var csrf string
	for _, cookie := range confirmed.Cookies() {
		switch {
		case cookie.Name == arrivalCookies[0].Name:
			if cookie.MaxAge >= 0 || cookie.Path != path {
				t.Fatal("confirmation did not remove exact pending custody")
			}
		case cookie.Name == "__Host-identity_csrf":
			csrf = cookie.Value
		case cookie.HttpOnly && cookie.Secure && cookie.Path == "/" && cookie.Value != "":
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || csrf == "" {
		t.Fatal("confirmation did not supply separate session and CSRF cookies")
	}
	public := readSession(&client, true)
	checkReferenceEnterpriseOrganization(t, ctx, features, sessionCookie.Value, public.Session.ID, "sso-saml", selected)
	replayJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	replayClient := client
	replayClient.Jar = replayJar
	replayed := do(&replayClient, http.MethodPost, path, assertionBody, string(selection.IdentityProviderOrigin), encodedForm, "")
	if replayed.StatusCode != http.StatusOK || replayed.Header.Get("Location") != "" || len(replayed.Cookies()) != 1 || replayed.Cookies()[0].Path != path {
		t.Fatal("replayed assertion did not stop at pending admission", replayed.StatusCode)
	}
	replayForm := readReferenceSAMLConfirmation(t, replayed.Body, path)
	denied := do(&replayClient, http.MethodPost, path, replayForm.Encode(), origin, encodedForm, "")
	// The native transaction deliberately masks database constraint failures at
	// the Work boundary. Its unavailable response must never issue a session.
	if denied.StatusCode != http.StatusServiceUnavailable || denied.Header.Get("Location") != "" || len(denied.Cookies()) != 0 {
		t.Fatal("a new pending browser pair bypassed settled assertion replay protection", denied.StatusCode)
	}
	readSession(&replayClient, false)
	logout := do(&client, http.MethodPost, "/v1/session/signout", `{}`, origin, "application/json", csrf)
	if logout.StatusCode != http.StatusOK || len(logout.Cookies()) != 2 {
		t.Fatal("normal session logout failed", logout.StatusCode)
	}
	appURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(appURL, []*http.Cookie{sessionCookie})
	readSession(&client, false)
}

func checkReferenceSAMLIDPMetadata(t *testing.T, response *http.Response, entity, sp, idp string) {
	t.Helper()
	defer response.Body.Close()
	var metadata struct {
		Entity string `xml:"entityID,attr"`
		ACS    []struct {
			Location string `xml:"Location,attr"`
			Index    int    `xml:"index,attr"`
			Default  bool   `xml:"isDefault,attr"`
		} `xml:"SPSSODescriptor>AssertionConsumerService"`
	}
	if response.StatusCode != http.StatusOK || xml.NewDecoder(io.LimitReader(response.Body, 96<<10)).Decode(&metadata) != nil ||
		metadata.Entity != entity || len(metadata.ACS) != 2 {
		t.Fatal("metadata did not advertise both selected ACS entries", response.StatusCode)
	}
	first, second := metadata.ACS[0], metadata.ACS[1]
	if first.Location != sp || first.Index != 0 || !first.Default || second.Location != idp || second.Index != 1 || second.Default {
		t.Fatal("metadata changed the default SP endpoint or advertised the wrong IdP endpoint")
	}
}

func readReferenceSAMLConfirmation(t *testing.T, body io.ReadCloser, path string) url.Values {
	t.Helper()
	defer body.Close()
	decoder := xml.NewDecoder(io.LimitReader(body, 16<<10))
	decoder.Strict, decoder.AutoClose, decoder.Entity = false, xml.HTMLAutoClose, xml.HTMLEntity
	result := make(url.Values)
	var form, sameOrigin bool
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("cannot read the confirmation document", err)
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		attrs := make(map[string]string, len(element.Attr))
		for _, attr := range element.Attr {
			attrs[attr.Name.Local] = attr.Value
		}
		switch element.Name.Local {
		case "meta":
			if attrs["name"] == "referrer" && attrs["content"] == "same-origin" {
				sameOrigin = true
			}
		case "form":
			form = attrs["method"] == "post" && attrs["action"] == path
		case "input":
			if attrs["type"] == "hidden" {
				result.Add(attrs["name"], attrs["value"])
			}
		}
	}
	if !form || !sameOrigin || len(result) != 2 || len(result["pending"]) != 1 || len(result["confirmation"]) != 1 ||
		result.Get("pending") == "" || result.Get("confirmation") == "" {
		t.Fatal("arrival did not render the exact same-origin confirmation form")
	}
	return result
}
