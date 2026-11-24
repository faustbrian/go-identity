//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresEnterpriseSAMLRoleSyncJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, enterpriseSAML: true, enterpriseSAMLRoles: true,
	})
}

func proveReferenceEnterpriseSAMLRoleSyncJourney(t *testing.T, ctx context.Context, base *http.Client, origin string,
	policy *reference.HTTPEnterpriseSAMLConfiguration, selected enterpriseProvisioned, idp referenceSAMLIdPFixture, roleEpoch uint64) {
	t.Helper()
	providerPath := "/saml2/" + string(selected.provider)
	acsPath, metadataPath := providerPath+"/acs", providerPath+"/metadata"
	appURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	request := func(client *http.Client, method, path string, body io.Reader) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, origin+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", string(policy.IdentityProviderOrigin))
		} else if path == providerPath+"/login" {
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("SAML role browser request failed", err)
		}
		return response
	}
	metadata := request(base, http.MethodGet, metadataPath, nil)
	certificate := referenceSAMLMetadataCertificate(t, metadata, origin+metadataPath, origin+acsPath, "", idp.certificateDER)
	newBrowser := func() *http.Client {
		t.Helper()
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		client := *base
		client.Jar = jar
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &client
	}
	permission := func(epoch uint64, want authorization.Outcome) {
		t.Helper()
		query := url.Values{"organizationID": {string(selected.organization)}, "organizationVersion": {strconv.FormatUint(epoch, 10)},
			"action": {"document.read"}, "resourceType": {"document"}, "resourceID": {"one"}}
		var decision organizationhttp.PermissionCheckResponse
		enterpriseOrganizationRequest(t, ctx, base, origin, selected, http.MethodGet, "/v1/organization/permission-check?"+query.Encode(), nil, "", &decision)
		if decision.Decision != want.String() || decision.OrganizationVersion != epoch {
			t.Fatal("public organization permission did not follow the signed SAML role claim", decision.Decision, decision.OrganizationVersion, epoch)
		}
	}
	readSession := func(client *http.Client, authenticated bool) sessionhttp.GetResponse {
		t.Helper()
		response := request(client, http.MethodGet, "/v1/session/get", nil)
		defer response.Body.Close()
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil || result.Authenticated != authenticated {
			t.Fatal("SAML role change did not fence the expected browser session", response.StatusCode, result.Authenticated)
		}
		if authenticated && (result.Principal == nil || result.Session == nil || result.Principal.UserID != selected.user || result.Principal.TenantID != otpTenant) {
			t.Fatal("SAML role callback did not authenticate the exact linked tenant user")
		}
		return result
	}
	login := func(claim *bool, key string) (*http.Client, []*http.Cookie) {
		t.Helper()
		client := newBrowser()
		start := request(client, http.MethodGet, providerPath+"/login", nil)
		location, cookies := start.Header.Get("Location"), start.Cookies()
		_ = start.Body.Close()
		if start.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location, policy.AuthorizationEndpoint+"?") || len(cookies) != 1 {
			t.Fatal("SAML role browser did not receive its own signed sign-in request", start.StatusCode)
		}
		correlation := cookies[0]
		if correlation.Name != "__Secure-identity_frontchannel" || correlation.Path != acsPath || !correlation.Secure || !correlation.HttpOnly || correlation.SameSite != http.SameSiteNoneMode {
			t.Fatal("SAML role sign-in did not retain exact browser correlation custody")
		}
		requestID, entity, relay := originalReferenceSAMLRequest(t, location, origin+acsPath)
		if entity != origin+metadataPath {
			t.Fatal("SAML role sign-in selected a foreign SP entity")
		}
		verifyReferenceSAMLRedirectSignature(t, certificate, location)
		encoded := idp.signedPOSTResponse(t, referenceSAMLResponseInput{
			RequestID: requestID, Issuer: referenceSAMLIdPEntity, Audience: entity, ACS: origin + acsPath,
			NameID: enterpriseProviderSubject, ResponseID: "_role_response_" + key, AssertionID: "_role_assertion_" + key,
			Now: time.Now().UTC().Truncate(time.Microsecond), RoleClaim: claim,
		})
		form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}.Encode()
		completed := request(client, http.MethodPost, acsPath, strings.NewReader(form))
		_ = completed.Body.Close()
		if claim == nil {
			if completed.StatusCode != http.StatusForbidden || completed.Header.Get("Location") != "" || len(completed.Cookies()) != 0 {
				t.Fatal("missing signed SAML role claim did not deny without browser issuance", completed.StatusCode)
			}
			return client, nil
		}
		if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != policy.SuccessCallback || len(completed.Cookies()) != 3 {
			t.Fatal("signed SAML role callback did not deliver a current browser session", completed.StatusCode)
		}
		preserved := completed.Cookies()
		client.Jar.SetCookies(appURL, []*http.Cookie{correlation})
		replay := request(client, http.MethodPost, acsPath, strings.NewReader(form))
		_ = replay.Body.Close()
		if replay.StatusCode != http.StatusForbidden || replay.Header.Get("Location") != "" || len(replay.Cookies()) != 0 {
			t.Fatal("original SAML role assertion was delivered more than once", replay.StatusCode)
		}
		return client, preserved
	}

	permission(roleEpoch, authorization.Deny)
	grant := true
	granted, preserved := login(&grant, "grant")
	first := readSession(granted, true)
	permission(roleEpoch+1, authorization.Allow)

	missing, _ := login(nil, "missing_before_withdrawal")
	readSession(missing, false)
	if unchanged := readSession(granted, true); unchanged.Session.ID != first.Session.ID {
		t.Fatal("missing SAML role claim replaced the existing authorized browser session")
	}
	permission(roleEpoch+1, authorization.Allow)

	grant = false
	withdrawn, _ := login(&grant, "withdraw")
	current := readSession(withdrawn, true)
	if current.Session.ID == first.Session.ID {
		t.Fatal("SAML role withdrawal reused the historical browser session")
	}
	permission(roleEpoch+2, authorization.Deny)
	old := newBrowser()
	old.Jar.SetCookies(appURL, preserved)
	readSession(old, false)

	missing, _ = login(nil, "missing_after_withdrawal")
	readSession(missing, false)
	permission(roleEpoch+2, authorization.Deny)
	if unchanged := readSession(withdrawn, true); unchanged.Session.ID != current.Session.ID {
		t.Fatal("missing SAML role claim changed the current withdrawn-role browser session")
	}
}
