//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresEnterpriseOIDCRoleSyncJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, enterpriseOIDC: true, enterpriseOIDCRoles: true})
}

func configureReferenceEnterpriseRoleSync(t *testing.T, c *reference.StoreConfiguration, provider *referenceEnterpriseIssuer) {
	t.Helper()
	roleID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	c.Organization.Core.DynamicRoles = organization.DynamicRoleConfig{Version: 1, MaximumRoles: 10,
		Catalog: []organization.Permission{{ID: "document-read", Action: "document.read", ResourceType: "document"}}}
	c.HTTPOrganization.RoleCreate, c.HTTPOrganization.PermissionCheck = true, true
	profile := c.EnterpriseOIDC.Login.Profiles[0]
	const claim = "document_reader"
	c.EnterpriseOIDC.Completion.Profiles[0].ClaimNames = []string{claim}
	c.EnterpriseOIDC.RoleSync = &ssopg.StaticOIDCRoleMapping{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
		MappingVersion: profile.MappingVersion, Rules: []ssopg.StaticOIDCRoleRule{{ClaimName: claim, RoleID: organization.ID(roleID)}}}
	provider.mux.Lock()
	provider.roleClaim = claim
	provider.mux.Unlock()
}

func enterpriseOrganizationRequest(t *testing.T, ctx context.Context, client *http.Client, origin string, selected enterpriseProvisioned, method, path string, body []byte, key string, result any) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+selected.bearer.Token())
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("enterprise organization request failed", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 {
		t.Fatal("enterprise organization route did not retain authorized response custody", path, response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		t.Fatal("enterprise organization response", err)
	}
}

func createReferenceEnterpriseRole(t *testing.T, ctx context.Context, client *http.Client, origin string, c reference.StoreConfiguration, selected enterpriseProvisioned) uint64 {
	t.Helper()
	return createReferenceEnterpriseDocumentRole(t, ctx, client, origin, c.EnterpriseOIDC.RoleSync.Rules[0].RoleID, selected)
}

func createReferenceEnterpriseDocumentRole(t *testing.T, ctx context.Context, client *http.Client, origin string, roleID organization.ID, selected enterpriseProvisioned) uint64 {
	t.Helper()
	var current organizationhttp.ReadResponse
	enterpriseOrganizationRequest(t, ctx, client, origin, selected, http.MethodGet, "/v1/organization/get?organizationID="+string(selected.organization), nil, "", &current)
	if current.Organization.ID != selected.organization || current.Organization.Version == 0 || current.Membership.UserID != selected.user || current.Membership.Role != organization.RoleOwner {
		t.Fatal("enterprise role setup did not retain the actual organization owner")
	}
	body, err := json.Marshal(map[string]any{"organizationID": selected.organization, "organizationVersion": current.Organization.Version,
		"roleID": roleID, "name": "Enterprise document reader",
		"statements": []map[string]string{{"permissionID": "document-read", "resourceID": "one", "effect": "allow"}}})
	if err != nil {
		t.Fatal(err)
	}
	var created organizationhttp.MutationResponse
	enterpriseOrganizationRequest(t, ctx, client, origin, selected, http.MethodPost, "/v1/organization/role/create", body, "enterprise-document-role", &created)
	if !created.Committed || created.OrganizationID != selected.organization || created.BeforeVersion != current.Organization.Version || created.AfterVersion != current.Organization.Version+1 {
		t.Fatal("enterprise custom role did not commit through native organization administration")
	}
	return created.AfterVersion
}

func proveReferenceEnterpriseRoleSyncJourney(t *testing.T, ctx context.Context, base *http.Client, origin string, provider *referenceEnterpriseIssuer, selected enterpriseProvisioned, roleEpoch uint64) {
	t.Helper()
	permission := func(epoch uint64, want authorization.Outcome) {
		t.Helper()
		query := url.Values{"organizationID": {string(selected.organization)}, "organizationVersion": {strconv.FormatUint(epoch, 10)},
			"action": {"document.read"}, "resourceType": {"document"}, "resourceID": {"one"}}
		var decision organizationhttp.PermissionCheckResponse
		enterpriseOrganizationRequest(t, ctx, base, origin, selected, http.MethodGet, "/v1/organization/permission-check?"+query.Encode(), nil, "", &decision)
		if decision.Decision != want.String() || decision.OrganizationVersion != epoch {
			t.Fatal("public organization permission did not follow the signed enterprise role claim", decision.Decision, epoch)
		}
	}
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
	readSession := func(client *http.Client, authenticated bool) sessionhttp.GetResponse {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/session/get", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil || result.Authenticated != authenticated {
			t.Fatal("enterprise role change did not fence the expected browser session", response.StatusCode, result.Authenticated)
		}
		if authenticated && (result.Principal == nil || result.Session == nil || result.Principal.UserID != selected.user || result.Principal.TenantID != otpTenant) {
			t.Fatal("enterprise role callback did not authenticate the exact linked human")
		}
		return result
	}
	login := func(grant bool, key string, exchanges int32) (*http.Client, []*http.Cookie) {
		t.Helper()
		provider.roleGrant.Store(grant)
		client := newBrowser()
		post := func(path string, body []byte) *http.Response {
			t.Helper()
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", origin)
			if path == "/v1/sso/signin-start" {
				request.Header.Set("Idempotency-Key", key)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			return response
		}
		preauth := post("/v1/session/preauth-issue", []byte(`{"method":"sso-oidc"}`))
		var flow struct{ FlowID string }
		err := json.NewDecoder(preauth.Body).Decode(&flow)
		_ = preauth.Body.Close()
		if preauth.StatusCode != http.StatusOK || err != nil || flow.FlowID == "" {
			t.Fatal("enterprise role browser did not obtain its own native flow", preauth.StatusCode, err)
		}
		body, err := json.Marshal(map[string]string{"flowID": flow.FlowID, "commandID": string(enterpriseCommand(t)), "providerID": string(selected.provider),
			"callback": origin + "/enterprise/complete", "errorCallback": origin + "/enterprise/error"})
		if err != nil {
			t.Fatal(err)
		}
		started := post("/v1/sso/signin-start", body)
		var start struct{ AuthorizationURL, TransactionID string }
		err = json.NewDecoder(started.Body).Decode(&start)
		_ = started.Body.Close()
		if started.StatusCode != http.StatusOK || err != nil || start.AuthorizationURL == "" || start.TransactionID == "" {
			t.Fatal("enterprise role sign-in start did not commit", started.StatusCode, err)
		}
		external := *provider.server.Client()
		external.CheckRedirect = client.CheckRedirect
		authorized, err := external.Get(start.AuthorizationURL)
		if err != nil {
			t.Fatal("controlled enterprise role authorization failed")
		}
		_ = authorized.Body.Close()
		callbackURL := authorized.Header.Get("Location")
		if authorized.StatusCode != http.StatusSeeOther || !strings.HasPrefix(callbackURL, origin+"/sso/oidc/callback?") {
			t.Fatal("enterprise role provider did not return the exact native callback")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		completed, err := client.Do(request)
		if err != nil {
			t.Fatal("enterprise role callback request failed")
		}
		_ = completed.Body.Close()
		if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != origin+"/enterprise/complete" || len(completed.Cookies()) != 2 || provider.posts.Load() != exchanges {
			t.Fatal("signed enterprise role callback did not commit a current browser session", completed.StatusCode, provider.posts.Load())
		}
		return client, completed.Cookies()
	}

	permission(roleEpoch, authorization.Deny)
	granted, preserved := login(true, "enterprise-role-grant", 1)
	first := readSession(granted, true)
	permission(roleEpoch+1, authorization.Allow)
	withdrawn, _ := login(false, "enterprise-role-withdraw", 2)
	current := readSession(withdrawn, true)
	if current.Session.ID == first.Session.ID {
		t.Fatal("role withdrawal reused the historical browser session")
	}
	permission(roleEpoch+2, authorization.Deny)
	appURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	old := newBrowser()
	old.Jar.SetCookies(appURL, preserved)
	readSession(old, false)
	readSession(withdrawn, true)
}
