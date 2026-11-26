//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

func TestReferencePostgresSCIMManagedUsersGetHTTPS(t *testing.T) {
	t.Run("standalone-user-get", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersGet: true,
		})
	})
	t.Run("with-create-list-and-bulk", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimBulk: true, scimManagedCreate: true,
			scimManagedUsersList: true, scimManagedUsersGet: true,
		})
	})
}

func configureReferenceSCIMManagedUsersGet(c *reference.StoreConfiguration) {
	n := &reference.HTTPManagedSCIMUsersGetConfiguration{}
	if c.HTTPManagedSCIMUsersList == nil {
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-users", [32]byte{0xb3}
		}
	}
	c.HTTPManagedSCIMUsersGet = n
}

func proveReferenceSCIMUsersGetRejectsCompetingOwners(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	invalid := func(selected reference.HTTPManagedSCIMUsersGetConfiguration) {
		t.Helper()
		c.HTTPManagedSCIMUsersGet = &selected
		stores, err := reference.ComposeStores(c, deps)
		if err == nil {
			_ = stores.Close(t.Context())
		}
		var input identity.InvalidInputError
		if !errors.As(err, &input) || input.Field != "reference_http_managed_scim_users_get" {
			t.Fatal("competing managed User Get native/quota owner reached construction", err)
		}
	}
	selected := *c.HTTPManagedSCIMUsersGet
	if c.HTTPManagedSCIMUsersList != nil {
		competingNative := selected
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		competingNative.Native = &profile
		invalid(competingNative)
		competingRate := selected
		competingRate.RateNamespace, competingRate.RateKey = "separate-get-budget", [32]byte{1}
		invalid(competingRate)
		return
	}
	missingNative := selected
	missingNative.Native = nil
	invalid(missingNative)
	missingRate := selected
	missingRate.RateNamespace, missingRate.RateKey = "", [32]byte{}
	invalid(missingRate)
}

func proveReferenceSCIMStandaloneUsersGet(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	native, bearer := referenceManagedUsersConnection(t, ctx, c, features, cookies, csrf, source, *c.HTTPManagedSCIMUsersGet.Native)
	proveReferenceSCIMUsersGetTLS(t, ctx, client, base, native, bearer, "", cookies, true)
}

func proveReferenceSCIMUsersGetTLS(t *testing.T, ctx context.Context, client *http.Client, base string, native *scimpg.ManagedConnectionService, bearer, configuredBearer string, cookies []*http.Cookie, standalone bool) {
	t.Helper()
	const name = "reference-managed-get-user"
	credential := authentication.NewBearerCredential(bearer)
	created, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{
		Operation: scim.UserCreate, Credential: credential, IdempotencyKey: "reference-managed-get-user-1",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `"}`),
	})
	var original struct {
		ID string `json:"id"`
	}
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" || created.ETag == "" {
		t.Fatal("persist User using genuinely issued managed bearer", err)
	}
	const collection = "/scim/v2/Users"
	resourcePath := collection + "/" + original.ID
	call := func(method, path, token string, status int, protocol bool, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed User Get TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("managed User Get TLS %s %s: status %d want %d; media %q, cleanup %v/%v", method, path, response.StatusCode, status, response.Header.Get("Content-Type"), readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || bytes.Contains(wire, []byte(bearer)) || configuredBearer != "" && bytes.Contains(wire, []byte(configuredBearer)) {
			t.Fatal("managed User Get changed cache/cookie/Location or credential custody")
		}
		if status != http.StatusOK {
			if response.Header.Get("ETag") != "" || bytes.Contains(wire, []byte(original.ID)) || bytes.Contains(wire, []byte(name)) {
				t.Fatal("denied Get disclosed resource data or version")
			}
			if protocol {
				var denial struct {
					Schemas []string `json:"schemas"`
					Status  string   `json:"status"`
				}
				if json.Unmarshal(wire, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(status) {
					t.Fatal("Get denial is not the exact SCIM status/schema envelope")
				}
			}
		}
		return wire, response.Header.Clone()
	}
	for _, query := range []scim.Query{{}, {Attributes: "userName"}, {ExcludedAttributes: "userName"}} {
		expected, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserGet, Credential: credential, ResourceID: original.ID, Query: query})
		if err != nil || expected.Status != http.StatusOK || expected.ETag != created.ETag {
			t.Fatal("read persisted native User/version oracle", err)
		}
		parameters := url.Values{}
		if query.Attributes != "" {
			parameters.Set("attributes", query.Attributes)
		}
		if query.ExcludedAttributes != "" {
			parameters.Set("excludedAttributes", query.ExcludedAttributes)
		}
		path := resourcePath
		if len(parameters) != 0 {
			path += "?" + parameters.Encode()
		}
		wire, headers := call(http.MethodGet, path, bearer, http.StatusOK, true)
		if !bytes.Equal(wire, expected.Body) || headers.Get("ETag") != string(expected.ETag) {
			t.Fatal("TLS Get changed exact native representation, projection or ETag")
		}
		var resource struct {
			ID       string  `json:"id"`
			UserName *string `json:"userName"`
			Meta     struct {
				Version string `json:"version"`
			} `json:"meta"`
		}
		if json.Unmarshal(wire, &resource) != nil || resource.ID != original.ID || resource.Meta.Version != headers.Get("ETag") || (resource.UserName == nil) != (query.ExcludedAttributes != "") || resource.UserName != nil && *resource.UserName != name {
			t.Fatal("SCIM Get omitted required version or ignored selected projection")
		}
	}
	call(http.MethodGet, resourcePath, "", http.StatusUnauthorized, true, func(r *http.Request) { r.AddCookie(cookies[0]) })
	call(http.MethodGet, resourcePath, "not-an-issued-managed-bearer", http.StatusUnauthorized, true)
	if configuredBearer != "" {
		call(http.MethodGet, resourcePath, configuredBearer, http.StatusUnauthorized, true)
	}
	call(http.MethodGet, resourcePath, bearer, http.StatusForbidden, true, func(r *http.Request) { r.Host = "localhost" })
	call(http.MethodGet, resourcePath, bearer, http.StatusUnsupportedMediaType, true, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") })
	missing, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal("construct valid but absent native resource ID", err)
	}
	call(http.MethodGet, collection+"/"+string(missing), bearer, http.StatusNotFound, true)
	call(http.MethodGet, resourcePath+"?filter=userName", bearer, http.StatusBadRequest, true)
	if standalone {
		for _, absent := range []struct{ method, path string }{
			{http.MethodGet, collection}, {http.MethodPost, "/v1/scim/connection-create"},
			{http.MethodGet, "/v1/scim/connection-get"}, {http.MethodGet, "/v1/scim/connection-list"},
			{http.MethodGet, "/scim/v2/ServiceProviderConfig"}, {http.MethodPost, "/scim/v2/Bulk"},
		} {
			call(absent.method, absent.path, bearer, http.StatusNotFound, false)
		}
	}
}
