//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

func TestReferencePostgresSCIMManagedUsersCreateHTTPS(t *testing.T) {
	t.Run("standalone-user-create", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersCreate: true,
		})
	})
	t.Run("with-admin-create-get-list-and-bulk", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimBulk: true, scimManagedCreate: true,
			scimManagedUsersList: true, scimManagedUsersGet: true, scimManagedUsersCreate: true,
		})
	})
}

func configureReferenceSCIMManagedUsersCreate(c *reference.StoreConfiguration, adminCreate bool) {
	n := &reference.HTTPManagedSCIMUsersCreateConfiguration{}
	if c.HTTPManagedSCIMUsersList == nil && c.HTTPManagedSCIMUsersGet == nil {
		if !adminCreate {
			profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
			n.Native = &profile
			c.HTTPManagedSCIMCreate = nil
		}
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-users", [32]byte{0xb3}
		}
	}
	c.HTTPManagedSCIMUsersCreate = n
}

func proveReferenceSCIMUsersCreateRejectsCompetingOwners(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	invalid := func(selected reference.HTTPManagedSCIMUsersCreateConfiguration) {
		t.Helper()
		c.HTTPManagedSCIMUsersCreate = &selected
		stores, err := reference.ComposeStores(c, deps)
		if err == nil {
			_ = stores.Close(t.Context())
		}
		var input identity.InvalidInputError
		if !errors.As(err, &input) || input.Field != "reference_http_managed_scim_users_create" {
			t.Fatal("competing managed User Create native/quota owner reached construction", err)
		}
	}
	selected := *c.HTTPManagedSCIMUsersCreate
	if c.HTTPManagedSCIMUsersList != nil || c.HTTPManagedSCIMUsersGet != nil {
		var profile *reference.ManagedSCIMConnectionConfiguration
		if c.HTTPManagedSCIMCreate != nil {
			native := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
			profile = &native
		} else if c.HTTPManagedSCIMUsersList != nil {
			profile = c.HTTPManagedSCIMUsersList.Native
		} else {
			profile = c.HTTPManagedSCIMUsersGet.Native
		}
		competingNative := selected
		competingNative.Native = profile
		invalid(competingNative)
		competingRate := selected
		competingRate.RateNamespace, competingRate.RateKey = "separate-create-budget", [32]byte{1}
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

func proveReferenceSCIMStandaloneUsersCreate(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	native, bearer := referenceManagedUsersConnection(t, ctx, c, features, cookies, csrf, source, *c.HTTPManagedSCIMUsersCreate.Native)
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	proveReferenceSCIMUsersCreateTLS(t, ctx, client, base, native, bearer, "", human.auth.Bearer.Token(), cookies, source, true, false)
}

func proveReferenceSCIMUsersCreateTLS(t *testing.T, ctx context.Context, client *http.Client, base string, native *scimpg.ManagedConnectionService, bearer, configuredBearer, sessionBearer string, cookies []*http.Cookie, source referenceDirectorySCIMSource, standalone, getSelected bool) {
	t.Helper()
	const collection = "/scim/v2/Users"
	const name = "reference-managed-create-user"
	body := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `"}`)
	call := func(method, path, token string, input []byte, status int, protocol bool, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if len(input) != 0 {
			request.Header.Set("Content-Type", "application/scim+json")
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed User Create TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("managed User Create TLS %s %s: status %d want %d; media %q, cleanup %v/%v", method, path, response.StatusCode, status, response.Header.Get("Content-Type"), readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("managed User Create changed cache or browser session custody")
		}
		for _, secret := range []string{bearer, configuredBearer, sessionBearer, cookies[0].Value} {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("managed User Create disclosed credential custody")
			}
		}
		if (status != http.StatusCreated && response.Header.Get("Location") != "") || (status >= 400 && response.Header.Get("ETag") != "") {
			t.Fatal("denied User Create disclosed resource location or version")
		}
		if protocol && status >= 400 {
			var denial struct {
				Schemas []string `json:"schemas"`
				Status  string   `json:"status"`
			}
			if json.Unmarshal(wire, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(status) {
				t.Fatal("Create denial is not the exact SCIM status/schema envelope")
			}
		}
		return wire, response.Header.Clone()
	}
	counts := func() [5]int {
		t.Helper()
		var got [5]int
		err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.users), (SELECT count(*) FROM scim.users),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1)`, string(scim.UserCreate)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4])
		if err != nil {
			t.Fatal("read actual User Create state and atomic command effects", err)
		}
		return got
	}
	before := counts()
	deny := func(token string, status int, kind string, changes ...func(*http.Request)) {
		t.Helper()
		wire, _ := call(http.MethodPost, collection, token, body, status, true, changes...)
		want, err := json.Marshal(scim.NewError(status, kind))
		if err != nil || !bytes.Equal(bytes.TrimSpace(wire), want) {
			t.Fatal("Create denial changed stable redacted protocol error", status, kind)
		}
		if got := counts(); got != before {
			t.Fatal("denied User Create changed native state or command/audit/outbox effects", got, before)
		}
	}
	deny("", http.StatusUnauthorized, "", func(r *http.Request) { r.AddCookie(cookies[0]) })
	deny("", http.StatusUnauthorized, "", func(r *http.Request) { r.Header.Set("X-API-Key", "not-a-managed-bearer") })
	deny(sessionBearer, http.StatusUnauthorized, "")
	deny("not-an-issued-managed-bearer", http.StatusUnauthorized, "")
	if configuredBearer != "" {
		deny(configuredBearer, http.StatusUnauthorized, "")
	}
	deny(bearer, http.StatusForbidden, "", func(r *http.Request) { r.Host = "localhost" })
	deny(bearer, http.StatusUnsupportedMediaType, "", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") })
	deny(bearer, http.StatusBadRequest, "invalidValue", func(r *http.Request) { r.Header.Set("Idempotency-Key", "caller-must-not-allocate-command") })
	oversized := []byte(strings.Repeat(" ", source.config.Limits.BodyBytes+1))
	wire, _ := call(http.MethodPost, collection, bearer, oversized, http.StatusRequestEntityTooLarge, true, func(r *http.Request) {
		r.ContentLength = -1
		r.TransferEncoding = []string{"chunked"}
	})
	const wantOverflow = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"413"}`
	if !bytes.Equal(bytes.TrimSpace(wire), []byte(wantOverflow)) || counts() != before {
		t.Fatal("oversized chunked Create changed the router hard-cap denial or native effects")
	}

	wire, headers := call(http.MethodPost, collection, bearer, body, http.StatusCreated, true)
	var resource struct {
		Schemas  []string `json:"schemas"`
		ID       string   `json:"id"`
		UserName string   `json:"userName"`
		Meta     struct {
			ResourceType string `json:"resourceType"`
			Version      string `json:"version"`
			Location     string `json:"location"`
		} `json:"meta"`
	}
	if json.Unmarshal(wire, &resource) != nil || len(resource.Schemas) != 1 || resource.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" || resource.UserName != name || resource.Meta.ResourceType != "User" || resource.Meta.Version == "" || resource.Meta.Version != headers.Get("ETag") {
		t.Fatal("HTTPS Create omitted canonical User representation or authoritative version")
	}
	if _, err := identity.ParseSubjectID(resource.ID); err != nil {
		t.Fatal("HTTPS Create did not allocate a canonical native resource ID", err)
	}
	wantLocation := source.config.BaseURL + "/Users/" + resource.ID
	if headers.Get("Location") != wantLocation || resource.Meta.Location != wantLocation {
		t.Fatal("HTTPS Create changed canonical Location or resource metadata")
	}
	credential := authentication.NewBearerCredential(bearer)
	expected, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserGet, Credential: credential, ResourceID: resource.ID})
	if err != nil || expected.Status != http.StatusOK || !bytes.Equal(wire, expected.Body) || headers.Get("ETag") != string(expected.ETag) {
		t.Fatal("HTTPS Create differs from exact persisted native User/version", err)
	}
	wantCounts := before
	for i := range wantCounts {
		wantCounts[i]++
	}
	if got := counts(); got != wantCounts {
		t.Fatal("HTTPS Create did not commit exactly one User and atomic command/audit/outbox effects", got, wantCounts)
	}
	if getSelected {
		read, readHeaders := call(http.MethodGet, collection+"/"+resource.ID, bearer, nil, http.StatusOK, true)
		if !bytes.Equal(read, expected.Body) || readHeaders.Get("ETag") != string(expected.ETag) {
			t.Fatal("selected HTTP Get did not observe exact HTTPS-created User")
		}
	}
	if standalone {
		_, otherMethod := call(http.MethodGet, collection, bearer, nil, http.StatusMethodNotAllowed, false)
		if otherMethod.Get("Allow") != http.MethodPost {
			t.Fatal("standalone collection allows a method other than POST")
		}
		for _, absent := range []struct{ method, path string }{
			{http.MethodGet, collection + "/" + resource.ID},
			{http.MethodPost, "/v1/scim/connection-create"}, {http.MethodGet, "/v1/scim/connection-get"},
			{http.MethodGet, "/v1/scim/connection-list"}, {http.MethodGet, "/scim/v2/ServiceProviderConfig"},
			{http.MethodPost, "/scim/v2/Bulk"},
		} {
			call(absent.method, absent.path, bearer, nil, http.StatusNotFound, false)
		}
	}
}
