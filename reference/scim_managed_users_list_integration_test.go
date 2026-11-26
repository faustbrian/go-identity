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
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

func TestReferencePostgresSCIMManagedUsersListHTTPS(t *testing.T) {
	t.Run("standalone-user-list", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersList: true,
		})
	})
	t.Run("with-create-and-bulk", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimBulk: true, scimManagedCreate: true, scimManagedUsersList: true,
		})
	})
}

func configureReferenceSCIMManagedUsersList(c *reference.StoreConfiguration, create bool) {
	n := &reference.HTTPManagedSCIMUsersListConfiguration{}
	if !create {
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
	}
	if c.SCIMBulk == nil {
		n.RateNamespace, n.RateKey = "reference-scim-users", [32]byte{0xb3}
	}
	c.HTTPManagedSCIMUsersList = n
}

func proveReferenceSCIMUsersListRejectsCompetingOwners(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	invalid := func(selected reference.HTTPManagedSCIMUsersListConfiguration) {
		t.Helper()
		c.HTTPManagedSCIMUsersList = &selected
		stores, err := reference.ComposeStores(c, deps)
		if err == nil {
			_ = stores.Close(t.Context())
		}
		var input identity.InvalidInputError
		if !errors.As(err, &input) || input.Field != "reference_http_managed_scim_users_list" {
			t.Fatal("invalid SCIM owner selection reached construction", err)
		}
	}
	selected := *c.HTTPManagedSCIMUsersList
	if c.SCIMBulk != nil {
		customRate := selected
		customRate.RateNamespace, customRate.RateKey = "alternate-protocol-quota", [32]byte{1}
		invalid(customRate)
	}
	if c.HTTPManagedSCIMCreate != nil {
		separateNative := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		selected.Native = &separateNative
	} else {
		selected.Native = nil
	}
	invalid(selected)
}

func referenceManagedSCIMNativeConfiguration(c *reference.HTTPManagedSCIMCreateConfiguration) reference.ManagedSCIMConnectionConfiguration {
	return reference.ManagedSCIMConnectionConfiguration{
		Authorization: c.Authorization, PolicyVersion: c.PolicyVersion, MaximumDuration: c.MaximumDuration,
		CursorKey: c.CursorKey, Provisioning: c.Provisioning, CredentialKey: c.CredentialKey, CredentialLifetime: c.CredentialLifetime,
	}
}

func referenceManagedUsersNative(t *testing.T, c reference.StoreConfiguration, source referenceDirectorySCIMSource, n reference.ManagedSCIMConnectionConfiguration) *scimpg.ManagedConnectionService {
	t.Helper()
	execution := c.Session.Native.Execution
	validation := c.Session.Native.Validation
	validation.Clock = execution.Clock
	profile := sessionpg.IdentifierAdmissionConfig(execution.Profile)
	selected := sessionpg.SingleFactorSessionAdmissionConfig{Verified: &profile}
	if c.OTP.Signin != nil {
		selected.OTP = &c.OTP.Signin.Profile
	}
	sessions, err := sessionpg.NewSingleFactorSessionService(source.pool, sessionpg.SingleFactorSessionServiceConfig{
		Repository: execution.Repository, Admission: selected, Validation: validation,
	})
	if err != nil {
		t.Fatal(err)
	}
	native, err := scimpg.NewManagedConnectionService(source.pool, scimpg.ManagedConnectionServiceConfig{
		Sessions: sessions, Authorization: n.Authorization, PolicyVersion: n.PolicyVersion, MaximumDuration: n.MaximumDuration,
		CursorKey: n.CursorKey, Limits: n.Provisioning.Limits,
		Writes: &scimpg.ManagedConnectionWriteConfig{SessionStorage: execution.Repository,
			Provisioning: n.Provisioning, Keyring: source.keys, CredentialKey: n.CredentialKey, CredentialLifetime: n.CredentialLifetime},
	})
	if err != nil {
		t.Fatal("construct actual managed SCIM owner", err)
	}
	return native
}

func proveReferenceSCIMStandaloneUsersList(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	n := *c.HTTPManagedSCIMUsersList.Native
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	policy := n.Authorization.(*referenceManagedReadPolicy)
	policy.mu.Lock()
	policy.actor = human.user
	policy.mu.Unlock()
	if _, err := authoritypg.InitializeAuthority(ctx, source.pool.Raw(), authoritypg.AuthorityScope{
		TenantID: otpTenant, PolicyNamespace: n.Provisioning.AuthorityNamespace, SubjectID: authorization.SubjectID(n.Provisioning.ActorID),
	}, time.Second); err != nil {
		t.Fatal("initialize original provisioning authority", err)
	}
	path, err := scim.ParseMappingPath("userName", nil, n.Provisioning.Limits)
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := scim.NewMappingSet([]scim.Mapping{{Source: path, Target: n.Provisioning.UserNameField, Writable: true}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("reference-standalone-managed-scim"))
	if err != nil {
		t.Fatal(err)
	}
	native := referenceManagedUsersNative(t, c, source, n)
	connection, err := native.ConnectionCreate(ctx, scimpg.ConnectionCreateRequest{Authentication: human.auth,
		OrganizationID: source.config.Scope.OrganizationID, ProviderID: "reference-managed-list", Mappings: mappings, IdempotencyKey: key})
	if err != nil || connection.Bearer.Token() == "" {
		t.Fatal("issue managed bearer using the native owner without enabling Create HTTP", err)
	}
	proveReferenceSCIMUsersListTLS(t, ctx, client, base, native, connection.Bearer.Token(), true)
}

func proveReferenceSCIMUsersListTLS(t *testing.T, ctx context.Context, client *http.Client, base string, native *scimpg.ManagedConnectionService, bearer string, standalone bool) {
	t.Helper()
	const name = "reference-managed-list-user"
	created, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserCreate,
		Credential: authentication.NewBearerCredential(bearer), IdempotencyKey: "reference-managed-list-user-1",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `"}`)})
	var original struct {
		ID string `json:"id"`
	}
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" {
		t.Fatal("provision actual source-owned User via native issued bearer", err)
	}
	call := func(method, path, credential, encoding string, status int, scimResponse bool, host ...string) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if credential != "" {
			request.Header.Set("Authorization", "Bearer "+credential)
		}
		if encoding != "" {
			request.Header.Set("Content-Encoding", encoding)
		}
		if len(host) == 1 {
			request.Host = host[0]
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || readErr != nil || closeErr != nil || len(wire) > 1<<20 ||
			(response.Header.Get("Content-Type") == "application/scim+json") != scimResponse {
			t.Fatalf("managed SCIM TLS: got %d and %q, want %d (SCIM media %v); read/close %v/%v", response.StatusCode,
				response.Header.Get("Content-Type"), status, scimResponse, readErr, closeErr)
		}
		if bytes.Contains(wire, []byte(bearer)) || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" ||
			(status != http.StatusOK && bytes.Contains(wire, []byte(original.ID))) {
			t.Fatal("SCIM response disclosed a bearer, denied resource or minted session custody")
		}
		return wire
	}
	const collection = "/scim/v2/Users"
	query := url.Values{"filter": {`userName eq "` + name + `"`}, "count": {"1"}, "startIndex": {"1"}, "attributes": {"userName"}}
	var page struct {
		TotalResults int `json:"totalResults"`
		StartIndex   int `json:"startIndex"`
		ItemsPerPage int `json:"itemsPerPage"`
		Resources    []struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
		}
	}
	if err := json.Unmarshal(call(http.MethodGet, collection+"?"+query.Encode(), bearer, "", http.StatusOK, true), &page); err != nil ||
		page.TotalResults != 1 || page.ItemsPerPage != 1 || page.StartIndex != 1 || len(page.Resources) != 1 ||
		page.Resources[0].ID != original.ID || page.Resources[0].UserName != name {
		t.Fatal("TLS List did not return exact filtered native resource", err)
	}
	call(http.MethodGet, collection, "", "", http.StatusUnauthorized, true)
	call(http.MethodGet, collection, "not-an-issued-bearer", "", http.StatusUnauthorized, true)
	call(http.MethodGet, collection, bearer, "", http.StatusForbidden, true, "localhost")
	call(http.MethodGet, collection, bearer, "gzip", http.StatusUnsupportedMediaType, true)
	call(http.MethodGet, collection+"/"+original.ID, bearer, "", http.StatusNotFound, false)
	if standalone {
		call(http.MethodPost, "/v1/scim/connection-create", "", "", http.StatusNotFound, false)
		call(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "", http.StatusNotFound, false)
	}
}
