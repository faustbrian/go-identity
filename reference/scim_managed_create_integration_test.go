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
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

func TestReferencePostgresSCIMManagedCreateHTTPS(t *testing.T) {
	t.Run("standalone-create", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedCreate: true,
		})
	})
	t.Run("with-org-http-read-and-bulk", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimBulk: true, scimManagedCreate: true,
		})
	})
}

func configureReferenceSCIMManagedCreate(t *testing.T, c *reference.StoreConfiguration, source referenceDirectorySCIMSource) {
	t.Helper()
	provisioning := source.config
	provisioning.Scope = scim.Scope{}
	provisioning.Credential = scimpg.ConfiguredCredential{}
	provisioning.ConnectionVersion = 0
	provisioning.CredentialExpiresAt = time.Time{}
	provisioning.AuthorityNamespace = c.Session.Native.Execution.Profile.PolicyNamespace
	var policy authorization.Service = &referenceManagedReadPolicy{organization: source.config.Scope.OrganizationID}
	if c.HTTPManagedSCIMRead != nil {
		policy = c.HTTPManagedSCIMRead.Authorization
	}
	c.HTTPManagedSCIMCreate = &reference.HTTPManagedSCIMCreateConfiguration{
		Authorization: policy, PolicyVersion: 9, MaximumDuration: 3 * time.Second,
		CursorKey: [32]byte{0xa3}, Provisioning: provisioning, CredentialKey: [32]byte{0xa4}, CredentialLifetime: time.Hour,
	}
	if c.HTTPOrganization == nil {
		c.HTTPManagedSCIMCreate.AdminRate = &reference.ManagedSCIMCreateAdminConfiguration{
			Namespace: "reference-managed-create", Key: [32]byte{0xa5},
			Denied: func(ctx context.Context, _ organizationhttp.AdminRateEvent) error { return ctx.Err() },
		}
	}
}

func proveReferenceSCIMManagedCreateHTTPS(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource, document []byte) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	policy := c.HTTPManagedSCIMCreate.Authorization.(*referenceManagedReadPolicy)
	policy.mu.Lock()
	policy.actor = human.user
	policy.mu.Unlock()
	provisioning := c.HTTPManagedSCIMCreate.Provisioning
	if _, err := authoritypg.InitializeAuthority(ctx, f.pool.Raw(), authoritypg.AuthorityScope{
		TenantID: otpTenant, PolicyNamespace: provisioning.AuthorityNamespace, SubjectID: authorization.SubjectID(provisioning.ActorID),
	}, time.Second); err != nil {
		t.Fatal("initialize actual provisioning principal authority", err)
	}
	type mapping struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		Writable bool   `json:"writable"`
	}
	type createRequest struct {
		OrganizationID string    `json:"organizationID"`
		ProviderID     string    `json:"providerID"`
		Mappings       []mapping `json:"mappings"`
	}
	type createResponse struct {
		Connection scimhttp.ManagedConnectionView `json:"connection"`
		Bearer     string                         `json:"bearer"`
	}
	input := createRequest{OrganizationID: string(source.config.Scope.OrganizationID), ProviderID: "reference-managed-create", Mappings: []mapping{{Source: "userName", Target: provisioning.UserNameField, Writable: true}}}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, key string, body []byte, bearer bool, want int) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		if bearer {
			request.Header.Set("Authorization", "Bearer "+human.auth.Bearer.Token())
		} else {
			request.AddCookie(cookies[0])
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != want || readErr != nil || closeErr != nil || len(wire) > 1<<20 {
			t.Fatalf("SCIM Create HTTPS: got %d want %d; cleanup %v/%v", response.StatusCode, want, readErr, closeErr)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
			t.Fatal("SCIM Create response cannot be cached or mint a browser session")
		}
		if bytes.Contains(wire, []byte(human.auth.Bearer.Token())) {
			t.Fatal("administrator session exposed in response")
		}
		return wire
	}
	const path = "/v1/scim/connection-create"
	const key = "reference-managed-create-1"
	call(http.MethodPost, path, key, encoded, false, 401)
	var first createResponse
	if err := json.Unmarshal(call(http.MethodPost, path, key, encoded, true, 200), &first); err != nil || first.Bearer == "" || first.Connection.ConnectionID == "" || first.Connection.OrganizationID != source.config.Scope.OrganizationID || first.Connection.TenantID != otpTenant || first.Connection.Version != 1 {
		t.Fatal("first committed Create must reveal the new bearer and exact native connection", err)
	}
	if bytes.Contains(document, []byte(first.Bearer)) {
		t.Fatal("OpenAPI disclosed new bearer")
	}
	var replay createResponse
	if err := json.Unmarshal(call(http.MethodPost, path, key, encoded, true, 200), &replay); err != nil || replay.Bearer != "" || replay.Connection.ConnectionID != first.Connection.ConnectionID {
		t.Fatal("exact retry did not recover metadata without a replacement bearer", err)
	}
	changed := []byte(strings.Replace(string(encoded), input.ProviderID, "different-provider", 1))
	call(http.MethodPost, path, key, changed, true, 409)
	if c.HTTPManagedSCIMRead != nil {
		var read scimhttp.ManagedConnectionView
		get := "/v1/scim/connection-get?connectionID=" + string(first.Connection.ConnectionID)
		if err := json.Unmarshal(call(http.MethodGet, get, "", nil, true, 200), &read); err != nil || read.ConnectionID != first.Connection.ConnectionID || read.ProviderID != first.Connection.ProviderID {
			t.Fatal("managed read did not observe the committed record", err)
		}
	}
	if c.HTTPManagedSCIMUsersList != nil || c.HTTPManagedSCIMUsersGet != nil || c.HTTPManagedSCIMUsersCreate != nil {
		n := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		native := referenceManagedUsersNative(t, c, source, n)
		if c.HTTPManagedSCIMUsersCreate != nil {
			var configuredBearer string
			if c.SCIMBulk != nil {
				configuredBearer = source.bearer.Token()
			}
			proveReferenceSCIMUsersCreateTLS(t, ctx, client, base, native, first.Bearer, configuredBearer, human.auth.Bearer.Token(), cookies, source, false, c.HTTPManagedSCIMUsersGet != nil)
		}
		if c.HTTPManagedSCIMUsersList != nil {
			proveReferenceSCIMUsersListTLS(t, ctx, client, base, native, first.Bearer, false, c.HTTPManagedSCIMUsersGet != nil)
		}
		if c.HTTPManagedSCIMUsersGet != nil {
			var configuredBearer string
			if c.SCIMBulk != nil {
				configuredBearer = source.bearer.Token()
			}
			proveReferenceSCIMUsersGetTLS(t, ctx, client, base, native, first.Bearer, configuredBearer, cookies, false)
		}
	}
	policy.denyWrite.Store(true)
	defer policy.denyWrite.Store(false)
	call(http.MethodPost, path, key, encoded, true, 403)
}
