//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

func TestReferencePostgresSCIMManagedGroupsReadHTTPS(t *testing.T) {
	t.Run("standalone-group-reads", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsRead: true,
		})
	})
	t.Run("with-ordinary-user-list-and-get", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsRead: true,
			scimManagedUsersList: true, scimManagedUsersGet: true,
		})
	})
}

func configureReferenceSCIMManagedGroupsRead(c *reference.StoreConfiguration) {
	n := &reference.HTTPManagedSCIMGroupsReadConfiguration{
		MaximumMembers: scim.DefaultGroupMembers, EnableGet: true, EnableList: true,
	}
	if c.HTTPManagedSCIMUsersList == nil && c.HTTPManagedSCIMUsersGet == nil {
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-groups", [32]byte{0xb4}
		}
	}
	c.HTTPManagedSCIMGroupsRead = n
}

func proveReferenceSCIMManagedGroupsReadTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	var profile *reference.ManagedSCIMConnectionConfiguration
	switch {
	case c.HTTPManagedSCIMUsersList != nil:
		profile = c.HTTPManagedSCIMUsersList.Native
	case c.HTTPManagedSCIMUsersGet != nil:
		profile = c.HTTPManagedSCIMUsersGet.Native
	default:
		profile = c.HTTPManagedSCIMGroupsRead.Native
	}
	if profile == nil {
		t.Fatal("selected managed Group reads have no native owner")
	}
	native := referenceManagedUsersNative(t, c, source, *profile)
	connection, other := referenceManagedGroupReadConnections(t, ctx, features, cookies, csrf, source, *profile, native)
	if c.HTTPManagedSCIMUsersList != nil {
		proveReferenceSCIMUsersListTLS(t, ctx, client, base, native, connection.Bearer.Token(), false, c.HTTPManagedSCIMUsersGet != nil)
	}
	if c.HTTPManagedSCIMUsersGet != nil {
		proveReferenceSCIMUsersGetTLS(t, ctx, client, base, native, connection.Bearer.Token(), source.bearer.Token(), cookies, false)
	}
	child := seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Unselected child", nil)
	seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Selected Alpha", nil)
	selected := seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Selected Zulu", []any{
		map[string]any{"value": child.ID, "type": "Group"},
	})
	before := referenceManagedGroupReadState(t, ctx, source)

	const collection = "/scim/v2/Groups"
	resourcePath := collection + "/" + selected.ID
	call := func(method, path, bearer string, status int, protocol bool, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed Group read TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("managed Group read TLS %s %s: status %d want %d; media %q, cleanup %v/%v", method, path, response.StatusCode, status, response.Header.Get("Content-Type"), readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || bytes.Contains(wire, []byte(connection.Bearer.Token())) || bytes.Contains(wire, []byte(other.Bearer.Token())) || bytes.Contains(wire, []byte(source.bearer.Token())) {
			t.Fatal("Group read changed cache/browser custody or disclosed a credential")
		}
		if status != http.StatusOK {
			if response.Header.Get("ETag") != "" || bytes.Contains(wire, []byte(selected.ID)) || bytes.Contains(wire, []byte("Selected Zulu")) {
				t.Fatal("Group denial disclosed the native representation or version")
			}
			if protocol {
				var denial struct {
					Schemas []string `json:"schemas"`
					Status  string   `json:"status"`
				}
				if json.Unmarshal(wire, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(status) {
					t.Fatal("Group denial lost its exact SCIM schema/status envelope")
				}
			}
		}
		return wire, response.Header.Clone()
	}
	nativeRead := func(operation scim.Operation, resourceID string, query scim.Query) scim.Response {
		t.Helper()
		calls := 0
		response, err := native.ExecuteManagedAdmittedGroupRead(ctx, otpTenant, scim.Request{
			Operation: operation, Credential: connection.Bearer, ResourceID: resourceID, Query: query,
		}, c.HTTPManagedSCIMGroupsRead.MaximumMembers, func(admissionCtx context.Context, client scim.ProtocolClient) *scim.Error {
			calls++
			if admissionCtx.Err() != nil || client.ID != profile.Provisioning.ActorID || client.TenantID != otpTenant {
				t.Fatal("native Group read admission changed configured service-account scope")
			}
			return nil
		})
		if err != nil || response.Status != http.StatusOK || calls != 1 {
			t.Fatal("read exact persisted native Group oracle through issued bearer admission", err)
		}
		return response
	}
	for _, query := range []scim.Query{{}, {Attributes: "displayName"}, {ExcludedAttributes: "members"}} {
		expected := nativeRead(scim.GroupGet, selected.ID, query)
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
		wire, headers := call(http.MethodGet, path, connection.Bearer.Token(), http.StatusOK, true)
		if !bytes.Equal(wire, expected.Body) || headers.Get("ETag") != string(selected.Version) || expected.ETag != selected.Version {
			t.Fatal("TLS Group Get changed exact native projection or strong ETag")
		}
		var resource struct {
			ID, DisplayName string
			Members         []json.RawMessage
			Meta            struct{ Version string }
		}
		if json.Unmarshal(wire, &resource) != nil || resource.ID != selected.ID || resource.DisplayName != "Selected Zulu" || resource.Meta.Version != string(selected.Version) || (len(resource.Members) == 1) != (query == (scim.Query{})) {
			t.Fatal("Group Get omitted resource/version or changed selected member projection")
		}
	}
	count := 1
	query := scim.Query{Filter: `displayName sw "Selected"`, SortBy: "displayName", StartIndex: 2, Count: &count, Attributes: "displayName"}
	expected := nativeRead(scim.GroupList, "", query)
	parameters := url.Values{"filter": {query.Filter}, "sortBy": {query.SortBy}, "startIndex": {"2"}, "count": {"1"}, "attributes": {query.Attributes}}
	wire, headers := call(http.MethodGet, collection+"?"+parameters.Encode(), connection.Bearer.Token(), http.StatusOK, true)
	var page struct {
		TotalResults, StartIndex, ItemsPerPage int
		Resources                              []struct {
			ID, DisplayName string
			Members         []json.RawMessage
			Meta            struct{ Version string }
		}
	}
	if !bytes.Equal(wire, expected.Body) || headers.Get("ETag") != "" || json.Unmarshal(wire, &page) != nil || page.TotalResults != 2 || page.StartIndex != 2 || page.ItemsPerPage != 1 || len(page.Resources) != 1 || page.Resources[0].ID != selected.ID || page.Resources[0].DisplayName != "Selected Zulu" || len(page.Resources[0].Members) != 0 || page.Resources[0].Meta.Version != string(selected.Version) {
		t.Fatal("TLS Group List lost exact bounded native snapshot, filter, sort, page or projection")
	}
	for _, path := range []string{collection, resourcePath} {
		call(http.MethodGet, path, "", http.StatusUnauthorized, true, func(r *http.Request) { r.AddCookie(cookies[0]) })
		call(http.MethodGet, path, "not-an-issued-managed-bearer", http.StatusUnauthorized, true, func(r *http.Request) { r.AddCookie(cookies[0]) })
		call(http.MethodGet, path, source.bearer.Token(), http.StatusUnauthorized, true)
		call(http.MethodGet, path, connection.Bearer.Token(), http.StatusForbidden, true, func(r *http.Request) { r.Host = "localhost" })
		call(http.MethodGet, path, connection.Bearer.Token(), http.StatusUnsupportedMediaType, true, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") })
		for _, header := range []string{"If-Match", "If-None-Match"} {
			call(http.MethodGet, path, connection.Bearer.Token(), http.StatusBadRequest, true, func(r *http.Request) { r.Header.Set(header, string(selected.Version)) })
		}
	}
	call(http.MethodGet, resourcePath, other.Bearer.Token(), http.StatusNotFound, true)
	wire, _ = call(http.MethodGet, collection+"?"+url.Values{"filter": {`id eq "` + selected.ID + `"`}}.Encode(), other.Bearer.Token(), http.StatusOK, true)
	var isolated struct {
		TotalResults, ItemsPerPage int
		Resources                  []json.RawMessage
	}
	if json.Unmarshal(wire, &isolated) != nil || isolated.TotalResults != 0 || isolated.ItemsPerPage != 0 || len(isolated.Resources) != 0 || bytes.Contains(wire, []byte(selected.ID)) {
		t.Fatal("another genuine managed connection read this connection's Groups")
	}
	for _, write := range []struct{ method, path string }{
		{http.MethodPost, collection}, {http.MethodPut, resourcePath}, {http.MethodPatch, resourcePath}, {http.MethodDelete, resourcePath},
	} {
		_, headers := call(write.method, write.path, connection.Bearer.Token(), http.StatusMethodNotAllowed, false)
		if headers.Get("Allow") != http.MethodGet {
			t.Fatal("Group read route advertised an unselected mutation")
		}
	}
	call(http.MethodPost, "/v1/scim/connection-create", connection.Bearer.Token(), http.StatusNotFound, false)
	if referenceManagedGroupReadState(t, ctx, source) != before {
		t.Fatal("Group TLS reads or rejected writes changed native Groups, Users, commands, request custody, audit or outbox")
	}
}

func referenceManagedGroupReadConnections(t *testing.T, ctx context.Context, features reference.FeatureSet, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource, profile reference.ManagedSCIMConnectionConfiguration, native *scimpg.ManagedConnectionService) (scimpg.ConnectionCreateResult, scimpg.ConnectionCreateResult) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	policy := profile.Authorization.(*referenceManagedReadPolicy)
	policy.mu.Lock()
	policy.actor = human.user
	policy.mu.Unlock()
	if _, err := authoritypg.InitializeAuthority(ctx, source.pool.Raw(), authoritypg.AuthorityScope{
		TenantID: otpTenant, PolicyNamespace: profile.Provisioning.AuthorityNamespace, SubjectID: authorization.SubjectID(profile.Provisioning.ActorID),
	}, time.Second); err != nil {
		t.Fatal("initialize genuine managed Group service-account authority", err)
	}
	path, err := scim.ParseMappingPath("userName", nil, profile.Provisioning.Limits)
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := scim.NewMappingSet([]scim.Mapping{{Source: path, Target: profile.Provisioning.UserNameField, Writable: true}})
	if err != nil {
		t.Fatal(err)
	}
	create := func(provider string) scimpg.ConnectionCreateResult {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte(provider))
		if err != nil {
			t.Fatal(err)
		}
		connection, err := native.ConnectionCreate(ctx, scimpg.ConnectionCreateRequest{
			Authentication: human.auth, OrganizationID: source.config.Scope.OrganizationID,
			ProviderID: scim.ProviderID(provider), Mappings: mappings, IdempotencyKey: key,
		})
		if err != nil || connection.Bearer.Token() == "" || connection.Connection.Scope().ProviderConnectionID == "" {
			t.Fatal("issue genuine managed Group connection without enabling management HTTP", err)
		}
		return connection
	}
	return create("reference-managed-group-read"), create("reference-managed-group-other")
}

// The managed public API intentionally selects no Group writes. Seed only its
// existing native storage representation, scoped by the actual ConnectionCreate
// result, so acceptance does not create a new product mutation entry point.
func seedReferenceManagedGroupReadFixture(t *testing.T, ctx context.Context, source referenceDirectorySCIMSource, scope scim.ConnectionScope, name string, members []any) scim.Resource {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	resource := scim.Resource{
		ID: string(id), Version: scim.Version(`"reference-managed-group-` + string(id) + `"`), CreatedAt: at, LastModified: at,
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, Attributes: map[string]any{"displayName": name},
	}
	if members != nil {
		resource.Attributes["members"] = members
	}
	wire, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	if _, err := source.pool.Raw().Exec(ctx, `INSERT INTO scim.groups(tenant_id,organization_id,provider_id,connection_id,resource_id,resource,command_id,effect_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, string(scope.TenantID), string(scope.OrganizationID), string(scope.ProviderID), string(scope.ProviderConnectionID), resource.ID, wire, string(command), digest[:]); err != nil {
		t.Fatal("seed fixture-only Group in the actual issued connection scope", err)
	}
	return resource
}

func referenceManagedGroupReadState(t *testing.T, ctx context.Context, source referenceDirectorySCIMSource) string {
	t.Helper()
	var state string
	if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY resource_id) FROM scim.groups g),
 'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY resource_id) FROM scim.users u),
 'identities',(SELECT count(*) FROM identity.users),
 'commands',(SELECT count(*) FROM identity.commands),
 'request_mappings',(SELECT count(*) FROM identity.request_key_mappings),
 'audits',(SELECT count(*) FROM audit.records),
 'outbox',(SELECT count(*) FROM public.outbox_messages))::text`).Scan(&state); err != nil {
		t.Fatal("snapshot protected native Group read effects", err)
	}
	return state
}
