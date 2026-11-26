//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

const referenceMixedSCIMBulk = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` +
	`{"method":"POST","path":"/Groups","bulkId":"new-group","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Reference Bulk group","members":[{"type":"User","value":"bulkId:new-user"}]}},` +
	`{"method":"POST","path":"/Users","bulkId":"new-user","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ReferenceBulkUser","displayName":"Reference Bulk user","active":true}}]}`

func TestReferencePostgresSCIMBulkHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, scimBulk: true,
	})
}

func configureReferenceSCIMBulk(t *testing.T, c *reference.StoreConfiguration, deps reference.ReferenceDependencies, origin string) referenceDirectorySCIMSource {
	t.Helper()
	c.Organization.SelectOrganizationID = func(ctx context.Context) (organization.ID, error) {
		return referenceDirectoryOrganization, ctx.Err()
	}
	source := newReferenceDirectorySCIMSource(t, deps.PostgreSQL, deps.EnvelopeKeys.(*keyring.Provider), scim.Scope{
		TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization,
		ProviderID: referenceDirectoryProvider, ConnectionID: referenceDirectoryConnection,
	}, referenceDirectorySCIMPolicy{}, 9, c.OTP.Store.GlobalAuthorityID)
	source.config.BaseURL = origin + "/scim/v2"
	c.SCIMBulk = &reference.SCIMBulkConfiguration{
		Native: source.config, MaximumGroupMembers: 8,
		Request:  scim.BulkPolicy{MaxOperations: 4, MaxPayloadBytes: 32768, MaxOperationBytes: 4096},
		Response: scim.DefaultBulkResponsePolicy(), RateNamespace: "reference-scim-bulk", RateKey: [32]byte{0xe1},
	}
	return source
}

func proveReferenceSCIMBulkHTTPS(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal("SCIM fixture requires the genuine signup session", err)
	}
	owner := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	organizations, err := features.Organizations()
	if err != nil {
		t.Fatal("SCIM fixture requires the selected organization owner", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("reference-scim-bulk-organization"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := organizations.Create(ctx, organization.CreateOperationRequest{
		Authentication: owner.auth, IdempotencyKey: key, Name: "SCIM Bulk test", Slug: "scim-bulk-test", CorrelationID: "reference-scim-setup",
	}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted || created.OrganizationID != source.config.Scope.OrganizationID {
		t.Fatal("SCIM organization must be created by its real owner", err)
	}
	_, err = authoritypg.InitializeAuthority(ctx, f.pool.Raw(), authoritypg.AuthorityScope{
		TenantID: authorization.TenantID(source.config.Scope.TenantID), PolicyNamespace: source.config.AuthorityNamespace,
		SubjectID: authorization.SubjectID(source.config.ActorID),
	}, time.Second)
	if err != nil {
		t.Fatal("initialize the configured SCIM service principal through its authority owner", err)
	}
	for range 2 {
		installed, err := f.stores.InitializeSCIMBulkConnection(ctx)
		if err != nil || installed.Outcome != identity.CommitOutcomeCommitted || installed.Version != 1 {
			t.Fatal("initialize or recover the original selected SCIM connection", err)
		}
	}

	call := func(method, path, body, bearer, requestKey, contentType string, want int, changes ...func(*http.Request)) []byte {
		t.Helper()
		var input io.Reader
		if body != "" {
			input = strings.NewReader(body)
		}
		request, err := http.NewRequestWithContext(ctx, method, base+path, input)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if requestKey != "" {
			request.Header.Set("Idempotency-Key", requestKey)
		}
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("SCIM HTTPS request failed", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != want || readErr != nil || closeErr != nil || len(wire) > 1<<20 {
			t.Fatalf("SCIM HTTPS %s %s: status %d, want %d; response cleanup %v/%v", method, path, response.StatusCode, want, readErr, closeErr)
		}
		if path == "/scim/v2/Bulk" || path == "/scim/v2/ServiceProviderConfig" {
			if response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || bytes.Contains(wire, []byte(source.bearer.Token())) || bytes.Contains(wire, []byte(cookies[0].Value)) {
				t.Fatal("SCIM response changed its protocol media or exposed browser/credential custody")
			}
		}
		return wire
	}
	assertError := func(wire []byte, status int, kind string) {
		t.Helper()
		want, err := json.Marshal(scim.NewError(status, kind))
		if err != nil || !bytes.Equal(bytes.TrimSpace(wire), want) {
			t.Fatalf("SCIM error must be the exact redacted protocol error for %d/%q", status, kind)
		}
	}
	bearer := source.bearer.Token()
	counts := func() [8]int {
		t.Helper()
		var got [8]int
		err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.users),(SELECT count(*) FROM scim.users),(SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands WHERE purpose IN ($1,$2,$3) AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose IN ($1,$2,$3)),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose IN ($1,$2,$3)),
 (SELECT count(*) FROM scim.bulk_requests),(SELECT count(*) FROM scim.bulk_children)`, string(scim.Bulk), string(scim.UserCreate), string(scim.GroupCreate)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6], &got[7])
		if err != nil {
			t.Fatal("read actual SCIM state and atomic command effects", err)
		}
		return got
	}
	before := counts()
	if before[0] < 1 || before != [8]int{before[0]} {
		t.Fatal("SCIM acceptance must begin with a real signup and no SCIM mutations", before)
	}

	assertError(call(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "", "", "", 401, func(r *http.Request) { r.AddCookie(cookies[0]) }), 401, "")
	assertError(call(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "unrecognized-test-service-credential", "", "", 401), 401, "")
	assertError(call(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", bearer, "", "", 403, func(r *http.Request) { r.Host = "localhost" }), 403, "")

	selectedRequest := c.SCIMBulk.Request
	c.SCIMBulk.Request.MaxOperations++
	c.SCIMBulk.Request.MaxPayloadBytes++
	c.SCIMBulk.Native.BaseURL = "https://caller-mutation.example/scim/v2"
	discovery := call(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", bearer, "", "", 200)
	var document struct {
		Schemas []string `json:"schemas"`
		Bulk    struct {
			Supported      bool `json:"supported"`
			MaxOperations  int  `json:"maxOperations"`
			MaxPayloadSize int  `json:"maxPayloadSize"`
		} `json:"bulk"`
	}
	if json.Unmarshal(discovery, &document) != nil || !slices.Equal(document.Schemas, []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}) || !document.Bulk.Supported || document.Bulk.MaxOperations != selectedRequest.MaxOperations || document.Bulk.MaxPayloadSize != selectedRequest.MaxPayloadBytes {
		t.Fatal("authorized discovery did not retain the executor's effective startup limits")
	}
	assertError(call(http.MethodPost, "/scim/v2/Bulk", referenceMixedSCIMBulk, bearer, "", "application/json", 415), 415, "")
	assertError(call(http.MethodPost, "/scim/v2/Bulk", `{"schemas":`, bearer, "", "application/scim+json", 400), 400, "invalidSyntax")
	tooMany := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[` + strings.Repeat(`{"method":"DELETE","path":"/Users/missing"},`, selectedRequest.MaxOperations) + `{"method":"DELETE","path":"/Users/missing"}]}`
	assertError(call(http.MethodPost, "/scim/v2/Bulk", tooMany, bearer, "", "application/scim+json", 413), 413, "")
	if got := counts(); got != before {
		t.Fatal("discovery or rejected protocol inputs created SCIM state", got, before)
	}

	first := call(http.MethodPost, "/scim/v2/Bulk", referenceMixedSCIMBulk, bearer, "reference-mixed-bulk", "application/scim+json", 200)
	var result struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Method, BulkID, Status, Location, Version string
		} `json:"Operations"`
	}
	if json.Unmarshal(first, &result) != nil || !slices.Equal(result.Schemas, []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"}) || len(result.Operations) != 2 {
		t.Fatal("selected HTTPS Bulk did not return the complete SCIM BulkResponse")
	}
	var resourceIDs [2]string
	for ordinal, want := range []struct{ bulkID, resourceType string }{{"new-group", "Groups"}, {"new-user", "Users"}} {
		got := result.Operations[ordinal]
		prefix := source.config.BaseURL + "/" + want.resourceType + "/"
		if got.Method != http.MethodPost || got.BulkID != want.bulkID || got.Status != "201" || got.Version == "" || !strings.HasPrefix(got.Location, prefix) {
			t.Fatal("mixed Bulk lost declaration order, original version or configured resource location", ordinal)
		}
		resourceIDs[ordinal] = strings.TrimPrefix(got.Location, prefix)
		if _, err := identity.ParseSubjectID(resourceIDs[ordinal]); err != nil {
			t.Fatal("Bulk location did not identify a real allocated resource", ordinal)
		}
	}
	if resourceIDs[0] == resourceIDs[1] {
		t.Fatal("mixed Group and User shared a resource allocation")
	}
	wantCounts := [8]int{before[0] + 1, 1, 1, 3, 3, 3, 1, 2}
	if got := counts(); got != wantCounts {
		t.Fatal("mixed Bulk did not commit exactly one parent and both atomic children", got, wantCounts)
	}
	for range 2 {
		replayed := call(http.MethodPost, "/scim/v2/Bulk", referenceMixedSCIMBulk, bearer, "reference-mixed-bulk", "application/scim+json", 200)
		if !bytes.Equal(first, replayed) {
			t.Fatal("exact HTTPS retry did not retain the original terminal bytes")
		}
	}
	changed := strings.Replace(referenceMixedSCIMBulk, "Reference Bulk group", "Changed Bulk group", 1)
	assertError(call(http.MethodPost, "/scim/v2/Bulk", changed, bearer, "reference-mixed-bulk", "application/scim+json", 409), 409, "")
	if got := counts(); got != wantCounts {
		t.Fatal("exact retry or same-key conflict duplicated durable state", got, wantCounts)
	}

	var groupWire, userWire []byte
	var kernelUsers int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT resource FROM scim.groups WHERE resource_id=$1),
 (SELECT resource FROM scim.users WHERE resource_id=$2),
 (SELECT count(*) FROM identity.users WHERE tenant_id=$3 AND user_id=$2)`, resourceIDs[0], resourceIDs[1], string(source.config.Scope.TenantID)).Scan(&groupWire, &userWire, &kernelUsers); err != nil {
		t.Fatal("read original mixed projections and authoritative User", err)
	}
	var group, user scim.Resource
	if json.Unmarshal(groupWire, &group) != nil || json.Unmarshal(userWire, &user) != nil || kernelUsers != 1 || group.ID != resourceIDs[0] || user.ID != resourceIDs[1] || string(group.Version) != result.Operations[0].Version || string(user.Version) != result.Operations[1].Version || user.Attributes["userName"] != "ReferenceBulkUser" || group.Attributes["displayName"] != "Reference Bulk group" {
		t.Fatal("stored Group/User identity or projection differs from the original Bulk result")
	}
	members, ok := group.Attributes["members"].([]any)
	if !ok || len(members) != 1 {
		t.Fatal("forward-reference Group did not retain exactly one User member")
	}
	member, ok := members[0].(map[string]any)
	if !ok || member["type"] != "User" || member["value"] != resourceIDs[1] {
		t.Fatal("forward Group reference did not resolve to its original committed User")
	}
	for _, path := range []string{"Users", "Groups", "Schemas", "ResourceTypes"} {
		call(http.MethodGet, "/scim/v2/"+path, "", bearer, "", "", 404)
	}
	call(http.MethodPost, "/scim/v2/Users", `{"userName":"unselected"}`, bearer, "", "application/scim+json", 404)
}
