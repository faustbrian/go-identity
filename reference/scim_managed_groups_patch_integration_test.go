//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedGroupsPatchHTTPS(t *testing.T) {
	t.Run("standalone-group-patch", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsPatch: true,
		})
	})
	t.Run("with-group-reads-and-replace", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsPatch: true,
			scimManagedGroupsRead: true, scimManagedGroupsReplace: true,
		})
	})
}

func configureReferenceSCIMManagedGroupsPatch(c *reference.StoreConfiguration) {
	n := &reference.HTTPManagedSCIMGroupsPatchConfiguration{MaximumMembers: scim.DefaultGroupMembers}
	userRoutesSelected := c.HTTPManagedSCIMUsersList != nil || c.HTTPManagedSCIMUsersGet != nil ||
		c.HTTPManagedSCIMUsersCreate != nil || c.HTTPManagedSCIMUsersDelete != nil ||
		c.HTTPManagedSCIMUsersPatch != nil || c.HTTPManagedSCIMUsersReplace != nil
	switch {
	case c.HTTPManagedSCIMGroupsRead != nil:
		n.MaximumMembers = c.HTTPManagedSCIMGroupsRead.MaximumMembers
	case c.HTTPManagedSCIMGroupsCreate != nil:
		n.MaximumMembers = c.HTTPManagedSCIMGroupsCreate.MaximumMembers
	case c.HTTPManagedSCIMGroupsReplace != nil:
		n.MaximumMembers = c.HTTPManagedSCIMGroupsReplace.MaximumMembers
	case !userRoutesSelected:
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-group-patch", [32]byte{0xb7}
		}
	}
	c.HTTPManagedSCIMGroupsPatch = n
}

func proveReferenceSCIMManagedGroupsPatchTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	var profile *reference.ManagedSCIMConnectionConfiguration
	switch {
	case c.HTTPManagedSCIMCreate != nil:
		n := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		profile = &n
	case c.HTTPManagedSCIMUsersList != nil:
		profile = c.HTTPManagedSCIMUsersList.Native
	case c.HTTPManagedSCIMUsersGet != nil:
		profile = c.HTTPManagedSCIMUsersGet.Native
	case c.HTTPManagedSCIMUsersCreate != nil:
		profile = c.HTTPManagedSCIMUsersCreate.Native
	case c.HTTPManagedSCIMUsersDelete != nil:
		profile = c.HTTPManagedSCIMUsersDelete.Native
	case c.HTTPManagedSCIMUsersPatch != nil:
		profile = c.HTTPManagedSCIMUsersPatch.Native
	case c.HTTPManagedSCIMUsersReplace != nil:
		profile = c.HTTPManagedSCIMUsersReplace.Native
	case c.HTTPManagedSCIMGroupsRead != nil:
		profile = c.HTTPManagedSCIMGroupsRead.Native
	case c.HTTPManagedSCIMGroupsCreate != nil:
		profile = c.HTTPManagedSCIMGroupsCreate.Native
	case c.HTTPManagedSCIMGroupsReplace != nil:
		profile = c.HTTPManagedSCIMGroupsReplace.Native
	default:
		profile = c.HTTPManagedSCIMGroupsPatch.Native
	}
	if profile == nil {
		t.Fatal("selected Group Patch has no first native owner")
	}
	native := referenceManagedUsersNative(t, c, source, *profile)
	connection, other := referenceManagedGroupReadConnections(t, ctx, features, cookies, csrf, source, *profile, native)
	child := seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Patch child", nil)
	foreign := seedReferenceManagedGroupReadFixture(t, ctx, source, other.Connection.Scope(), "Foreign Patch child", nil)
	admit := func(context.Context, scim.ProtocolClient) *scim.Error { return nil }
	created, err := native.ExecuteManagedAdmittedGroupCreate(ctx, otpTenant, scim.Request{
		Operation: scim.GroupCreate, Credential: connection.Bearer, IdempotencyKey: "reference-managed-group-patch-seed",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original parent","externalId":"retained-correlation"}`),
	}, c.HTTPManagedSCIMGroupsPatch.MaximumMembers, admit)
	var original struct{ ID string }
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" || created.ETag == "" {
		t.Fatal("seed native Group without selecting public Create", err)
	}
	const collection = "/scim/v2/Groups"
	path := collection + "/" + original.ID
	patch := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Patched parent"},{"op":"add","path":"members","value":[{"value":"` + child.ID + `","type":"Group"}]}]}`)
	call := func(method, target, bearer, version string, body []byte, status int, protocol bool, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if version != "" {
			request.Header.Set("If-Match", version)
		}
		if len(body) != 0 {
			request.Header.Set("Content-Type", "application/scim+json")
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed Group Patch TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || response.TLS == nil || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("Group Patch TLS %s %s: status %d want %d; cleanup %v/%v", method, target, response.StatusCode, status, readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("Group Patch changed browser or cache custody")
		}
		for _, secret := range []string{connection.Bearer.Token(), other.Bearer.Token(), source.bearer.Token(), cookies[0].Value} {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("Group Patch disclosed credential custody")
			}
		}
		if status >= 400 && (response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || bytes.Contains(wire, []byte(original.ID))) {
			t.Fatal("Group Patch denial disclosed the native target or version")
		}
		return wire, response.Header.Clone()
	}
	before := referenceManagedGroupReadState(t, ctx, source)
	for _, bearer := range []string{"", "not-an-issued-managed-bearer", source.bearer.Token()} {
		call(http.MethodPatch, path, bearer, string(created.ETag), patch, http.StatusUnauthorized, true)
		if referenceManagedGroupReadState(t, ctx, source) != before {
			t.Fatal("invalid bearer changed native Group Patch custody or effects")
		}
	}
	call(http.MethodPatch, path, connection.Bearer.Token(), string(created.ETag), patch, http.StatusBadRequest, true, func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden-patch-key") })
	if referenceManagedGroupReadState(t, ctx, source) != before {
		t.Fatal("caller Patch key changed native command custody or effects")
	}
	counts := func() [4]int {
		t.Helper()
		var got [4]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.request_key_mappings m JOIN identity.commands c USING(command_id) WHERE c.purpose=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed')`, string(scim.GroupPatch)).Scan(&got[0], &got[1], &got[2], &got[3]); err != nil {
			t.Fatal("read Group Patch original custody and effects", err)
		}
		return got
	}
	denyMutation := func(bearer, version string, body []byte, status int) {
		t.Helper()
		var beforeGroups, afterGroups string
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(g) ORDER BY resource_id)::text FROM scim.groups g`).Scan(&beforeGroups); err != nil {
			t.Fatal(err)
		}
		beforeCounts := counts()
		call(http.MethodPatch, path, bearer, version, body, status, true)
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(g) ORDER BY resource_id)::text FROM scim.groups g`).Scan(&afterGroups); err != nil {
			t.Fatal(err)
		}
		afterCounts := counts()
		if beforeGroups != afterGroups || beforeCounts[0] != afterCounts[0] || beforeCounts[2] != afterCounts[2] || beforeCounts[3] != afterCounts[3] {
			t.Fatal("denied Patch changed owned/foreign Groups or committed effects")
		}
	}
	foreignPatch := bytes.Replace(patch, []byte(child.ID), []byte(foreign.ID), 1)
	denyMutation(connection.Bearer.Token(), string(created.ETag), foreignPatch, http.StatusBadRequest)
	denyMutation(other.Bearer.Token(), string(created.ETag), patch, http.StatusNotFound)
	beforeCounts := counts()
	first, headers := call(http.MethodPatch, path, connection.Bearer.Token(), string(created.ETag), patch, http.StatusOK, true)
	var resource struct {
		ID, DisplayName, ExternalID string
		Members                     []struct{ Value, Type string }
		Meta                        struct{ ResourceType, Version, Location string }
	}
	etag, location := headers.Get("ETag"), source.config.BaseURL+"/Groups/"+original.ID
	if json.Unmarshal(first, &resource) != nil || resource.ID != original.ID || resource.DisplayName != "Patched parent" || resource.ExternalID != "retained-correlation" || len(resource.Members) != 1 || resource.Members[0].Value != child.ID || resource.Members[0].Type != "Group" || resource.Meta.ResourceType != "Group" || resource.Meta.Version != etag || resource.Meta.Location != location || headers.Get("Location") != location || etag == string(created.ETag) || len(etag) < 3 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatal("Group Patch lost exact native resource, retained fields, typed member or changed strong metadata")
	}
	wantCounts := beforeCounts
	for i := range wantCounts {
		wantCounts[i]++
	}
	if counts() != wantCounts {
		t.Fatal("Group Patch did not commit one original mapping, command, audit and outbox effect")
	}
	assertPersisted := func(want []byte, version string, generation int) {
		t.Helper()
		read, err := native.ExecuteManagedAdmittedGroupRead(ctx, otpTenant, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: original.ID}, c.HTTPManagedSCIMGroupsPatch.MaximumMembers, admit)
		var actualGeneration int
		if err != nil || read.Status != http.StatusOK || !bytes.Equal(read.Body, want) || string(read.ETag) != version || read.Location != location {
			t.Fatal("TLS Patch differs from exact persisted native Group", err)
		}
		if err := source.pool.Raw().QueryRow(ctx, `SELECT generation FROM scim.groups WHERE tenant_id=$1 AND resource_id=$2`, string(otpTenant), original.ID).Scan(&actualGeneration); err != nil || actualGeneration != generation {
			t.Fatal("Patch/replay lost atomic native generation", err)
		}
	}
	assertPersisted(first, etag, 2)
	after := referenceManagedGroupReadState(t, ctx, source)
	var equivalent bytes.Buffer
	if err := json.Indent(&equivalent, patch, "", "  "); err != nil {
		t.Fatal(err)
	}
	replayed, replayHeaders := call(http.MethodPatch, path, connection.Bearer.Token(), string(created.ETag), equivalent.Bytes(), http.StatusOK, true)
	if !bytes.Equal(first, replayed) || replayHeaders.Get("ETag") != etag || replayHeaders.Get("Location") != location || referenceManagedGroupReadState(t, ctx, source) != after || counts() != wantCounts {
		t.Fatal("equivalent headerless Patch replay lost original response or repeated durable effects")
	}
	denyMutation(connection.Bearer.Token(), `"stale-group-patch-version"`, patch, http.StatusPreconditionFailed)
	denyMutation(connection.Bearer.Token(), string(created.ETag), bytes.Replace(patch, []byte("Patched parent"), []byte("Changed original"), 1), http.StatusPreconditionFailed)
	assertPersisted(first, etag, 2)
	if c.HTTPManagedSCIMGroupsRead != nil {
		read, readHeaders := call(http.MethodGet, path, connection.Bearer.Token(), "", nil, http.StatusOK, true)
		if !bytes.Equal(read, first) || readHeaders.Get("ETag") != etag || readHeaders.Get("Location") != "" {
			t.Fatal("co-selected Group Get lost exact patched state")
		}
		query := url.Values{"filter": {`id eq "` + original.ID + `"`}, "count": {"1"}}
		listed, _ := call(http.MethodGet, collection+"?"+query.Encode(), connection.Bearer.Token(), "", nil, http.StatusOK, true)
		var page struct {
			TotalResults int
			Resources    []json.RawMessage
		}
		if json.Unmarshal(listed, &page) != nil || page.TotalResults != 1 || len(page.Resources) != 1 || !bytes.Equal(page.Resources[0], first) {
			t.Fatal("co-selected Group List lost exact patched state")
		}
	}
	if c.HTTPManagedSCIMGroupsReplace != nil {
		replacement := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Co-selected replacement"}`)
		replaced, replaceHeaders := call(http.MethodPut, path, connection.Bearer.Token(), etag, replacement, http.StatusOK, true)
		assertPersisted(replaced, replaceHeaders.Get("ETag"), 3)
	} else {
		_, rejected := call(http.MethodPut, path, connection.Bearer.Token(), etag, first, http.StatusMethodNotAllowed, false)
		if rejected.Get("Allow") != http.MethodPatch {
			t.Fatal("standalone Patch selected another resource mutation")
		}
	}
}
