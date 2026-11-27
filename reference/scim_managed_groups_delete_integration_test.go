//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedGroupsDeleteHTTPS(t *testing.T) {
	t.Run("standalone-group-delete", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsDelete: true,
		})
	})
	t.Run("with-group-get-and-list", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsDelete: true,
			scimManagedGroupsRead: true,
		})
	})
}

func configureReferenceSCIMManagedGroupsDelete(c *reference.StoreConfiguration) {
	n := &reference.HTTPManagedSCIMGroupsDeleteConfiguration{MaximumMembers: scim.DefaultGroupMembers}
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
	case c.HTTPManagedSCIMGroupsPatch != nil:
		n.MaximumMembers = c.HTTPManagedSCIMGroupsPatch.MaximumMembers
	case !userRoutesSelected:
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-group-delete", [32]byte{0xb8}
		}
	}
	c.HTTPManagedSCIMGroupsDelete = n
}

func proveReferenceSCIMManagedGroupsDeleteTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
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
	case c.HTTPManagedSCIMGroupsPatch != nil:
		profile = c.HTTPManagedSCIMGroupsPatch.Native
	default:
		profile = c.HTTPManagedSCIMGroupsDelete.Native
	}
	if profile == nil {
		t.Fatal("selected Group Delete has no first native owner")
	}
	native := referenceManagedUsersNative(t, c, source, *profile)
	connection, other := referenceManagedGroupReadConnections(t, ctx, features, cookies, csrf, source, *profile, native)
	admit := func(context.Context, scim.ProtocolClient) *scim.Error { return nil }
	user, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{
		Operation: scim.UserCreate, Credential: connection.Bearer, IdempotencyKey: "reference-group-delete-user",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"reference-group-delete-member"}`),
	})
	var member struct{ ID string }
	if err != nil || user.Status != http.StatusCreated || json.Unmarshal(user.Body, &member) != nil || member.ID == "" {
		t.Fatal("seed actual linked managed User", err)
	}
	seedGroup := func(key, body string) (scim.Response, string) {
		t.Helper()
		response, err := native.ExecuteManagedAdmittedGroupCreate(ctx, otpTenant, scim.Request{
			Operation: scim.GroupCreate, Credential: connection.Bearer, IdempotencyKey: key,
			ContentType: "application/scim+json", Body: []byte(body),
		}, c.HTTPManagedSCIMGroupsDelete.MaximumMembers, admit)
		var resource struct{ ID string }
		if err != nil || response.Status != http.StatusCreated || json.Unmarshal(response.Body, &resource) != nil || resource.ID == "" || response.ETag == "" {
			t.Fatal("seed native Group without selecting public Create", err)
		}
		return response, resource.ID
	}
	child, childID := seedGroup("reference-group-delete-child", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Nested Group remains"}`)
	created, id := seedGroup("reference-group-delete-parent", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Delete parent only","members":[{"value":"`+member.ID+`","type":"User"},{"value":"`+childID+`","type":"Group"}]}`)
	const collection = "/scim/v2/Groups"
	path := collection + "/" + id
	deleteAttempts := 0
	call := func(method, target, bearer, version, alias string, status int, protocol bool) ([]byte, http.Header) {
		t.Helper()
		if method == http.MethodDelete {
			deleteAttempts++
		}
		request, err := http.NewRequestWithContext(ctx, method, base+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if version != "" {
			request.Header.Set("If-Match", version)
		}
		if alias != "" {
			request.Header.Set("Idempotency-Key", alias)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed Group Delete TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || response.TLS == nil || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("Group Delete TLS %s after %d DELETE attempts (alias present=%v): status %d want %d; media %q, cleanup %v/%v", method, deleteAttempts, alias != "", response.StatusCode, status, response.Header.Get("Content-Type"), readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || (method == http.MethodDelete && response.Header.Get("ETag") != "") {
			t.Fatal("Group Delete changed cache, representation or browser custody")
		}
		for _, secret := range []string{connection.Bearer.Token(), other.Bearer.Token(), source.bearer.Token(), cookies[0].Value} {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("Group Delete disclosed credential custody")
			}
		}
		if status == http.StatusNoContent && (len(wire) != 0 || response.Header.Get("Content-Type") != "") {
			t.Fatal("Group Delete/replay is not exact empty 204")
		}
		if protocol && status >= 400 {
			var denial struct {
				Schemas []string
				Status  string
			}
			if json.Unmarshal(wire, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(status) || bytes.Contains(wire, []byte(id)) || response.Header.Get("ETag") != "" {
				t.Fatal("Group Delete denial lost redaction or exact SCIM status/schema")
			}
		}
		return wire, response.Header.Clone()
	}
	relatedState := func() string {
		t.Helper()
		var state string
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'projection',(SELECT to_jsonb(s) FROM scim.users s WHERE s.tenant_id=$1 AND s.resource_id=$2),
 'identity',(SELECT to_jsonb(u) FROM identity.users u JOIN scim.users s ON s.tenant_id=u.tenant_id AND s.user_id=u.user_id WHERE s.tenant_id=$1 AND s.resource_id=$2),
 'attributes',(SELECT jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text) FROM identity.user_attributes a JOIN scim.users s ON s.tenant_id=a.tenant_id AND s.user_id=a.user_id WHERE s.tenant_id=$1 AND s.resource_id=$2),
 'nested',(SELECT to_jsonb(g) FROM scim.groups g WHERE g.tenant_id=$1 AND g.resource_id=$3))::text`, string(otpTenant), member.ID, childID).Scan(&state); err != nil {
			t.Fatal("snapshot linked User, identity fields and nested Group", err)
		}
		return state
	}
	counts := func() [3]int {
		t.Helper()
		var got [3]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed')`, string(scim.GroupDelete)).Scan(&got[0], &got[1], &got[2]); err != nil {
			t.Fatal("read committed Group Delete effects", err)
		}
		return got
	}
	beforeRelated := relatedState()
	before := referenceManagedGroupReadState(t, ctx, source)
	call(http.MethodDelete, path, "", string(created.ETag), "", http.StatusUnauthorized, true)
	if referenceManagedGroupReadState(t, ctx, source) != before {
		t.Fatal("unissued Group Delete changed native custody or effects")
	}
	for _, denial := range []struct {
		bearer, version string
		status          int
	}{
		{connection.Bearer.Token(), `"stale-group-delete-version"`, http.StatusPreconditionFailed},
		{other.Bearer.Token(), string(created.ETag), http.StatusNotFound},
	} {
		beforeCounts := counts()
		call(http.MethodDelete, path, denial.bearer, denial.version, "", denial.status, true)
		read, err := native.ExecuteManagedAdmittedGroupRead(ctx, otpTenant, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: id}, c.HTTPManagedSCIMGroupsDelete.MaximumMembers, admit)
		if err != nil || read.Status != http.StatusOK || !bytes.Equal(read.Body, created.Body) || read.ETag != created.ETag || relatedState() != beforeRelated || counts() != beforeCounts {
			t.Fatal("stale or foreign Delete changed target, linked members or committed effects", err)
		}
	}
	beforeCounts := counts()
	call(http.MethodDelete, path, connection.Bearer.Token(), string(created.ETag), "", http.StatusNoContent, false)
	wantCounts := beforeCounts
	for i := range wantCounts {
		wantCounts[i]++
	}
	if counts() != wantCounts {
		t.Fatal("Group Delete did not commit one command, audit and outbox effect")
	}
	after := referenceManagedGroupReadState(t, ctx, source)
	call(http.MethodDelete, path, connection.Bearer.Token(), string(created.ETag), "", http.StatusNoContent, false)
	if referenceManagedGroupReadState(t, ctx, source) != after {
		t.Fatal("headerless Delete replay repeated native custody or effects")
	}
	const alias = "reference-group-delete-original-alias"
	call(http.MethodDelete, path, connection.Bearer.Token(), string(created.ETag), alias, http.StatusNoContent, false)
	afterAlias := referenceManagedGroupReadState(t, ctx, source)
	for _, key := range []string{"", alias} {
		call(http.MethodDelete, path, connection.Bearer.Token(), string(created.ETag), key, http.StatusNoContent, false)
		if referenceManagedGroupReadState(t, ctx, source) != afterAlias || counts() != wantCounts {
			t.Fatal("optional alias and headerless replay did not share one original deletion")
		}
	}
	call(http.MethodDelete, collection+"/"+childID, connection.Bearer.Token(), string(child.ETag), alias, http.StatusConflict, true)
	if referenceManagedGroupReadState(t, ctx, source) != afterAlias || relatedState() != beforeRelated || counts() != wantCounts {
		t.Fatal("reused Delete alias retargeted the original or changed linked resources")
	}
	var generation int
	var tombstone, empty bool
	if err := source.pool.Raw().QueryRow(ctx, `SELECT generation,deleted_at IS NOT NULL,resource=convert_to('null','UTF8') FROM scim.groups WHERE tenant_id=$1 AND resource_id=$2`, string(otpTenant), id).Scan(&generation, &tombstone, &empty); err != nil || generation != 2 || !tombstone || !empty {
		t.Fatal("Group Delete/replay lost its exact generation-two native tombstone", err)
	}
	readUser, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserGet, Credential: connection.Bearer, ResourceID: member.ID})
	if err != nil || readUser.Status != http.StatusOK || readUser.ETag != user.ETag || !bytes.Equal(readUser.Body, user.Body) {
		t.Fatal("Group Delete changed linked User read behavior", err)
	}
	readChild, err := native.ExecuteManagedAdmittedGroupRead(ctx, otpTenant, scim.Request{Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: childID}, c.HTTPManagedSCIMGroupsDelete.MaximumMembers, admit)
	if err != nil || readChild.Status != http.StatusOK || readChild.ETag != child.ETag || !bytes.Equal(readChild.Body, child.Body) {
		t.Fatal("Group Delete changed linked nested Group read behavior", err)
	}
	if c.HTTPManagedSCIMGroupsRead != nil {
		call(http.MethodGet, path, connection.Bearer.Token(), "", "", http.StatusNotFound, true)
		read, headers := call(http.MethodGet, collection+"/"+childID, connection.Bearer.Token(), "", "", http.StatusOK, true)
		if !bytes.Equal(read, child.Body) || headers.Get("ETag") != string(child.ETag) {
			t.Fatal("co-selected Group Get lost the surviving nested member")
		}
		query := url.Values{"filter": {`id eq "` + id + `"`}}
		listed, _ := call(http.MethodGet, collection+"?"+query.Encode(), connection.Bearer.Token(), "", "", http.StatusOK, true)
		var page struct {
			TotalResults int
			Resources    []json.RawMessage
		}
		if json.Unmarshal(listed, &page) != nil || page.TotalResults != 0 || len(page.Resources) != 0 {
			t.Fatal("co-selected Group List exposed the tombstoned Group")
		}
	} else {
		_, headers := call(http.MethodGet, path, connection.Bearer.Token(), "", "", http.StatusMethodNotAllowed, false)
		if headers.Get("Allow") != http.MethodDelete {
			t.Fatal("standalone Delete selected another resource method")
		}
	}
	if referenceManagedGroupReadState(t, ctx, source) != afterAlias || relatedState() != beforeRelated || counts() != wantCounts {
		t.Fatal("Delete read coexistence changed original custody, linked resources or effects")
	}
}
