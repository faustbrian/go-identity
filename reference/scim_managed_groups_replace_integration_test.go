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
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedGroupsReplaceHTTPS(t *testing.T) {
	t.Run("standalone-group-replace", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsReplace: true,
		})
	})
	t.Run("with-group-get-and-list", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsReplace: true,
			scimManagedGroupsRead: true,
		})
	})
}

func configureReferenceSCIMManagedGroupsReplace(c *reference.StoreConfiguration) {
	n := &reference.HTTPManagedSCIMGroupsReplaceConfiguration{MaximumMembers: scim.DefaultGroupMembers}
	userRoutesSelected := c.HTTPManagedSCIMUsersList != nil || c.HTTPManagedSCIMUsersGet != nil ||
		c.HTTPManagedSCIMUsersCreate != nil || c.HTTPManagedSCIMUsersDelete != nil ||
		c.HTTPManagedSCIMUsersPatch != nil || c.HTTPManagedSCIMUsersReplace != nil
	switch {
	case c.HTTPManagedSCIMGroupsRead != nil:
		n.MaximumMembers = c.HTTPManagedSCIMGroupsRead.MaximumMembers
	case c.HTTPManagedSCIMGroupsCreate != nil:
		n.MaximumMembers = c.HTTPManagedSCIMGroupsCreate.MaximumMembers
	case !userRoutesSelected:
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-group-replace", [32]byte{0xb6}
		}
	}
	c.HTTPManagedSCIMGroupsReplace = n
}

func proveReferenceSCIMManagedGroupsReplaceTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
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
	default:
		profile = c.HTTPManagedSCIMGroupsReplace.Native
	}
	if profile == nil {
		t.Fatal("selected conditional Group Replace has no first native owner")
	}
	native := referenceManagedUsersNative(t, c, source, *profile)
	connection, other := referenceManagedGroupReadConnections(t, ctx, features, cookies, csrf, source, *profile, native)
	oldChild := seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Original child", nil)
	newChild := seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Replacement child", nil)
	foreign := seedReferenceManagedGroupReadFixture(t, ctx, source, other.Connection.Scope(), "Foreign child", nil)
	created, err := native.ExecuteManagedAdmittedGroupCreate(ctx, otpTenant, scim.Request{
		Operation: scim.GroupCreate, Credential: connection.Bearer, IdempotencyKey: "reference-managed-group-replace-seed",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Original parent","members":[{"value":"` + oldChild.ID + `","type":"Group"}]}`),
	}, c.HTTPManagedSCIMGroupsReplace.MaximumMembers, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
	var original struct {
		ID   string
		Meta struct{ Created string }
	}
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" || created.ETag == "" {
		t.Fatal("seed original native Group without selecting public Group Create", err)
	}
	const collection = "/scim/v2/Groups"
	resourcePath := collection + "/" + original.ID
	const name = "Reference replaced parent"
	replace := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + name + `","members":[{"value":"` + newChild.ID + `","type":"Group"}]}`)
	call := func(method, path, bearer, version string, input []byte, status int, protocol bool, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		if version != "" {
			request.Header.Set("If-Match", version)
		}
		if len(input) != 0 {
			request.Header.Set("Content-Type", "application/scim+json")
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed conditional Group Replace TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || response.TLS == nil || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("conditional Group Replace TLS %s %s: status %d want %d; media %q, cleanup %v/%v", method, path, response.StatusCode, status, response.Header.Get("Content-Type"), readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("conditional Group Replace changed cache or browser session custody")
		}
		for _, secret := range []string{connection.Bearer.Token(), other.Bearer.Token(), source.bearer.Token(), cookies[0].Value} {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("conditional Group Replace disclosed credential custody")
			}
		}
		if status >= 400 && (response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || bytes.Contains(wire, []byte(original.ID))) {
			t.Fatal("conditional Group Replace denial disclosed the native target, version or location")
		}
		if protocol && status >= 400 {
			var denial struct {
				Schemas []string `json:"schemas"`
				Status  string   `json:"status"`
			}
			if json.Unmarshal(wire, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(status) {
				t.Fatal("conditional Group Replace denial lost its exact SCIM schema/status envelope")
			}
		}
		return wire, response.Header.Clone()
	}
	beforeValidation := referenceManagedGroupReadState(t, ctx, source)
	denyBeforeEffects := func(bearer, version string, status int, changes ...func(*http.Request)) {
		t.Helper()
		call(http.MethodPut, resourcePath, bearer, version, replace, status, true, changes...)
		if referenceManagedGroupReadState(t, ctx, source) != beforeValidation {
			t.Fatal("unvalidated Group Replace changed resources, commands, request custody, audit or outbox")
		}
	}
	denyBeforeEffects("", string(created.ETag), http.StatusUnauthorized, func(r *http.Request) { r.AddCookie(cookies[0]) })
	denyBeforeEffects("not-an-issued-managed-bearer", string(created.ETag), http.StatusUnauthorized)
	denyBeforeEffects(source.bearer.Token(), string(created.ETag), http.StatusUnauthorized)
	denyBeforeEffects(connection.Bearer.Token(), string(created.ETag), http.StatusBadRequest, func(r *http.Request) {
		r.Header.Set("Idempotency-Key", "caller-must-not-allocate-group-replace-command")
	})
	denyBeforeEffects(connection.Bearer.Token(), "", http.StatusPreconditionRequired)

	groupsState := func() string {
		t.Helper()
		var state string
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(g) ORDER BY resource_id)::text FROM scim.groups g`).Scan(&state); err != nil {
			t.Fatal("snapshot exact owned and foreign Group projections", err)
		}
		return state
	}
	counts := func() [5]int {
		t.Helper()
		var got [5]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose=$1),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.request_key_mappings m JOIN identity.commands c USING(command_id) WHERE c.purpose=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed')`, string(scim.GroupReplace)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4]); err != nil {
			t.Fatal("observe Group Replace original command, mapping and committed effects", err)
		}
		return got
	}
	denyWithoutMutation := func(bearer, version string, input []byte, status int) {
		t.Helper()
		before, beforeCounts := groupsState(), counts()
		call(http.MethodPut, resourcePath, bearer, version, input, status, true)
		afterCounts := counts()
		if groupsState() != before || afterCounts[1] != beforeCounts[1] || afterCounts[3] != beforeCounts[3] || afterCounts[4] != beforeCounts[4] {
			t.Fatal("denied Group Replace changed owned/foreign Groups or committed command/audit/outbox effects")
		}
	}
	foreignBody := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied foreign parent","members":[{"value":"` + foreign.ID + `","type":"Group"}]}`)
	denyWithoutMutation(connection.Bearer.Token(), string(created.ETag), foreignBody, http.StatusBadRequest)
	denyWithoutMutation(other.Bearer.Token(), string(created.ETag), replace, http.StatusNotFound)
	denyWithoutMutation(connection.Bearer.Token(), `"stale-native-group-version"`, replace, http.StatusPreconditionFailed)

	beforeCounts := counts()
	first, firstHeaders := call(http.MethodPut, resourcePath, connection.Bearer.Token(), string(created.ETag), replace, http.StatusOK, true)
	var resource struct {
		Schemas         []string `json:"schemas"`
		ID, DisplayName string
		Members         []struct{ Value, Type string }
		Meta            struct{ ResourceType, Created, Version, Location string }
	}
	etag := firstHeaders.Get("ETag")
	wantLocation := source.config.BaseURL + "/Groups/" + original.ID
	if json.Unmarshal(first, &resource) != nil || len(resource.Schemas) != 1 || resource.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:Group" || resource.ID != original.ID || resource.DisplayName != name || len(resource.Members) != 1 || resource.Members[0].Value != newChild.ID || resource.Members[0].Type != "Group" || resource.Meta.ResourceType != "Group" || resource.Meta.Created != original.Meta.Created {
		t.Fatal("HTTPS Group Replace lost canonical schema, identity, creation time or exact replacement member")
	}
	if len(etag) < 3 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || etag == string(created.ETag) || resource.Meta.Version != etag || firstHeaders.Get("Location") != wantLocation || resource.Meta.Location != wantLocation {
		t.Fatal("HTTPS Group Replace lost the changed native strong ETag or authoritative Location")
	}
	wantCounts := beforeCounts
	for i := range wantCounts {
		wantCounts[i]++
	}
	if got := counts(); got != wantCounts {
		t.Fatal("HTTPS Group Replace did not commit one original command, mapping, audit and outbox effect", got, wantCounts)
	}
	assertPersisted := func(want []byte, version string, generation int) {
		t.Helper()
		read, err := native.ExecuteManagedAdmittedGroupRead(ctx, otpTenant, scim.Request{
			Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: original.ID,
		}, c.HTTPManagedSCIMGroupsReplace.MaximumMembers, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
		if err != nil || read.Status != http.StatusOK || !bytes.Equal(read.Body, want) || string(read.ETag) != version || read.Location != wantLocation {
			t.Fatal("HTTPS Group Replace differs from exact persisted native Group/member/version", err)
		}
		var actualGeneration int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT generation FROM scim.groups WHERE tenant_id=$1 AND resource_id=$2`, string(otpTenant), original.ID).Scan(&actualGeneration); err != nil || actualGeneration != generation {
			t.Fatal("conditional Group Replace advanced the wrong native generation", err)
		}
	}
	assertPersisted(first, etag, 2)
	after := referenceManagedGroupReadState(t, ctx, source)
	var equivalent bytes.Buffer
	if err := json.Indent(&equivalent, replace, "", "  "); err != nil {
		t.Fatal(err)
	}
	replayed, replayHeaders := call(http.MethodPut, resourcePath, connection.Bearer.Token(), string(created.ETag), equivalent.Bytes(), http.StatusOK, true)
	if !bytes.Equal(first, replayed) || firstHeaders.Get("Content-Type") != replayHeaders.Get("Content-Type") || replayHeaders.Get("ETag") != etag || replayHeaders.Get("Location") != wantLocation || referenceManagedGroupReadState(t, ctx, source) != after || counts() != wantCounts {
		t.Fatal("headerless Group Replace replay lost the original response or repeated protected effects")
	}
	assertPersisted(first, etag, 2)
	changed := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Changed original input"}`)
	denyWithoutMutation(connection.Bearer.Token(), string(created.ETag), changed, http.StatusPreconditionFailed)
	denyWithoutMutation(connection.Bearer.Token(), `"another-stale-group-version"`, replace, http.StatusPreconditionFailed)

	if c.HTTPManagedSCIMGroupsRead != nil {
		read, headers := call(http.MethodGet, resourcePath, connection.Bearer.Token(), "", nil, http.StatusOK, true)
		if !bytes.Equal(read, first) || headers.Get("ETag") != etag || headers.Get("Location") != "" {
			t.Fatal("co-selected Group Get did not observe the exact replaced Group")
		}
		query := url.Values{"filter": {`id eq "` + original.ID + `"`}, "count": {"1"}}
		listed, headers := call(http.MethodGet, collection+"?"+query.Encode(), connection.Bearer.Token(), "", nil, http.StatusOK, true)
		var page struct {
			TotalResults, StartIndex, ItemsPerPage int
			Resources                              []json.RawMessage
		}
		if json.Unmarshal(listed, &page) != nil || page.TotalResults != 1 || page.StartIndex != 1 || page.ItemsPerPage != 1 || len(page.Resources) != 1 || !bytes.Equal(page.Resources[0], first) || headers.Get("ETag") != "" || headers.Get("Location") != "" {
			t.Fatal("co-selected Group List did not observe the exact replaced Group")
		}
	} else {
		_, headers := call(http.MethodGet, resourcePath, connection.Bearer.Token(), "", nil, http.StatusMethodNotAllowed, false)
		if headers.Get("Allow") != http.MethodPut {
			t.Fatal("standalone Group Replace advertised another resource method")
		}
		call(http.MethodPost, collection, connection.Bearer.Token(), "", replace, http.StatusNotFound, false)
	}

	beforeClear := counts()
	clearBody := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Cleared parent"}`)
	cleared, clearHeaders := call(http.MethodPut, resourcePath, connection.Bearer.Token(), etag, clearBody, http.StatusOK, true)
	var empty struct {
		ID, DisplayName string
		Members         []json.RawMessage
	}
	if json.Unmarshal(cleared, &empty) != nil || empty.ID != original.ID || empty.DisplayName != "Cleared parent" || len(empty.Members) != 0 || clearHeaders.Get("ETag") == etag || clearHeaders.Get("Location") != wantLocation {
		t.Fatal("Group Replace merged omitted members instead of clearing the prior typed links")
	}
	assertPersisted(cleared, clearHeaders.Get("ETag"), 3)
	for i := range beforeClear {
		beforeClear[i]++
	}
	if counts() != beforeClear {
		t.Fatal("omitted-member Group Replace did not commit exactly one additional original command and effects")
	}
}
