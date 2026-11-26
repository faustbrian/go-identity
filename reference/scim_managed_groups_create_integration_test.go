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

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedGroupsCreateHTTPS(t *testing.T) {
	t.Run("standalone-group-create", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsCreate: true,
		})
	})
	t.Run("with-group-get-and-list", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedGroupsCreate: true,
			scimManagedGroupsRead: true,
		})
	})
}

func configureReferenceSCIMManagedGroupsCreate(c *reference.StoreConfiguration) {
	n := &reference.HTTPManagedSCIMGroupsCreateConfiguration{MaximumMembers: scim.DefaultGroupMembers}
	userRoutesSelected := c.HTTPManagedSCIMUsersList != nil || c.HTTPManagedSCIMUsersGet != nil ||
		c.HTTPManagedSCIMUsersCreate != nil || c.HTTPManagedSCIMUsersDelete != nil ||
		c.HTTPManagedSCIMUsersPatch != nil || c.HTTPManagedSCIMUsersReplace != nil
	if c.HTTPManagedSCIMGroupsRead != nil {
		n.MaximumMembers = c.HTTPManagedSCIMGroupsRead.MaximumMembers
	} else if !userRoutesSelected {
		profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
		n.Native = &profile
		c.HTTPManagedSCIMCreate = nil
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-group-create", [32]byte{0xb5}
		}
	}
	c.HTTPManagedSCIMGroupsCreate = n
}

func proveReferenceSCIMManagedGroupsCreateTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	var profile *reference.ManagedSCIMConnectionConfiguration
	switch {
	case c.HTTPManagedSCIMUsersList != nil:
		profile = c.HTTPManagedSCIMUsersList.Native
	case c.HTTPManagedSCIMUsersGet != nil:
		profile = c.HTTPManagedSCIMUsersGet.Native
	case c.HTTPManagedSCIMGroupsRead != nil:
		profile = c.HTTPManagedSCIMGroupsRead.Native
	default:
		profile = c.HTTPManagedSCIMGroupsCreate.Native
	}
	if profile == nil {
		t.Fatal("selected managed Group Create has no native owner")
	}
	native := referenceManagedUsersNative(t, c, source, *profile)
	connection, other := referenceManagedGroupReadConnections(t, ctx, features, cookies, csrf, source, *profile, native)
	child := seedReferenceManagedGroupReadFixture(t, ctx, source, connection.Connection.Scope(), "Owned child", nil)
	foreign := seedReferenceManagedGroupReadFixture(t, ctx, source, other.Connection.Scope(), "Foreign child", nil)
	const collection = "/scim/v2/Groups"
	const name = "Reference managed parent"
	body := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + name + `","members":[{"value":"` + child.ID + `","type":"Group"}]}`)
	call := func(method, path, bearer string, input []byte, status int, protocol bool, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if len(input) != 0 {
			request.Header.Set("Content-Type", "application/scim+json")
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed Group Create TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != status || readErr != nil || closeErr != nil || len(wire) > 1<<20 || (response.Header.Get("Content-Type") == "application/scim+json") != protocol {
			t.Fatalf("managed Group Create TLS %s %s: status %d want %d; media %q, cleanup %v/%v", method, path, response.StatusCode, status, response.Header.Get("Content-Type"), readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("managed Group Create changed cache or browser session custody")
		}
		for _, secret := range []string{connection.Bearer.Token(), other.Bearer.Token(), source.bearer.Token(), cookies[0].Value} {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("managed Group Create disclosed credential custody")
			}
		}
		if (status != http.StatusCreated && response.Header.Get("Location") != "") || (status >= 400 && response.Header.Get("ETag") != "") {
			t.Fatal("Group denial disclosed resource location or version")
		}
		if protocol && status >= 400 {
			var denial struct {
				Schemas []string `json:"schemas"`
				Status  string   `json:"status"`
			}
			if json.Unmarshal(wire, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(status) {
				t.Fatal("Group Create denial lost its exact SCIM schema/status envelope")
			}
		}
		return wire, response.Header.Clone()
	}
	beforeValidation := referenceManagedGroupReadState(t, ctx, source)
	denyBeforeEffects := func(bearer string, input []byte, status int, changes ...func(*http.Request)) {
		t.Helper()
		call(http.MethodPost, collection, bearer, input, status, true, changes...)
		if referenceManagedGroupReadState(t, ctx, source) != beforeValidation {
			t.Fatal("unvalidated Group Create changed Groups, Users, commands, request custody, audit or outbox")
		}
	}
	denyBeforeEffects("", body, http.StatusUnauthorized, func(r *http.Request) { r.AddCookie(cookies[0]) })
	denyBeforeEffects("not-an-issued-managed-bearer", body, http.StatusUnauthorized)
	denyBeforeEffects(source.bearer.Token(), body, http.StatusUnauthorized)
	denyBeforeEffects(connection.Bearer.Token(), body, http.StatusBadRequest, func(r *http.Request) {
		r.Header.Set("Idempotency-Key", "caller-must-not-allocate-group-command")
	})
	denyBeforeEffects(connection.Bearer.Token(), []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"missing-display-name"}`), http.StatusBadRequest)
	counts := func() [4]int {
		t.Helper()
		var got [4]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM scim.groups),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed'),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1 AND c.state='committed')`, string(scim.GroupCreate)).Scan(&got[0], &got[1], &got[2], &got[3]); err != nil {
			t.Fatal("observe native Group Create and atomic committed effects", err)
		}
		return got
	}
	beforeForeign := counts()
	foreignBody := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Denied foreign parent","members":[{"value":"` + foreign.ID + `","type":"Group"}]}`)
	call(http.MethodPost, collection, connection.Bearer.Token(), foreignBody, http.StatusBadRequest, true)
	if counts() != beforeForeign {
		t.Fatal("wrong-connection member committed a Group or command/audit/outbox effects")
	}

	beforeCreate := counts()
	wire, headers := call(http.MethodPost, collection, connection.Bearer.Token(), body, http.StatusCreated, true)
	var resource struct {
		Schemas         []string `json:"schemas"`
		ID, DisplayName string
		Members         []struct{ Value, Type string }
		Meta            struct{ ResourceType, Version, Location string }
	}
	if json.Unmarshal(wire, &resource) != nil || len(resource.Schemas) != 1 || resource.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:Group" || resource.DisplayName != name || len(resource.Members) != 1 || resource.Members[0].Value != child.ID || resource.Members[0].Type != "Group" || resource.Meta.ResourceType != "Group" {
		t.Fatal("HTTPS Group Create lost canonical schema, name or exact typed child member")
	}
	if _, err := identity.ParseSubjectID(resource.ID); err != nil {
		t.Fatal("HTTPS Group Create did not allocate a canonical native resource ID", err)
	}
	etag := headers.Get("ETag")
	if len(etag) < 3 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || resource.Meta.Version != etag {
		t.Fatal("HTTPS Group Create lost the native strong ETag")
	}
	wantLocation := source.config.BaseURL + "/Groups/" + resource.ID
	if headers.Get("Location") != wantLocation || resource.Meta.Location != wantLocation {
		t.Fatal("HTTPS Group Create changed canonical Location or resource metadata")
	}
	expected, err := native.ExecuteManagedAdmittedGroupRead(ctx, otpTenant, scim.Request{
		Operation: scim.GroupGet, Credential: connection.Bearer, ResourceID: resource.ID,
	}, c.HTTPManagedSCIMGroupsCreate.MaximumMembers, func(context.Context, scim.ProtocolClient) *scim.Error { return nil })
	if err != nil || expected.Status != http.StatusOK || !bytes.Equal(wire, expected.Body) || etag != string(expected.ETag) {
		t.Fatal("HTTPS Group Create differs from exact persisted native Group/member/version", err)
	}
	wantCounts := beforeCreate
	for i := range wantCounts {
		wantCounts[i]++
	}
	if got := counts(); got != wantCounts {
		t.Fatal("HTTPS Group Create did not commit one Group and atomic command/audit/outbox effects", got, wantCounts)
	}

	if c.HTTPManagedSCIMGroupsRead != nil {
		read, readHeaders := call(http.MethodGet, collection+"/"+resource.ID, connection.Bearer.Token(), nil, http.StatusOK, true)
		if !bytes.Equal(read, expected.Body) || readHeaders.Get("ETag") != etag {
			t.Fatal("co-selected Group Get did not observe the exact HTTPS-created Group")
		}
		query := url.Values{"filter": {`id eq "` + resource.ID + `"`}, "count": {"1"}}
		listed, listHeaders := call(http.MethodGet, collection+"?"+query.Encode(), connection.Bearer.Token(), nil, http.StatusOK, true)
		var page struct {
			TotalResults, StartIndex, ItemsPerPage int
			Resources                              []json.RawMessage
		}
		if json.Unmarshal(listed, &page) != nil || page.TotalResults != 1 || page.StartIndex != 1 || page.ItemsPerPage != 1 || len(page.Resources) != 1 || !bytes.Equal(page.Resources[0], expected.Body) || listHeaders.Get("ETag") != "" {
			t.Fatal("co-selected Group List did not observe the exact HTTPS-created Group")
		}
		call(http.MethodGet, collection+"/"+resource.ID, other.Bearer.Token(), nil, http.StatusNotFound, true)
	} else {
		_, otherMethod := call(http.MethodGet, collection, connection.Bearer.Token(), nil, http.StatusMethodNotAllowed, false)
		if otherMethod.Get("Allow") != http.MethodPost {
			t.Fatal("standalone Group Create advertised an unselected collection method")
		}
		call(http.MethodGet, collection+"/"+resource.ID, connection.Bearer.Token(), nil, http.StatusNotFound, false)
	}
	if counts() != wantCounts {
		t.Fatal("Group read coexistence changed committed Group Create effects")
	}
}
