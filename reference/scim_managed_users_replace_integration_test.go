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

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedUsersReplaceHTTPS(t *testing.T) {
	t.Run("standalone-user-replace", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersReplace: true,
		})
	})
	t.Run("with-user-list-get-create-and-patch", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersReplace: true,
			scimManagedUsersList: true, scimManagedUsersGet: true, scimManagedUsersCreate: true, scimManagedUsersPatch: true,
		})
	})
}

func configureReferenceSCIMManagedUsersReplace(c *reference.StoreConfiguration, adminCreate bool) {
	n := &reference.HTTPManagedSCIMUsersReplaceConfiguration{}
	if c.HTTPManagedSCIMUsersList == nil && c.HTTPManagedSCIMUsersGet == nil && c.HTTPManagedSCIMUsersCreate == nil && c.HTTPManagedSCIMUsersDelete == nil && c.HTTPManagedSCIMUsersPatch == nil {
		if !adminCreate {
			profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
			n.Native = &profile
			c.HTTPManagedSCIMCreate = nil
		}
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-users", [32]byte{0xb3}
		}
	}
	c.HTTPManagedSCIMUsersReplace = n
}

func proveReferenceSCIMUsersReplaceHTTPS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
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
	default:
		profile = c.HTTPManagedSCIMUsersReplace.Native
	}
	if profile == nil {
		t.Fatal("selected conditional User Replace has no first native owner")
	}
	native, bearer := referenceManagedUsersConnection(t, ctx, c, features, cookies, csrf, source, *profile)
	credential := authentication.NewBearerCredential(bearer)
	created, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{
		Operation: scim.UserCreate, Credential: credential, IdempotencyKey: "reference-managed-replace-user-1",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"reference-managed-replace-original","externalId":"old-correlation","name":{"familyName":"Omitted name"},"emails":[{"value":"old@example.test"}]}`),
	})
	var original struct {
		ID   string `json:"id"`
		Meta struct {
			Created string `json:"created"`
		} `json:"meta"`
	}
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" || created.ETag == "" {
		t.Fatal("persist physical User using the genuinely issued native bearer", err)
	}
	resourcePath := "/scim/v2/Users/" + original.ID
	const updatedName = "reference-managed-replace-updated"
	replace := []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + updatedName + `","active":true}`)
	call := func(method, token, version string, input []byte, status int, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+resourcePath, bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
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
			t.Fatal("managed conditional User Replace TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
		closeErr := response.Body.Close()
		if response.StatusCode != status || response.TLS == nil || readErr != nil || closeErr != nil || len(wire) > 8192 {
			t.Fatalf("conditional User Replace TLS status %d want %d; cleanup %v/%v", response.StatusCode, status, readErr, closeErr)
		}
		if response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("conditional User Replace changed SCIM media, cache or browser session custody")
		}
		secrets := []string{bearer, source.bearer.Token()}
		for _, cookie := range cookies {
			secrets = append(secrets, cookie.Value)
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("conditional User Replace disclosed credential custody")
			}
		}
		if status >= 400 && (response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || bytes.Contains(wire, []byte(original.ID))) {
			t.Fatal("conditional User Replace denial disclosed the native target, version or location")
		}
		return wire, response.Header.Clone()
	}
	projectionState := func() string {
		t.Helper()
		var state string
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'projection',to_jsonb(s),
 'identity',(SELECT to_jsonb(u) FROM identity.users u WHERE u.tenant_id=s.tenant_id AND u.user_id=s.user_id),
 'attributes',(SELECT to_jsonb(a) FROM identity.user_attributes a WHERE a.tenant_id=s.tenant_id AND a.user_id=s.user_id))::text
 FROM scim.users s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(otpTenant), original.ID).Scan(&state); err != nil {
			t.Fatal("read exact physical scoped User, identity and mapped fields", err)
		}
		return state
	}
	counts := func() [7]int {
		t.Helper()
		var got [7]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.users WHERE tenant_id=$1),
 (SELECT count(*) FROM scim.users WHERE tenant_id=$1),
 (SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose=$2),
 (SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose=$2 AND state='committed'),
 (SELECT count(*) FROM identity.request_key_mappings m JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2)`, string(otpTenant), string(scim.UserReplace)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6]); err != nil {
			t.Fatal("read actual scoped Replace command, mapping, audit and outbox effects", err)
		}
		return got
	}
	before, beforeCounts := projectionState(), counts()
	deny := func(token, version string, status int, kind string, changes ...func(*http.Request)) {
		t.Helper()
		wire, _ := call(http.MethodPut, token, version, replace, status, changes...)
		want, err := json.Marshal(scim.NewError(status, kind))
		if err != nil || !bytes.Equal(bytes.TrimSpace(wire), want) || projectionState() != before || counts() != beforeCounts {
			t.Fatal("denied conditional User Replace changed native state, command custody or redacted error", status)
		}
	}
	deny("", string(created.ETag), http.StatusUnauthorized, "", func(r *http.Request) { r.AddCookie(cookies[0]) })
	deny("not-an-issued-managed-bearer", string(created.ETag), http.StatusUnauthorized, "")
	if source.bearer.Token() != "" {
		deny(source.bearer.Token(), string(created.ETag), http.StatusUnauthorized, "")
	}
	deny(bearer, string(created.ETag), http.StatusBadRequest, "invalidValue", func(r *http.Request) { r.Header.Set("Idempotency-Key", "caller-must-not-allocate-replace-command") })
	deny(bearer, string(created.ETag), http.StatusUnsupportedMediaType, "", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") })
	deny(bearer, "", http.StatusPreconditionRequired, "")
	stale, _ := call(http.MethodPut, bearer, `"stale-native-replace-version"`, replace, http.StatusPreconditionFailed)
	wantStale, err := json.Marshal(scim.NewError(http.StatusPreconditionFailed, ""))
	if err != nil || !bytes.Equal(bytes.TrimSpace(stale), wantStale) || projectionState() != before {
		t.Fatal("stale live User Replace changed persisted User state or its redacted 412")
	}
	beforeCounts = counts()
	first, firstHeaders := call(http.MethodPut, bearer, string(created.ETag), replace, http.StatusOK)
	var resource struct {
		Schemas  []string `json:"schemas"`
		ID       string   `json:"id"`
		UserName string   `json:"userName"`
		Active   *bool    `json:"active"`
		Meta     struct {
			ResourceType string `json:"resourceType"`
			Created      string `json:"created"`
			Version      string `json:"version"`
			Location     string `json:"location"`
		} `json:"meta"`
	}
	etag := firstHeaders.Get("ETag")
	wantLocation := source.config.BaseURL + "/Users/" + original.ID
	if json.Unmarshal(first, &resource) != nil || len(resource.Schemas) != 1 || resource.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" || resource.ID != original.ID || resource.UserName != updatedName || resource.Active == nil || !*resource.Active || resource.Meta.ResourceType != "User" || resource.Meta.Created != original.Meta.Created || resource.Meta.Version != etag || etag == string(created.ETag) || len(etag) <= 2 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || firstHeaders.Get("Location") != wantLocation || resource.Meta.Location != wantLocation {
		t.Fatal("HTTPS Replace lost its complete input, strong changed ETag or exact native User/Location binding")
	}
	var replacement map[string]any
	if json.Unmarshal(first, &replacement) != nil {
		t.Fatal("decode complete replacement User")
	}
	for _, omitted := range []string{"externalId", "name", "emails"} {
		if _, exists := replacement[omitted]; exists {
			t.Fatalf("HTTPS Replace retained omitted writable field %s as a PATCH merge", omitted)
		}
	}
	after, afterCounts := projectionState(), counts()
	wantCounts := beforeCounts
	for i := 2; i < len(wantCounts); i++ {
		wantCounts[i]++
	}
	if after == before || afterCounts != wantCounts {
		t.Fatal("conditional User Replace did not commit exactly one original command, mapping, audit and outbox effect", afterCounts, wantCounts)
	}
	var equivalent bytes.Buffer
	if err := json.Indent(&equivalent, replace, "", "  "); err != nil {
		t.Fatal("format equivalent original replacement", err)
	}
	replayed, replayedHeaders := call(http.MethodPut, bearer, string(created.ETag), equivalent.Bytes(), http.StatusOK)
	if !bytes.Equal(first, replayed) || firstHeaders.Get("Content-Type") != replayedHeaders.Get("Content-Type") || firstHeaders.Get("ETag") != replayedHeaders.Get("ETag") || firstHeaders.Get("Location") != replayedHeaders.Get("Location") || projectionState() != after || counts() != afterCounts {
		t.Fatal("headerless conditional Replace replay duplicated mutation or changed original command/receipt custody")
	}
	var generation int64
	var live, identityActive bool
	var userID string
	var projectionWire []byte
	if err := source.pool.Raw().QueryRow(ctx, `SELECT s.generation,s.deleted_at IS NULL,u.status='active',s.user_id,s.resource
 FROM scim.users s JOIN identity.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
 WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(otpTenant), original.ID).Scan(&generation, &live, &identityActive, &userID, &projectionWire); err != nil || generation != 2 || !live || !identityActive {
		t.Fatal("conditional Replace/replay did not advance exactly one native generation or changed identity status", err)
	}
	var projection scim.Resource
	if json.Unmarshal(projectionWire, &projection) != nil || projection.ID != original.ID || projection.Version != scim.Version(etag) || projection.Attributes["userName"] != updatedName || projection.ExternalID != "" {
		t.Fatal("persisted native projection differs from the exact HTTPS Replace User/version")
	}
	reader, err := kernel.NewRepository(source.pool, kernel.Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{profile.Provisioning.FieldSchema}, ProfileSchema: kernel.ProfileSchemaRef{ID: profile.Provisioning.FieldSchema.ID, Version: profile.Provisioning.FieldSchema.Version}})
	if err != nil {
		t.Fatal("compose actual mapped native profile reader", err)
	}
	nativeProfile, err := reader.GetProfile(ctx, identity.ProfileQuery{TenantID: otpTenant, UserID: identity.UserID(userID)})
	if err != nil {
		t.Fatal("read physical mapped identity after HTTPS Replace", err)
	}
	foundName := false
	for _, field := range nativeProfile.Profile.AdditionalFields {
		if field.Name == profile.Provisioning.UserNameField {
			foundName = field.Value.Kind == identity.AttributeString && field.Value.Scalar.Kind == identity.AttributeString && field.Value.Scalar.String == updatedName
		}
	}
	if !foundName {
		t.Fatal("HTTPS Replace did not update the actual mapped identity field")
	}
	read, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserGet, Credential: credential, ResourceID: original.ID})
	if err != nil || read.Status != http.StatusOK || !bytes.Equal(read.Body, first) || read.ETag != scim.Version(etag) || read.Location != wantLocation {
		t.Fatal("native read differs from persisted TLS-replaced User", err)
	}
	if c.HTTPManagedSCIMUsersGet != nil {
		wire, headers := call(http.MethodGet, bearer, "", nil, http.StatusOK)
		if !bytes.Equal(wire, first) || headers.Get("ETag") != etag || headers.Get("Location") != "" || projectionState() != after || counts() != afterCounts {
			t.Fatal("selected HTTP Get did not observe exact Replace state without another mutation")
		}
	}
}
