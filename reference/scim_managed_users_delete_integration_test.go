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
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/reference"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedUsersDeleteHTTPS(t *testing.T) {
	t.Run("standalone-user-delete", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersDelete: true,
		})
	})
	t.Run("with-user-list-get-and-create", func(t *testing.T) {
		proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
			postgresBaseline: true, organization: true, scimManagedUsersDelete: true,
			scimManagedUsersList: true, scimManagedUsersGet: true, scimManagedUsersCreate: true,
		})
	})
}

func configureReferenceSCIMManagedUsersDelete(c *reference.StoreConfiguration, adminCreate bool) {
	n := &reference.HTTPManagedSCIMUsersDeleteConfiguration{}
	if c.HTTPManagedSCIMUsersList == nil && c.HTTPManagedSCIMUsersGet == nil && c.HTTPManagedSCIMUsersCreate == nil {
		if !adminCreate {
			profile := referenceManagedSCIMNativeConfiguration(c.HTTPManagedSCIMCreate)
			n.Native = &profile
			c.HTTPManagedSCIMCreate = nil
		}
		if c.SCIMBulk == nil {
			n.RateNamespace, n.RateKey = "reference-scim-users", [32]byte{0xb3}
		}
	}
	c.HTTPManagedSCIMUsersDelete = n
}

func proveReferenceSCIMUsersDeleteHTTPS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
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
	default:
		profile = c.HTTPManagedSCIMUsersDelete.Native
	}
	if profile == nil {
		t.Fatal("selected conditional User Delete has no first native owner")
	}
	native, bearer := referenceManagedUsersConnection(t, ctx, c, features, cookies, csrf, source, *profile)
	credential := authentication.NewBearerCredential(bearer)
	created, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{
		Operation: scim.UserCreate, Credential: credential, IdempotencyKey: "reference-managed-delete-user-1",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"reference-managed-delete-user"}`),
	})
	var original struct {
		ID string `json:"id"`
	}
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" || created.ETag == "" {
		t.Fatal("persist physical User using the genuinely issued native bearer", err)
	}
	resourcePath := "/scim/v2/Users/" + original.ID
	call := func(method, token, version string, status int, changes ...func(*http.Request)) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+resourcePath, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if version != "" {
			request.Header.Set("If-Match", version)
		}
		for _, change := range changes {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed conditional User Delete TLS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
		closeErr := response.Body.Close()
		if response.StatusCode != status || readErr != nil || closeErr != nil || len(wire) > 8192 {
			t.Fatalf("conditional User Delete TLS status %d want %d; cleanup %v/%v", response.StatusCode, status, readErr, closeErr)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("conditional User Delete changed cache, representation or browser session custody")
		}
		for _, secret := range []string{bearer, cookies[0].Value} {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("conditional User Delete disclosed credential custody")
			}
		}
		if status == http.StatusNoContent {
			if len(wire) != 0 || response.Header.Get("Content-Type") != "" {
				t.Fatal("conditional User Delete/replay did not return exact bodyless 204")
			}
		} else if response.Header.Get("Content-Type") != "application/scim+json" || bytes.Contains(wire, []byte(original.ID)) {
			t.Fatal("conditional User Delete denial changed SCIM media or disclosed the target")
		}
		return wire, response.Header.Clone()
	}
	projectionState := func() string {
		t.Helper()
		var state string
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'projection',to_jsonb(s),'identity',(SELECT to_jsonb(u) FROM identity.users u WHERE u.tenant_id=s.tenant_id AND u.user_id=s.user_id))::text
 FROM scim.users s WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(otpTenant), original.ID).Scan(&state); err != nil {
			t.Fatal("read exact physical scoped User and global identity", err)
		}
		return state
	}
	counts := func() [7]int {
		t.Helper()
		var got [7]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.users), (SELECT count(*) FROM scim.users),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1 AND state='committed'),
 (SELECT count(*) FROM identity.request_key_mappings m JOIN identity.commands c USING(command_id) WHERE c.purpose=$1),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.purpose=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.purpose=$1)`, string(scim.UserDelete)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6]); err != nil {
			t.Fatal("read actual conditional Delete command/custody/audit/outbox effects", err)
		}
		return got
	}
	before, beforeCounts := projectionState(), counts()
	deny := func(token, version string, status int, kind string, changes ...func(*http.Request)) {
		t.Helper()
		wire, _ := call(http.MethodDelete, token, version, status, changes...)
		want, err := json.Marshal(scim.NewError(status, kind))
		if err != nil || !bytes.Equal(bytes.TrimSpace(wire), want) || projectionState() != before || counts() != beforeCounts {
			t.Fatal("denied conditional User Delete changed native state, custody or redacted error", status)
		}
	}
	deny("", string(created.ETag), http.StatusUnauthorized, "", func(r *http.Request) { r.AddCookie(cookies[0]) })
	deny(bearer, string(created.ETag), http.StatusBadRequest, "invalidValue", func(r *http.Request) { r.Header.Set("Idempotency-Key", "caller-must-not-allocate-delete-command") })
	deny(bearer, "", http.StatusPreconditionRequired, "")
	stale, _ := call(http.MethodDelete, bearer, `"stale-native-delete-version"`, http.StatusPreconditionFailed)
	wantStale, err := json.Marshal(scim.NewError(http.StatusPreconditionFailed, ""))
	if err != nil || !bytes.Equal(bytes.TrimSpace(stale), wantStale) || projectionState() != before {
		t.Fatal("stale live User Delete changed the persisted projection/identity or SCIM 412")
	}
	beforeCounts = counts()
	first, firstHeaders := call(http.MethodDelete, bearer, string(created.ETag), http.StatusNoContent)
	after, afterCounts := projectionState(), counts()
	if after == before {
		t.Fatal("successful conditional User Delete did not withdraw the actual native projection")
	}
	wantCounts := beforeCounts
	for i := 2; i < len(wantCounts); i++ {
		wantCounts[i]++
	}
	if afterCounts != wantCounts {
		t.Fatal("conditional User Delete did not commit exactly one original command, mapping, audit and outbox effect", afterCounts, wantCounts)
	}
	replayed, replayedHeaders := call(http.MethodDelete, bearer, string(created.ETag), http.StatusNoContent)
	if !bytes.Equal(first, replayed) || firstHeaders.Get("Content-Type") != replayedHeaders.Get("Content-Type") || projectionState() != after || counts() != afterCounts {
		t.Fatal("headerless conditional Delete replay duplicated withdrawal or changed command/custody/audit/outbox state")
	}
	var generation int64
	var tombstone, identityActive bool
	if err := source.pool.Raw().QueryRow(ctx, `SELECT s.generation,s.deleted_at IS NOT NULL,u.status='active'
 FROM scim.users s JOIN identity.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
 WHERE s.tenant_id=$1 AND s.resource_id=$2`, string(otpTenant), original.ID).Scan(&generation, &tombstone, &identityActive); err != nil || generation != 2 || !tombstone || !identityActive {
		t.Fatal("conditional Delete/replay lost the native tombstone or changed global identity status", err)
	}
	read, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserGet, Credential: credential, ResourceID: original.ID})
	var absent *scim.Error
	if !errors.As(err, &absent) || absent == nil || absent.StatusCode() != http.StatusNotFound || read.Status != 0 || len(read.Body) != 0 || read.ContentType != "" || read.ETag != "" || read.Location != "" {
		t.Fatal("native read still exposed the TLS-deleted User", err)
	}
	if c.HTTPManagedSCIMUsersGet != nil {
		wire, _ := call(http.MethodGet, bearer, "", http.StatusNotFound)
		var denial struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(wire, &denial) != nil || denial.Status != strconv.Itoa(http.StatusNotFound) || counts() != afterCounts || projectionState() != after {
			t.Fatal("selected HTTP Get did not observe deletion without another mutation")
		}
	}
}
