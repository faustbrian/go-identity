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
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
)

func TestReferencePostgresSCIMManagedUsersDeactivationHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, scimManagedUsersPatch: true,
		scimManagedUsersDeactivation: true,
	})
}

func proveReferenceSCIMUsersDeactivationHTTPS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource) {
	t.Helper()
	if c.HTTPManagedSCIMUsersPatch == nil || c.HTTPManagedSCIMUsersPatch.Native == nil {
		t.Fatal("standalone deactivation requires the selected Patch native owner")
	}
	profile := *c.HTTPManagedSCIMUsersPatch.Native
	native, bearer := referenceManagedUsersConnection(t, ctx, c, features, cookies, csrf, source, profile)
	credential := authentication.NewBearerCredential(bearer)
	const userName = "reference-managed-deactivation-user"
	created, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{
		Operation: scim.UserCreate, Credential: credential, IdempotencyKey: "reference-managed-deactivation-user-1",
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","active":true}`),
	})
	type userRepresentation struct {
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
	strongVersion := func(version string) bool {
		return len(version) > 2 && strings.HasPrefix(version, `"`) && strings.HasSuffix(version, `"`)
	}
	var original userRepresentation
	if err != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &original) != nil || original.ID == "" || original.Active == nil || !*original.Active || !strongVersion(string(created.ETag)) {
		t.Fatal("create an active native User with the genuinely issued bearer and strong initial ETag", err)
	}
	var userID, providerID, connectionID string
	if err := source.pool.Raw().QueryRow(ctx, `SELECT user_id,provider_id,connection_id FROM scim.users
 WHERE tenant_id=$1 AND organization_id=$2 AND resource_id=$3 AND deleted_at IS NULL`, string(otpTenant), string(source.config.Scope.OrganizationID), original.ID).Scan(&userID, &providerID, &connectionID); err != nil {
		t.Fatal("read the actual issued connection's exact native User binding", err)
	}
	authority, err := organizationpg.OrganizationAuthorityScope(otpTenant, source.config.Scope.OrganizationID, identity.UserID(userID))
	if err != nil {
		t.Fatal("select the exact organization membership authority", err)
	}
	if _, err := authoritypg.InitializeAuthority(ctx, source.pool.Raw(), authority, time.Second); err != nil {
		t.Fatal("initialize the isolated target membership authority", err)
	}
	if _, err := source.pool.Raw().Exec(ctx, `INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version)
 VALUES($1,$2,$3,'member','active',1,1)`, string(otpTenant), string(source.config.Scope.OrganizationID), userID); err != nil {
		t.Fatal("seed the isolated canonical membership at its first incarnation", err)
	}
	if _, err := source.pool.Raw().Exec(ctx, `UPDATE organization.organizations SET member_count=member_count+1,version=version+1
 WHERE tenant_id=$1 AND organization_id=$2`, string(otpTenant), string(source.config.Scope.OrganizationID)); err != nil {
		t.Fatal("align the isolated organization aggregate with its seeded membership", err)
	}
	if _, err := source.pool.Raw().Exec(ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active)
 VALUES($1,$2,$3,1,$4,$5,$6,1,true)`, string(otpTenant), string(source.config.Scope.OrganizationID), userID, providerID, connectionID, original.ID); err != nil {
		t.Fatal("seed exact current source ownership using the Reference-installed membership migration", err)
	}
	var organizationVersion, memberCount int64
	if err := source.pool.Raw().QueryRow(ctx, `SELECT version,member_count FROM organization.organizations
 WHERE tenant_id=$1 AND organization_id=$2`, string(otpTenant), string(source.config.Scope.OrganizationID)).Scan(&organizationVersion, &memberCount); err != nil {
		t.Fatal("observe the original scoped organization aggregate", err)
	}
	counts := func() [5]int {
		t.Helper()
		var got [5]int
		if err := source.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose=$2),
 (SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose=$2 AND state='committed'),
 (SELECT count(*) FROM identity.request_key_mappings m JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2),
 (SELECT count(*) FROM audit.identity_command_bindings a JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings o JOIN identity.commands c USING(command_id) WHERE c.tenant_id=$1 AND c.purpose=$2)`, string(otpTenant), string(scim.UserPatch)).Scan(&got[0], &got[1], &got[2], &got[3], &got[4]); err != nil {
			t.Fatal("observe actual Patch command, request mapping, audit and outbox effects", err)
		}
		return got
	}
	snapshot := func() string {
		t.Helper()
		var state string
		if err := source.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'projection',(SELECT to_jsonb(s) FROM scim.users s WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$4 AND connection_id=$5 AND resource_id=$6),
 'identity',(SELECT to_jsonb(u) FROM identity.users u WHERE tenant_id=$1 AND user_id=$3),
 'membership',(SELECT to_jsonb(m) FROM organization.memberships m WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),
 'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY to_jsonb(g)::text) FROM organization.directory_membership_grants g WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),
 'organization',(SELECT to_jsonb(o) FROM organization.organizations o WHERE tenant_id=$1 AND organization_id=$2),
 'authority',(SELECT to_jsonb(a) FROM authorization_subject_authorities a WHERE tenant_id=$1 AND policy_namespace=$7 AND subject_id=$8))::text`, string(otpTenant), string(source.config.Scope.OrganizationID), userID, providerID, connectionID, original.ID, authority.PolicyNamespace, string(authority.SubjectID)).Scan(&state); err != nil {
			t.Fatal("snapshot exact native, identity, source, membership, organization and authority state", err)
		}
		return state
	}
	const patch = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	call := func(body []byte) ([]byte, http.Header) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPatch, base+"/scim/v2/Users/"+original.ID, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+bearer)
		request.Header.Set("If-Match", string(created.ETag))
		request.Header.Set("Content-Type", "application/scim+json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("managed User deactivation HTTPS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || response.TLS == nil || readErr != nil || closeErr != nil || len(wire) > 8192 {
			t.Fatalf("managed deactivation TLS status %d want 200; cleanup %v/%v", response.StatusCode, readErr, closeErr)
		}
		if response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" {
			t.Fatal("managed deactivation changed SCIM media, cache or browser session custody")
		}
		secrets := []string{bearer, source.bearer.Token()}
		for _, cookie := range cookies {
			secrets = append(secrets, cookie.Value)
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(wire, []byte(secret)) {
				t.Fatal("managed deactivation disclosed credential custody")
			}
		}
		return wire, response.Header.Clone()
	}
	before, beforeCounts := snapshot(), counts()
	first, headers := call([]byte(patch))
	var deactivated userRepresentation
	etag := headers.Get("ETag")
	wantLocation := source.config.BaseURL + "/Users/" + original.ID
	if json.Unmarshal(first, &deactivated) != nil || len(deactivated.Schemas) != 1 || deactivated.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" || deactivated.ID != original.ID || deactivated.UserName != userName || deactivated.Active == nil || *deactivated.Active || deactivated.Meta.ResourceType != "User" || deactivated.Meta.Created != original.Meta.Created || deactivated.Meta.Version != etag || !strongVersion(etag) || etag == string(created.ETag) || headers.Get("Location") != wantLocation || deactivated.Meta.Location != wantLocation {
		t.Fatal("HTTPS deactivation must retain the User and creation time, set active:false and advance its strong ETag")
	}
	var generation int64
	var live, globalActive bool
	var projectionWire []byte
	if err := source.pool.Raw().QueryRow(ctx, `SELECT s.generation,s.deleted_at IS NULL,u.status='active',s.resource
 FROM scim.users s JOIN identity.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
 WHERE s.tenant_id=$1 AND s.organization_id=$2 AND s.provider_id=$3 AND s.connection_id=$4 AND s.resource_id=$5`, string(otpTenant), string(source.config.Scope.OrganizationID), providerID, connectionID, original.ID).Scan(&generation, &live, &globalActive, &projectionWire); err != nil || generation != 2 || !live || !globalActive {
		t.Fatal("deactivation must retain a live generation-two projection without disabling the core User", err)
	}
	var projection scim.Resource
	if json.Unmarshal(projectionWire, &projection) != nil || projection.ID != original.ID || projection.Version != scim.Version(etag) || projection.Attributes["active"] != false {
		t.Fatal("persisted inactive native projection must match the HTTPS resource and ETag")
	}
	var memberState, memberVersion, memberAuthority, grantVersion, authorityVersion string
	var grantActive bool
	var afterOrganizationVersion, afterMemberCount int64
	if err := source.pool.Raw().QueryRow(ctx, `SELECT m.state,m.version::text,m.authorization_version::text,g.active,g.version::text,a.version::text,o.version,o.member_count
 FROM organization.memberships m
 JOIN organization.directory_membership_grants g ON g.tenant_id=m.tenant_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id AND g.member_version=1 AND g.provider_id=$4 AND g.connection_id=$5 AND g.resource_id=$6
 JOIN organization.organizations o ON o.tenant_id=m.tenant_id AND o.organization_id=m.organization_id
 JOIN authorization_subject_authorities a ON a.tenant_id=m.tenant_id AND a.policy_namespace=$7 AND a.subject_id=$8
 WHERE m.tenant_id=$1 AND m.organization_id=$2 AND m.user_id=$3`, string(otpTenant), string(source.config.Scope.OrganizationID), userID, providerID, connectionID, original.ID, authority.PolicyNamespace, string(authority.SubjectID)).Scan(&memberState, &memberVersion, &memberAuthority, &grantActive, &grantVersion, &authorityVersion, &afterOrganizationVersion, &afterMemberCount); err != nil || memberState != "removed" || memberVersion != "2" || memberAuthority != "2" || grantActive || grantVersion != "2" || authorityVersion != "2" || afterOrganizationVersion != organizationVersion+1 || afterMemberCount != memberCount-1 {
		t.Fatal("deactivation must retire the exact current source and revoke only its final scoped membership and authority once", err)
	}
	after, afterCounts := snapshot(), counts()
	wantCounts := beforeCounts
	for i := range wantCounts {
		wantCounts[i]++
	}
	if after == before || afterCounts != wantCounts {
		t.Fatal("deactivation must commit exactly one original Patch command, mapping, audit and outbox effect", afterCounts, wantCounts)
	}
	read, err := native.ExecuteManagedProvisioning(ctx, otpTenant, scim.Request{Operation: scim.UserGet, Credential: credential, ResourceID: original.ID})
	if err != nil || read.Status != http.StatusOK || !bytes.Equal(read.Body, first) || read.ETag != scim.Version(etag) || read.Location != wantLocation {
		t.Fatal("deactivation must leave the exact inactive resource readable through the native owner", err)
	}
	var equivalent bytes.Buffer
	if err := json.Indent(&equivalent, []byte(patch), "", "  "); err != nil {
		t.Fatal(err)
	}
	replayed, replayHeaders := call(equivalent.Bytes())
	if !bytes.Equal(replayed, first) || replayHeaders.Get("Content-Type") != headers.Get("Content-Type") || replayHeaders.Get("ETag") != etag || replayHeaders.Get("Location") != wantLocation || snapshot() != after || counts() != afterCounts {
		t.Fatal("equivalent HTTPS retry with the original If-Match must preserve the exact acknowledgement without repeating any effect")
	}
}
