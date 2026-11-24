//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

const (
	referenceDirectorySCIMActor     = "reference-directory-service"
	referenceDirectorySCIMAuthority = "reference-directory-source"
)

type referenceDirectorySCIMSource struct {
	pool   *database.Pool
	config scimpostgres.Config
	keys   *keyring.Provider
	native *scimpostgres.Service
	groups *scimpostgres.GroupsService
	bearer authentication.BearerCredential
}

type referenceDirectorySCIMEdge struct {
	scope           scim.Scope
	userID, groupID string
	groupETag       scim.Version
}

// NewService and NewGroupsService perform no IO, so this configured source can
// enter ComposeStores before the operator applies the selected owner schema.
// The same graph keyring owns both fixture commands and composed ingestion.
func newReferenceDirectorySCIMSource(t *testing.T, pool *database.Pool, keys *keyring.Provider, scope scim.Scope, policy authorization.Service, policyVersion uint64, globalAuthorityID string) referenceDirectorySCIMSource {
	t.Helper()
	const policyID = "reference-directory-scim"
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: policyVersion}
	requestKeys, err := kernel.NewRequestKeyConfig(policyID, [32]byte{0xcf}, query)
	if err != nil {
		t.Fatal("configure scoped SCIM request custody", err)
	}
	bearer := authentication.NewBearerCredential("isolated-reference-scim-directory-credential-with-entropy")
	credential, err := scimpostgres.NewConfiguredCredential("reference-directory-credential", bearer, [32]byte{0xd1})
	if err != nil {
		t.Fatal("configure original SCIM credential", err)
	}
	schema := identity.AttributeSchema{ID: policyID, Version: 1}
	for _, name := range []string{"scim_user_name", "scim_display_name"} {
		schema.Fields = append(schema.Fields, identity.FieldPolicy{
			Name: name, Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar,
			Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead,
			WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1,
		})
	}
	fields, err := identity.NewAttributeProcessor(schema, policy, func(_ context.Context, _ identity.NormalizationPolicy, value identity.AttributeScalar) (identity.AttributeScalar, error) {
		return value, nil
	}, identity.AttributeProcessorConfig{
		Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: policyVersion,
		ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
			_, err := identity.ParseSubjectID(string(id))
			return err
		},
		ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil },
	})
	if err != nil {
		t.Fatal("configure SCIM native field policy", err)
	}
	config := scimpostgres.Config{
		Scope: scope, ConnectionVersion: 1, Credential: credential,
		CredentialExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		ActorID:             referenceDirectorySCIMActor, PolicyID: policyID, PolicyVersion: policyVersion,
		ConfigurationID: "reference-directory-scim-v1", Authorization: policy,
		AuthorityNamespace: referenceDirectorySCIMAuthority, GlobalAuthorityID: globalAuthorityID,
		Fields: fields, FieldSchema: schema, UserNameField: "scim_user_name", DisplayNameField: "scim_display_name",
		RequestKeys: requestKeys,
		Coordinator: kernel.CoordinatorConfig{
			MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
			CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xd3}},
			QueryPolicy: &query, AdmissionPolicy: &query,
		},
		IntentKey: [32]byte{0xd4}, ActiveEnvelopeKeyID: "issue-envelope", Limits: scim.DefaultLimits(),
		BaseURL: "https://directory.example.test/scim/v2", MaximumDuration: 3 * time.Second,
	}
	native, err := scimpostgres.NewService(pool, config, keys)
	if err != nil {
		t.Fatal("construct real configured SCIM source before composition", err)
	}
	groups, err := scimpostgres.NewGroupsService(native, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal("select real SCIM Groups source", err)
	}
	return referenceDirectorySCIMSource{pool: pool, config: config, keys: keys, native: native, groups: groups, bearer: bearer}
}

// The operator schema, deployment/tenant authorities, and genuine organization
// must already exist. These calls use their real owners; no SCIM or identity
// state is inserted by fixture SQL. Mapping to a local user/team stays explicit
// in the caller rather than being inferred from the created SCIM identifiers.
func (f referenceDirectorySCIMSource) createGroupEdge(t *testing.T, ctx context.Context) referenceDirectorySCIMEdge {
	t.Helper()
	_, err := authoritypg.InitializeAuthority(ctx, f.pool.Raw(), authoritypg.AuthorityScope{
		TenantID: authorization.TenantID(f.config.Scope.TenantID), PolicyNamespace: f.config.AuthorityNamespace,
		SubjectID: authorization.SubjectID(f.config.ActorID),
	}, time.Second)
	if err != nil {
		t.Fatal("initialize original SCIM service authority", err)
	}
	installed, err := f.native.InitializeConfiguredConnection(ctx)
	if err != nil || installed.Outcome != identity.CommitOutcomeCommitted || installed.Version != 1 {
		t.Fatal("initialize configured SCIM connection through its owner", err)
	}
	user, err := f.native.Execute(ctx, scim.Request{
		Operation: scim.UserCreate, Credential: f.bearer, ContentType: "application/scim+json",
		IdempotencyKey: "reference-directory-source-user",
		Body:           []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ReferenceDirectoryMember","displayName":"Reference directory member"}`),
	})
	if err != nil {
		t.Fatal("create real SCIM source User", err)
	}
	userID := referenceDirectorySCIMResourceID(t, user, http.StatusCreated)
	groupBody, err := json.Marshal(struct {
		Schemas     []string            `json:"schemas"`
		DisplayName string              `json:"displayName"`
		Members     []map[string]string `json:"members"`
	}{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, DisplayName: "Reference directory group",
		Members: []map[string]string{{"type": "User", "value": userID}},
	})
	if err != nil {
		t.Fatal("encode explicit source Group membership", err)
	}
	group, err := f.groups.Execute(ctx, scim.Request{
		Operation: scim.GroupCreate, Credential: f.bearer, ContentType: "application/scim+json",
		IdempotencyKey: "reference-directory-source-group", Body: groupBody,
	})
	if err != nil {
		t.Fatal("create real SCIM source Group membership", err)
	}
	groupID := referenceDirectorySCIMResourceID(t, group, http.StatusCreated)
	return referenceDirectorySCIMEdge{scope: f.config.Scope, userID: userID, groupID: groupID, groupETag: group.ETag}
}

func referenceDirectorySCIMResourceID(t *testing.T, response scim.Response, status int) string {
	t.Helper()
	var body struct {
		ID string `json:"id"`
	}
	if response.Status != status || json.Unmarshal(response.Body, &body) != nil || body.ID == "" || response.ETag == "" {
		t.Fatal("real SCIM source response lost its resource identity or version", response.Status)
	}
	return body.ID
}
