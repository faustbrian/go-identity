//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

func TestReferencePostgresAPIKeyMetadataHTTPS(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "populated-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyUpgrade: upgrade, apiKeyMetadata: true, postgresBaseline: true})
		})
	}
}

func TestReferencePostgresOrganizationAPIKeyMetadataHTTPS(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "populated-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organizationKey: true, organizationKeyUpgrade: upgrade, organizationKeyMetadata: true, postgresBaseline: true})
		})
	}
}

func TestReferencePostgresLegacyAPIKeyMetadataHTTPS(t *testing.T) {
	for _, noExpiry := range []bool{false, true} {
		name := "finite-expiry"
		if noExpiry {
			name = "absent-expiry"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyLegacy: true, apiKeyLegacyNoExpiry: noExpiry, apiKeyMetadata: true, postgresBaseline: true})
		})
	}
}

func proveReferenceOrganizationMetadata(t *testing.T, ctx context.Context, f liveStores, api *httptest.Server, org organization.ID, id apikey.KeyID, removed, current apikey.Authentication) {
	t.Helper()
	stored := func() []byte {
		t.Helper()
		var record []byte
		if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, otpTenant, string(id)).Scan(&record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	before := stored()
	target := "organizationID=" + url.QueryEscape(string(org))
	get := "/v1/apikey/get?" + target + "&keyID=" + url.QueryEscape(string(id))
	if status, out := referenceMetadataHTTPS(t, ctx, api, get, removed.Bearer.Token()); status != 403 || out.Key.ID != "" {
		t.Fatal("removed creator retained organization metadata access", status)
	}
	if status, out := referenceMetadataHTTPS(t, ctx, api, get, current.Bearer.Token()); status != 200 || out.Key.ID != id || out.Key.Owner.Kind != "organization" || out.Key.Owner.OrganizationID != apikey.OrganizationID(org) || out.Key.Owner.UserID != "" {
		t.Fatal("surviving owner could not read independent organization key", status, out.Error)
	}
	if status, out := referenceMetadataHTTPS(t, ctx, api, "/v1/apikey/list?"+target+"&limit=1", current.Bearer.Token()); status != 200 || len(out.Keys) != 1 || out.Keys[0].ID != id || out.NextCursor != "" {
		t.Fatal("organization metadata page lost owner scope", status, out.Error)
	}
	if status, out := referenceMetadataHTTPS(t, ctx, api, "/v1/apikey/get?keyID="+string(id), current.Bearer.Token()); status != 403 || out.Key.ID != "" {
		t.Fatal("self metadata acquired implicit organization target", status)
	}
	if !bytes.Equal(stored(), before) {
		t.Fatal("organization metadata mutated key authority")
	}
}

// Reuse the real registration, verification and bearer issuer. Add metadata
// only after durable keys exist so migration cannot substitute fresh fixtures
// for preservation of existing credential state.
func proveReferenceAPIKeyMetadata(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, workers []deliverypg.WorkerConfig, config reference.ReferenceConfig, original reference.StoreSet, features reference.FeatureSet, caller apikey.Authentication) {
	t.Helper()
	owner, err := features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	var ids []apikey.KeyID
	for _, label := range []string{"first", "second"} {
		key, _ := identity.NewIdempotencyKey([]byte("metadata-populate-" + label))
		issued, err := owner.Create(ctx, apikey.CreateRequest{Authentication: caller, IdempotencyKey: key, Name: label, Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "127.0.0.1"})
		if err != nil {
			t.Fatal("populate actual metadata key", err)
		}
		record, committed := issued.Record()
		if !committed {
			t.Fatal("metadata seed did not commit")
		}
		ids = append(ids, record.ID)
	}
	slices.Sort(ids)
	revocationKey, err := identity.NewIdempotencyKey([]byte("metadata-populate-revoked"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Revoke(ctx, apikey.Revocation{Authentication: caller, IdempotencyKey: revocationKey, KeyID: ids[1], ExpectedVersion: 1, Network: "127.0.0.1"}); err != nil {
		t.Fatal("populate terminal metadata", err)
	}
	if got, err := owner.Get(ctx, apikey.GetRequest{Authentication: caller, KeyID: ids[0]}); err != nil || got.Record.ID != ids[0] {
		t.Fatal("exact native lookup required unselected paging schema", err)
	}
	if got, err := owner.List(ctx, apikey.ListRequest{Authentication: caller, Limit: 1}); !errors.Is(err, identity.UnavailableError{}) || len(got.Records) != 0 {
		t.Fatal("unselected native paging silently scanned", err)
	}
	keyState := func() string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(k) ORDER BY key_id)::text,'[]') FROM identity_api_keys.keys k`).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := keyState()
	invalid := c
	invalid.HTTPAPIKey = &reference.HTTPAPIKeyConfiguration{List: true}
	if graph, err := reference.ComposeStores(invalid, deps); err == nil {
		_ = graph.Close(ctx)
		t.Fatal("HTTP list accepted missing explicit paging selection")
	}
	selected := *c.APIKey
	selected.MetadataPaging = true
	c.APIKey = &selected
	c.HTTPAPIKey = &reference.HTTPAPIKeyConfiguration{Get: true, List: true}
	conflicting := *c.HTTPAPIKey
	conflicting.StandaloneRate = &reference.APIKeyMetadataRateConfiguration{Namespace: "competing-safe", EmergencyMaximumKeys: 32, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }}
	invalid = c
	invalid.HTTPAPIKey = &conflicting
	if graph, err := reference.ComposeStores(invalid, deps); err == nil {
		_ = graph.Close(ctx)
		t.Fatal("metadata created a second emergency budget beside session reads")
	}
	stores, current := composeReferenceAPIKeyGraph(t, c, deps, workers)
	request := applyRequest(t, ctx, stores, []reference.ModuleID{"identity/apikey/postgres"})
	if len(request.Plan.Steps) == 0 {
		t.Fatal("selected paging produced no additive migration")
	}
	request.CommandID = "migration_apikey_metadata_0001"
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("reference-metadata-migration"))
	for range 2 {
		out, err := stores.ReferenceMigrationApply(ctx, request)
		if err != nil || out.Result.State() != reference.MigrationApplied || keyState() != before {
			t.Fatal("paging migration changed durable keys", err)
		}
	}
	if err := current.Initialize(ctx); err != nil {
		t.Fatal("metadata selected startup", err)
	}
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	newAPI := func(features reference.FeatureSet) *httptest.Server {
		t.Helper()
		server, err := reference.NewServer(config, deps, features)
		if err != nil {
			t.Fatal("metadata actual HTTP composition", err)
		}
		for _, op := range server.OpenAPI().Operations() {
			if op.Record.OperationID == "identity.apikey.create" || op.Record.OperationID == "identity.apikey.rotate" || op.Record.OperationID == "identity.apikey.delete" {
				t.Fatal("read-only metadata advertised mutation")
			}
		}
		api := httptest.NewTLSServer(server.Handler())
		t.Cleanup(api.Close)
		return api
	}
	api := newAPI(current)
	read := func(path, bearer string) (int, referenceMetadataReply) {
		t.Helper()
		return referenceMetadataHTTPS(t, ctx, api, path, bearer)
	}
	if status, out := read("/v1/apikey/get?keyID="+url.QueryEscape(string(ids[0])), caller.Bearer.Token()); status != 200 || out.Key.ID != ids[0] || !slices.Equal(out.Key.Permissions, []string{"invoice.read"}) {
		t.Fatal("real metadata get", status, out.Error)
	}
	status, first := read("/v1/apikey/list?limit=1", caller.Bearer.Token())
	if status != 200 || len(first.Keys) != 1 || first.Keys[0].ID != ids[0] || first.NextCursor == "" {
		t.Fatal("real first metadata page", status, first.Error)
	}
	// A scoped position survives reconstruction, but the new graph must repeat
	// real session and owner authorization before returning the next record.
	// This graph selects no other safe HTTP reader: explicit standalone policy
	// must supply the same canonical budget without requiring session routes.
	sharedPolicy := *c.HTTPSession
	c.HTTPSession = nil
	standalone := *c.HTTPAPIKey
	standalone.StandaloneRate = &reference.APIKeyMetadataRateConfiguration{Namespace: sharedPolicy.RateNamespace, EmergencyMaximumKeys: sharedPolicy.EmergencyMaximumKeys, Degraded: sharedPolicy.Degraded}
	c.HTTPAPIKey = &standalone
	nextStores, next := composeReferenceAPIKeyGraph(t, c, deps, workers)
	if err := next.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	stores, current, api = nextStores, next, newAPI(next)
	if status, out := read("/v1/apikey/list?limit=1&cursor="+url.QueryEscape(first.NextCursor), caller.Bearer.Token()); status != 200 || len(out.Keys) != 1 || out.Keys[0].ID != ids[1] || out.Keys[0].Status != "revoked" || out.NextCursor != "" {
		t.Fatal("reconstructed metadata continuation", status, out.Error)
	}
	if status, out := read("/v1/apikey/list?limit=1", ""); status == 200 || len(out.Keys) != 0 {
		t.Fatal("anonymous metadata read acquired authority")
	}
	for _, path := range []string{"/v1/apikey/get?keyID=" + string(ids[0]) + "&userID=other", "/v1/apikey/list?limit=01", "/v1/apikey/list?limit=1&cursor=invalid"} {
		if status, out := read(path, caller.Bearer.Token()); status == 200 || out.Key.ID != "" || len(out.Keys) != 0 {
			t.Fatal("invalid metadata query returned data")
		}
	}
	if keyState() != before {
		t.Fatal("metadata reads mutated key state")
	}
	sessions, err := current.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(caller.Bearer.Token())
	credential, _ := session.NewCredential(session.CredentialBearer, token)
	command, _ := identity.NewCommandID()
	out, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: command, CorrelationID: string(command), Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
	if err != nil || !out.SignedOut {
		t.Fatal("metadata bearer logout", err)
	}
	if status, out := read("/v1/apikey/list?limit=1", caller.Bearer.Token()); status == 200 || len(out.Keys) != 0 {
		t.Fatal("logged-out metadata caller retained authority")
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if status, out := read("/v1/apikey/get?keyID="+string(ids[0]), caller.Bearer.Token()); status == 200 || out.Key.ID != "" {
		t.Fatal("closed metadata graph remained usable")
	}
}

type referenceMetadataKey struct {
	ID          apikey.KeyID `json:"id"`
	Status      string       `json:"status"`
	Permissions []string     `json:"permissions"`
	ExpiresAt   *time.Time   `json:"expiresAt"`
	Owner       struct {
		Kind           string                `json:"kind"`
		UserID         identity.UserID       `json:"userID"`
		OrganizationID apikey.OrganizationID `json:"organizationID"`
	} `json:"owner"`
}
type referenceMetadataReply struct {
	Key        referenceMetadataKey   `json:"key"`
	Keys       []referenceMetadataKey `json:"keys"`
	NextCursor string                 `json:"nextCursor"`
	Error      string                 `json:"error"`
}

func referenceMetadataHTTPS(t *testing.T, ctx context.Context, api *httptest.Server, path, bearer string) (int, referenceMetadataReply) {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, "GET", api.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := api.Client().Do(r)
	if err != nil {
		t.Fatal("metadata HTTPS", err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 131073))
	closeErr := response.Body.Close()
	var out referenceMetadataReply
	if readErr != nil || closeErr != nil || len(payload) > 131072 || json.Unmarshal(payload, &out) != nil || len(response.Cookies()) != 0 || response.Header.Get("Cache-Control") != "no-store" || bearer != "" && bytes.Contains(payload, []byte(bearer)) || bytes.Contains(payload, []byte(`"digest"`)) || bytes.Contains(payload, []byte(`"secret"`)) {
		t.Fatal("metadata response custody")
	}
	return response.StatusCode, out
}
