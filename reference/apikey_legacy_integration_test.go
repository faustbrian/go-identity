//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresLegacyAPIKeyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyLegacy: true, postgresBaseline: true})
}

func TestReferencePostgresLegacyNoExpiryAPIKeyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyLegacy: true, apiKeyLegacyNoExpiry: true, postgresBaseline: true})
}

func proveReferenceLegacyAPIKey(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, workers []deliverypg.WorkerConfig, config reference.ReferenceConfig, originalStores reference.StoreSet, originalFeatures reference.FeatureSet, caller apikey.Authentication, user identity.UserID, noExpiry bool) {
	t.Helper()
	key := func(label string) identity.IdempotencyKey {
		t.Helper()
		k, err := identity.NewIdempotencyKey([]byte(label))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	original, err := originalFeatures.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	modern, err := original.Create(ctx, apikey.CreateRequest{Authentication: caller, IdempotencyKey: key("reference-prelegacy-modern"), Name: "existing modern key", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "127.0.0.1"})
	if err != nil {
		t.Fatal("populate modern credential before legacy selection", err)
	}
	modernWire, err := modern.Reveal()
	if err != nil {
		t.Fatal("original modern reveal unavailable")
	}
	var installed bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity_api_keys.legacy_imports') IS NOT NULL`).Scan(&installed); err != nil || installed {
		t.Fatal("modern-only graph installed unselected legacy history", err)
	}
	spec := c.APIKey.Configuration.Spec()
	spec.ID, spec.Algorithm, spec.State = "reference-legacy", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
	spec.AllowLegacyNoExpiry = noExpiry
	legacy, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	selected := *c.APIKey
	selected.LegacyConfiguration = legacy
	selected.ValidateCanonicalKeyID = func(ctx context.Context, id apikey.KeyID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if id != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
			return apikey.ErrInvalid
		}
		return nil
	}
	c.APIKey = &selected
	invalid := c
	missingPolicy := selected
	missingPolicy.ValidateCanonicalKeyID = nil
	invalid.APIKey = &missingPolicy
	if bad, err := reference.ComposeStores(invalid, deps); err == nil {
		_ = bad.Close(ctx)
		t.Fatal("Reference selected legacy profile without canonical-ID policy")
	}
	stores, features := composeReferenceAPIKeyGraph(t, c, deps, workers)
	owner, err := features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := owner.Import(ctx, apikey.ImportRequest{Authentication: caller}); !errors.As(err, &unavailable) {
		t.Fatal("uninitialized graph reached native import")
	}
	request := applyRequest(t, ctx, stores, []reference.ModuleID{"identity/apikey/postgres"})
	if len(request.Plan.Steps) == 0 {
		t.Fatal("legacy selection produced no additive owned migration")
	}
	request.CommandID, request.IdempotencyKey = "migration_apikey_legacy_0001", key("reference-legacy-migration")
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("legacy populated operator migration", err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("legacy configuration initialization", err)
	}
	verify := func(configuration apikey.Configuration, raw string, allow bool) apikey.AtomicVerificationResult {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		r := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(id), TenantID: otpTenant, ConfigurationID: configuration.Spec().ID, ConfigurationRevision: configuration.Spec().Revision, RequiredPermissions: []string{"invoice.read"}}
		if configuration.Spec().Algorithm == apikey.AlgorithmLegacySHA256V1 {
			r.LegacySecret, err = apikey.ParseLegacySecret(raw)
		} else {
			r.Secret, err = apikey.ParseSecret(raw)
		}
		if err != nil {
			t.Fatal("invalid consumer credential")
		}
		out, err := owner.VerifyAndConsume(ctx, r)
		if allow {
			if err != nil || out.Result == nil || out.Result.ValidateAt(configuration, time.Now()) != nil || out.Result.Owner.Spec().UserID != user {
				t.Fatal("Reference credential lost current owner authority", err)
			}
		} else if err == nil || out.Result != nil {
			t.Fatal("Reference credential denial failed")
		}
		return out
	}
	verify(c.APIKey.Configuration, modernWire, true)
	directory, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: otpTenant, UserID: user})
	if err != nil {
		t.Fatal(err)
	}
	credentialOwner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: otpTenant, Kind: apikey.OwnerUser, UserID: user, Version: status.AuthorityVersion})
	if err != nil {
		t.Fatal(err)
	}
	canonical := apikey.KeyID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	rawID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	raw := "reference-bare-" + string(rawID)
	digest, _ := apikey.NewLegacyDigest(sha256.Sum256([]byte(raw)))
	record := apikey.Record{ID: canonical, Owner: credentialOwner, Version: 3, AuthorityVersion: 2, ConfigurationID: spec.ID, ConfigurationRevision: spec.Revision, Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: time.Now().UTC().Add(-500 * 24 * time.Hour).Truncate(time.Microsecond), ExpiresAt: time.Now().UTC().Add(500 * 24 * time.Hour).Truncate(time.Microsecond), RootID: canonical, RootVersion: 2, Issuer: spec.Issuer, Environment: spec.Environment, Audience: spec.Audience}
	if noExpiry {
		record.ExpiresAt = time.Time{}
	}
	input := apikey.ImportRequest{Authentication: caller, IdempotencyKey: key("reference-legacy-import"), Record: record, Digest: digest, SourceID: "reference-import-source", SourceVersion: 7, Network: "127.0.0.1"}
	imported, err := owner.Import(ctx, input)
	if err != nil || imported.Outcome != identity.CommitOutcomeCommitted || imported.Binding.RecordID != string(canonical) {
		t.Fatal("Reference digest-only import", err)
	}
	verified := verify(legacy, raw, true)
	if verified.Result.Record.Version != 3 || !verified.Result.Record.CreatedAt.Equal(record.CreatedAt) || !verified.Result.Record.ExpiresAt.Equal(record.ExpiresAt) {
		t.Fatal("Reference import changed historical metadata")
	}
	verify(legacy, raw+"-wrong", false)
	nextStores, nextFeatures := composeReferenceAPIKeyGraph(t, c, deps, workers)
	if err := nextFeatures.Initialize(ctx); err != nil {
		t.Fatal("legacy graph reconstruction", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	stores, features = nextStores, nextFeatures
	if _, err := owner.Import(ctx, input); !errors.As(err, &unavailable) {
		t.Fatal("closed legacy handle retained import authority")
	}
	owner, err = features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := owner.Import(ctx, input); err != nil || repeated.Binding != imported.Binding || repeated.Outcome != imported.Outcome {
		t.Fatal("reconstructed legacy graph changed original import", err)
	}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range server.OpenAPI().Operations() {
		if op.Record.OperationID == "identity.apikey.import" {
			t.Fatal("native legacy selection invented a public import route")
		}
	}
	api := httptest.NewTLSServer(server.Handler())
	t.Cleanup(api.Close)
	client := api.Client()
	client.Timeout = 5 * time.Second
	type reply struct {
		Committed bool   `json:"committed"`
		Secret    string `json:"secret"`
		Key       struct {
			ID      apikey.KeyID `json:"id"`
			Version uint64       `json:"version"`
		} `json:"key"`
	}
	call := func(operation string, id apikey.KeyID, version uint64) reply {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"keyID": id, "expectedVersion": version})
		r, err := http.NewRequestWithContext(ctx, "POST", api.URL+"/v1/apikey/"+operation, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "reference-legacy-"+operation)
		r.Header.Set("Authorization", "Bearer "+caller.Bearer.Token())
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 131073))
		closeErr := response.Body.Close()
		var out reply
		if readErr != nil || closeErr != nil || len(wire) > 131072 || json.Unmarshal(wire, &out) != nil || response.StatusCode != 200 || !out.Committed || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || bytes.Contains(wire, []byte(raw)) || bytes.Contains(wire, []byte(caller.Bearer.Token())) {
			t.Fatal("legacy HTTP lifecycle failed or disclosed retained custody", response.StatusCode)
		}
		return out
	}
	rotated := call("rotate", canonical, 3)
	if rotated.Secret == "" || rotated.Key.ID == canonical {
		t.Fatal("legacy HTTP rotation did not create a distinct modern successor")
	}
	verify(legacy, raw, false)
	successor := verify(c.APIKey.Configuration, rotated.Secret, true)
	if !successor.Result.Record.ExpiresAt.Equal(successor.Result.Record.CreatedAt.Add(c.APIKey.Configuration.Spec().MaximumLifetime)) || !record.ExpiresAt.IsZero() && successor.Result.Record.ExpiresAt.After(record.ExpiresAt) {
		t.Fatal("legacy HTTP successor expanded original or modern expiry")
	}
	if revoked := call("delete", rotated.Key.ID, rotated.Key.Version); revoked.Secret != "" {
		t.Fatal("legacy successor revocation disclosed material")
	}
	verify(c.APIKey.Configuration, rotated.Secret, false)
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(caller.Bearer.Token())
	if err != nil {
		t.Fatal("genuine bearer token malformed")
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	signoutID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: signoutID, CorrelationID: string(signoutID), Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{}); err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("legacy workflow bearer logout", err)
	}
	if out, err := owner.Import(ctx, input); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("logged-out session recovered legacy management authority")
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_api_keys.configurations SET enabled=false WHERE tenant_id=$1 AND configuration_id=$2`, otpTenant, spec.ID); err != nil {
		t.Fatal(err)
	}
	_, disabled := composeReferenceAPIKeyGraph(t, c, deps, workers)
	if err := disabled.Initialize(ctx); err == nil {
		t.Fatal("reconstructed graph reset disabled legacy authority")
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT enabled FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2`, otpTenant, spec.ID).Scan(&installed); err != nil || installed {
		t.Fatal("startup revived disabled legacy configuration", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := originalStores.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
