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
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresAPIKeyUpdateHTTPS(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "populated-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyUpgrade: upgrade, apiKeyUpdate: true, postgresBaseline: true})
		})
	}
}

func TestReferencePostgresLegacyAPIKeyUpdateHTTPS(t *testing.T) {
	for _, noExpiry := range []bool{false, true} {
		name := "finite-expiry"
		if noExpiry {
			name = "absent-expiry"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyLegacy: true, apiKeyLegacyNoExpiry: noExpiry, apiKeyUpdate: true, postgresBaseline: true})
		})
	}
}

func TestReferencePostgresOrganizationAPIKeyUpdateHTTPS(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "populated-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organizationKey: true, organizationKeyUpgrade: upgrade, organizationKeyUpdate: true, postgresBaseline: true})
		})
	}
}

type referenceUpdateReply struct {
	Committed     bool                   `json:"committed"`
	CommitOutcome string                 `json:"commitOutcome"`
	CommandID     identity.CommandID     `json:"commandID"`
	Recovery      identity.RecoveryQuery `json:"recovery"`
	Key           struct {
		referenceMetadataKey
		Version          uint64 `json:"version"`
		Name             string `json:"name"`
		AuthorityVersion uint64 `json:"authorityVersion"`
		RootVersion      uint64 `json:"rootVersion"`
	} `json:"key"`
	Error string `json:"error"`
}

// The existing genuine baseline supplies registration, verification and bearer
// credentials. Only transport selection changes; every domain owner stays real.
func proveReferenceKeyUpdate(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, workers []deliverypg.WorkerConfig, config reference.ReferenceConfig, original reference.StoreSet, features reference.FeatureSet, caller, removed apikey.Authentication, organization apikey.OrganizationID, id apikey.KeyID, raw string) {
	t.Helper()
	old, err := features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	before, err := old.Get(ctx, apikey.GetRequest{Authentication: caller, OrganizationID: organization, KeyID: id})
	if err != nil {
		t.Fatal("genuine pre-update metadata", err)
	}
	// Updating is independently selected on an already populated graph. It
	// neither installs another migration nor implicitly exposes sibling routes.
	h := *c.HTTPAPIKey
	h.Create, h.Rotate, h.Revoke, h.Get, h.List = false, false, false, false, false
	h.Update = true
	c.HTTPAPIKey = &h
	stores, current := composeReferenceAPIKeyGraph(t, c, deps, workers)
	if err := current.Initialize(ctx); err != nil {
		t.Fatal("update-only populated graph", err)
	}
	if err := original.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Update(ctx, apikey.UpdateRequest{Authentication: caller}); err == nil {
		t.Fatal("closed pre-update handle retained authority")
	}
	owner, err := current.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	newServer := func(selected reference.FeatureSet) *httptest.Server {
		t.Helper()
		server, err := reference.NewServer(config, deps, selected)
		if err != nil {
			t.Fatal("update-only actual composition", err)
		}
		for _, op := range server.OpenAPI().Operations() {
			if op.Record.OperationID == "identity.apikey.create" || op.Record.OperationID == "identity.apikey.rotate" || op.Record.OperationID == "identity.apikey.delete" {
				t.Fatal("update-only graph exposed sibling mutation")
			}
		}
		api := httptest.NewTLSServer(server.Handler())
		t.Cleanup(api.Close)
		api.Client().Timeout = 5 * time.Second
		return api
	}
	api := newServer(current)
	call := func(api *httptest.Server, key string, body map[string]any, auth apikey.Authentication) (int, referenceUpdateReply) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, api.URL+"/v1/apikey/update", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Authorization", "Bearer "+auth.Bearer.Token())
		response, err := api.Client().Do(r)
		if err != nil {
			t.Fatal("actual update HTTPS", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 131073))
		closeErr := response.Body.Close()
		var out referenceUpdateReply
		if readErr != nil || closeErr != nil || len(payload) > 131072 || json.Unmarshal(payload, &out) != nil || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || bytes.Contains(payload, []byte(`"secret"`)) || bytes.Contains(payload, []byte(`"digest"`)) || bytes.Contains(payload, []byte(raw)) || bytes.Contains(payload, []byte(auth.Bearer.Token())) {
			t.Fatal("update response custody")
		}
		return response.StatusCode, out
	}
	body := map[string]any{"keyID": id, "expectedVersion": before.Record.Version, "name": "renamed through HTTPS", "permissions": before.Record.Grant}
	if organization != "" {
		body["organizationID"] = organization
	}
	if removed.Bearer.Token() != "" {
		if status, out := call(api, "removed-creator-update", body, removed); status != 403 || out.Committed || out.Key.ID != "" {
			t.Fatal("removed creator retained update authority", status)
		}
	}
	// Native organization support does not enable unselected HTTP owner input.
	if organization != "" {
		selfConfig := c
		selfHTTP := h
		selfHTTP.OrganizationOwned = false
		selfConfig.HTTPAPIKey = &selfHTTP
		_, self := composeReferenceAPIKeyGraph(t, selfConfig, deps, workers)
		if err := self.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		if status, out := call(newServer(self), "unselected-organization-update", body, caller); status != 400 || out.Committed {
			t.Fatal("unselected organization update acquired authority", status)
		}
	}
	status, renamed := call(api, "reference-update-name-original", body, caller)
	if status != 200 || !renamed.Committed || renamed.Key.ID != id || renamed.Key.Version != before.Record.Version+1 || renamed.Key.Name != "renamed through HTTPS" || renamed.Key.AuthorityVersion != before.Record.AuthorityVersion || renamed.Key.RootVersion != before.Record.RootVersion || !slices.Equal(renamed.Key.Permissions, before.Record.Grant) || (renamed.Key.ExpiresAt == nil) != before.Record.ExpiresAt.IsZero() || renamed.Key.ExpiresAt != nil && !renamed.Key.ExpiresAt.Equal(before.Record.ExpiresAt) {
		t.Fatal("HTTPS name update changed credential authority/expiry", status, renamed.Error)
	}
	verify := func(allowed bool) {
		t.Helper()
		r := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandIDForReference(t)), TenantID: otpTenant, ConfigurationID: before.Record.ConfigurationID, ConfigurationRevision: before.Record.ConfigurationRevision, RequiredPermissions: []string{"invoice.read"}}
		if before.Record.ConfigurationID == c.APIKey.Configuration.Spec().ID {
			r.Secret, err = apikey.ParseSecret(raw)
		} else {
			r.LegacySecret, err = apikey.ParseLegacySecret(raw)
		}
		if err != nil {
			t.Fatal(err)
		}
		out, err := owner.VerifyAndConsume(ctx, r)
		if allowed && (err != nil || out.Result == nil) || !allowed && (err == nil || out.Result != nil) {
			t.Fatal("unchanged credential did not enforce updated grant", err)
		}
	}
	verify(true)
	// Reconstruct both native and HTTP owners, preserving original command and
	// actual database state rather than executing a replacement intent.
	nextStores, next := composeReferenceAPIKeyGraph(t, c, deps, workers)
	if err := next.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	stores, current = nextStores, next
	owner, err = current.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	api = newServer(current)
	if status, replay := call(api, "reference-update-name-original", body, caller); status != 200 || !replay.Committed || replay.CommandID != renamed.CommandID || replay.Key.Version != renamed.Key.Version {
		t.Fatal("restart lost original update snapshot", status)
	}
	if status, out := call(api, "stale-update-version", body, caller); status != 409 || out.Committed {
		t.Fatal("stale CAS update was admitted", status)
	}
	body["expectedVersion"] = renamed.Key.Version
	body["permissions"] = []string{"invoice.read", "invoice.write"}
	if status, out := call(api, "expanding-update-grant", body, caller); status < 400 || out.Committed || out.Key.ID != "" {
		t.Fatal("update expanded current grant", status)
	}
	body["permissions"] = []string{}
	status, narrowed := call(api, "reference-update-narrow-original", body, caller)
	if status != 200 || !narrowed.Committed || narrowed.Key.Version != renamed.Key.Version+1 || narrowed.Key.AuthorityVersion != renamed.Key.AuthorityVersion+1 || len(narrowed.Key.Permissions) != 0 || narrowed.Key.RootVersion != renamed.Key.RootVersion+1 {
		t.Fatal("HTTPS narrowing lost exact security transition", status, narrowed.Error)
	}
	verify(false)
	// A current actor can recover the original receipt without re-executing or
	// refreshing its historical result. The existing public handle owns custody.
	var recovered identity.CommandResult
	if organization != "" {
		recovered, err = owner.RecoverOrganization(ctx, organization, apikey.RecoveryRequest{Authentication: caller, Query: narrowed.Recovery})
	} else {
		recovered, err = owner.Recover(ctx, apikey.RecoveryRequest{Authentication: caller, Query: narrowed.Recovery})
	}
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding.CommandID != narrowed.CommandID {
		t.Fatal("Reference update recovery disconnected", err)
	}
	sessions, err := current.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(caller.Bearer.Token())
	credential, _ := session.NewCredential(session.CredentialBearer, token)
	command := commandIDForReference(t)
	if out, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: command, CorrelationID: string(command), Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{}); err != nil || !out.SignedOut {
		t.Fatal("update consumer logout", err)
	}
	if status, out := call(api, "reference-update-narrow-original", body, caller); status != 403 || out.Committed || out.Key.ID != "" {
		t.Fatal("logged-out actor recovered update authority", status)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := owner.Update(ctx, apikey.UpdateRequest{Authentication: caller}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed update handle reached native owner", err)
	}
}
