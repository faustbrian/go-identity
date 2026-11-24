//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const referenceDirectoryOrganization = "AAAAAAAAAAAAAAAAAAAAMA"
const referenceDirectoryProvider = "reference-directory-provider"

// Registration, verification delivery and password sign-in supply the real
// browser session. Only pre-existing provider metadata is fixture-owned.
func TestReferencePostgresDirectorySyncHTTPS(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		name := "shared-organization-rate"
		if standalone {
			name = "standalone-directory-rate"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, directorySync: true, directorySyncStandalone: standalone})
		})
	}
}

type referenceDirectoryPolicy struct{}

func (referenceDirectoryPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(d.Request.Tenant) == otpTenant && d.PolicyRevision == 9 && d.Request.Subject.Kind == authorization.SubjectUser {
		switch d.Request.Action {
		case "org:sso-read", "org:sso-write":
			if d.Request.Resource.Type == "organization" && d.Request.Resource.ID == referenceDirectoryOrganization {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.sso.directory-sync-start", "identity.sso.directory-sync-start.recover", "identity.sso.directory-sync-cancel", "identity.sso.directory-sync-cancel.recover":
			if d.Request.Resource.Type == "identity.user" && string(d.Request.Resource.ID) == string(d.Request.Subject.ID) ||
				d.Request.Resource.Type == "identity.request-admission" && string(d.Request.Resource.ID) == string(d.Request.Action) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	return (referenceOrganizationPolicy{}).Decide(ctx, d)
}

func (p referenceDirectoryPolicy) ObserveDirectorySyncAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	decision, err := p.Decide(ctx, d)
	return ssopg.ProviderUpdateAuthorizationEvidence{Context: d.Clone(), Decision: decision, ActorAuthorizationVersion: version, ValidUntil: d.Request.Environment.Time.Add(15 * time.Second)}, err
}

func configureReferenceDirectorySync(t *testing.T, c *reference.StoreConfiguration, origin string, standalone bool) {
	t.Helper()
	c.Organization.SelectOrganizationID = func(ctx context.Context) (organization.ID, error) {
		return referenceDirectoryOrganization, ctx.Err()
	}
	c.DirectorySync = &reference.DirectorySyncConfiguration{TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization,
		ConnectionID: "reference-directory-source", PolicyID: "reference-directory", KeyReference: "issue-envelope", Authorization: referenceDirectoryPolicy{}}
	c.HTTPDirectorySync = &reference.HTTPDirectorySyncConfiguration{Origins: []identityhttp.Origin{identityhttp.Origin(origin)}}
	if standalone {
		rate := c.HTTPOrganization
		c.HTTPDirectorySync.Rate = &reference.DirectorySyncHTTPRateConfiguration{
			SafeNamespace: rate.SafeNamespace, AdminNamespace: rate.AdminNamespace, EmergencyMaximumKeys: rate.EmergencyMaximumKeys,
			AdminKey: rate.AdminKey, Degraded: rate.Degraded, Denied: rate.Denied,
		}
		c.HTTPOrganization = nil
	}
}

type referenceDirectoryProjection struct {
	GenerationID           identity.CommandID `json:"generationID"`
	ProviderID             string             `json:"providerID"`
	MappingVersion         uint64             `json:"mappingVersion"`
	Mode                   string             `json:"mode"`
	Version                uint64             `json:"version"`
	State                  string             `json:"state"`
	ReadCount              uint64             `json:"readCount"`
	AppliedCount           uint64             `json:"appliedCount"`
	RejectedCount          uint64             `json:"rejectedCount"`
	Checkpoint             string             `json:"checkpoint"`
	Stopped                bool               `json:"stopped"`
	ReconciliationRequired bool               `json:"reconciliationRequired"`
	Completion             struct {
		CommandID identity.CommandID `json:"commandID"`
		Outcome   string             `json:"outcome"`
	} `json:"completion"`
}

func proveReferenceDirectorySyncHTTPS(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, cookies []*http.Cookie, csrf string, standalone bool, callerConfig kernel.CoordinatorConfig) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil || len(cookies) != 1 || csrf == "" {
		t.Fatal("directory journey requires the genuinely signed-in browser")
	}
	human := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	call := func(method, path, body, key string, browser bool, want int, mutate ...func(*http.Request)) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		if browser {
			request.AddCookie(cookies[0])
			if method == http.MethodPost {
				request.Header.Set("Origin", origin)
				request.Header.Set("X-CSRF-Token", csrf)
			}
		} else {
			request.Header.Set("Authorization", "Bearer "+human.auth.Bearer.Token())
		}
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		for _, change := range mutate {
			change(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("directory HTTPS request failed", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(wire) > 16384 || response.StatusCode != want {
			t.Fatalf("directory HTTPS %s %s: status %d, want %d; response cleanup %v/%v", method, path, response.StatusCode, want, readErr, closeErr)
		}
		if want == http.StatusOK && (response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || bytes.Contains(wire, []byte(cookies[0].Value)) || bytes.Contains(wire, []byte(csrf))) {
			t.Fatal("directory response exposed or replaced browser custody")
		}
		return wire
	}
	if standalone {
		organizations, err := features.Organizations()
		if err != nil {
			t.Fatal("selected native directory organization owner", err)
		}
		key, err := identity.NewIdempotencyKey([]byte("reference-directory-create-organization"))
		if err != nil {
			t.Fatal(err)
		}
		created, err := organizations.Create(ctx, organization.CreateOperationRequest{Authentication: human.auth, IdempotencyKey: key,
			Name: "Directory test", Slug: "directory-test", CorrelationID: "reference-directory-setup"}, "127.0.0.1")
		if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted || created.OrganizationID != referenceDirectoryOrganization {
			t.Fatal("directory selected organization was not created by its genuine native owner", err)
		}
		call(http.MethodPost, "/v1/organization/create", `{"name":"Directory test","slug":"directory-test"}`, "reference-directory-create-organization", false, 404)
	} else {
		created := call(http.MethodPost, "/v1/organization/create", `{"name":"Directory test","slug":"directory-test"}`, "reference-directory-create-organization", false, 200)
		var org organizationhttp.MutationResponse
		if json.Unmarshal(created, &org) != nil || !org.Committed || org.OrganizationID != referenceDirectoryOrganization {
			t.Fatal("directory selected organization was not created by its genuine owner")
		}
	}
	// This fixture represents an already installed provider. It does not forge
	// directory generations, command receipts, source grants, or session state.
	_, err = f.pool.Raw().Exec(ctx, `INSERT INTO sso_providers.providers
	(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,
	metadata_version,metadata_configuration_envelope,metadata_mapping_version,enabled,enablement_proof,enablement_credential_generation)
	VALUES ($1,$2,$3,$4,$5,1,1,3,$5,2,true,$5,1)`, otpTenant, referenceDirectoryOrganization, referenceDirectoryProvider, bytes.Repeat([]byte{0x41}, 32), []byte("installed-provider-fixture"))
	if err != nil {
		t.Fatal("install exact existing provider metadata", err)
	}
	decode := func(wire []byte) referenceDirectoryProjection {
		t.Helper()
		var out referenceDirectoryProjection
		if json.Unmarshal(wire, &out) != nil || out.GenerationID == "" {
			t.Fatal("directory response lost its safe native generation")
		}
		return out
	}
	const start = `{"providerID":"reference-directory-provider","providerVersion":3,"mappingVersion":2,"mode":"apply"}`
	const key = "reference-directory-original-start"
	call(http.MethodPost, "/v1/sso/directory-sync-apply", `{}`, "", true, 404)
	call(http.MethodPost, "/v1/sso/directory-sync-start", start, key, true, 403, func(r *http.Request) { r.Header.Del("X-CSRF-Token") })
	wrongCSRF, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	wrongWire, err := wrongCSRF.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	call(http.MethodPost, "/v1/sso/directory-sync-start", start, key, true, 403, func(r *http.Request) { r.Header.Set("X-CSRF-Token", wrongWire) })
	call(http.MethodPost, "/v1/sso/directory-sync-start", start, key, true, 403, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") })
	call(http.MethodPost, "/v1/sso/directory-sync-start", start, key, true, 403, func(r *http.Request) { r.Header.Del("Cookie") })
	call(http.MethodPost, "/v1/sso/directory-sync-start", `{"providerID":"foreign-provider","providerVersion":3,"mappingVersion":2,"mode":"apply"}`, "reference-directory-foreign-provider", true, 403)
	call(http.MethodPost, "/v1/sso/directory-sync-start", `{"providerID":"reference-directory-provider","providerVersion":2,"mappingVersion":2,"mode":"apply"}`, "reference-directory-stale-provider", true, 403)
	first := decode(call(http.MethodPost, "/v1/sso/directory-sync-start", start, key, true, 200))
	if first.ProviderID != referenceDirectoryProvider || first.MappingVersion != 2 || first.Mode != "apply" || first.Completion.CommandID != first.GenerationID || first.Completion.Outcome != "committed" {
		t.Fatal("directory start did not expose the committed native generation")
	}
	charges := func(operation string) int {
		t.Helper()
		var value int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT COALESCE(sum(value),0)::integer FROM risk_store.counter_windows
		WHERE tenant_id=$1 AND operation=$2 AND dimension='target_or_resource'`, otpTenant, operation).Scan(&value); err != nil || value == 0 {
			t.Fatal("native directory command did not reserve its protected resource counter", err)
		}
		return value
	}
	startCharges := charges("identity.sso.directory-sync-start")
	repeat := func() referenceDirectoryProjection {
		// ComposeStores owns retained key custody. Editing the caller's map
		// after setup must not remove the original key from the live graph.
		version := callerConfig.CurrentFingerprintKeyVersion
		original, ok := callerConfig.RetainedFingerprintKeys[version]
		if !ok {
			t.Fatal("missing caller fingerprint key fixture")
		}
		delete(callerConfig.RetainedFingerprintKeys, version)
		defer func() { callerConfig.RetainedFingerprintKeys[version] = original }()
		return decode(call(http.MethodPost, "/v1/sso/directory-sync-start", start, key, true, 200))
	}()
	if repeat != first || charges("identity.sso.directory-sync-start") != startCharges {
		t.Fatal("exact directory start retry replaced original command custody")
	}
	statusPath := "/v1/sso/directory-sync-status?generationID=" + string(first.GenerationID)
	running := decode(call(http.MethodGet, statusPath, "", "", true, 200))
	checkpoint, err := base64.RawURLEncoding.DecodeString(running.Checkpoint)
	if err != nil || len(checkpoint) != 32 || bytes.Equal(checkpoint, make([]byte, 32)) || running.Version != 1 || running.State != "running" || running.ReadCount != 0 || running.AppliedCount != 0 || running.RejectedCount != 0 || running.ReconciliationRequired {
		t.Fatal("current native directory status did not retain the initial bounded state")
	}
	foreign, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	call(http.MethodGet, "/v1/sso/directory-sync-status?generationID="+string(foreign), "", "", true, 403)
	call(http.MethodPost, "/v1/sso/directory-sync-cancel", `{"generationID":"`+string(first.GenerationID)+`","expectedVersion":2}`, "", true, 409)
	cancel := `{"generationID":"` + string(first.GenerationID) + `","expectedVersion":1}`
	call(http.MethodPost, "/v1/sso/directory-sync-cancel", cancel, "forbidden-cancel-key", true, 400)
	canceled := decode(call(http.MethodPost, "/v1/sso/directory-sync-cancel", cancel, "", true, 200))
	if !canceled.Stopped || canceled.State != "canceled" || canceled.ReconciliationRequired || canceled.Checkpoint != running.Checkpoint || canceled.Completion.Outcome != "committed" {
		t.Fatal("keyless cancellation did not stop the actual native generation")
	}
	cancelCharges := charges("identity.sso.directory-sync-cancel")
	if repeated := decode(call(http.MethodPost, "/v1/sso/directory-sync-cancel", cancel, "", true, 200)); repeated != canceled || charges("identity.sso.directory-sync-cancel") != cancelCharges {
		t.Fatal("keyless cancellation did not replay the original cancellation")
	}
	final := decode(call(http.MethodGet, statusPath, "", "", true, 200))
	if final.State != "canceled" || final.Version != 2 || final.Checkpoint != running.Checkpoint || final.ReadCount != 0 || final.AppliedCount != 0 || final.RejectedCount != 0 || final.ReconciliationRequired {
		t.Fatal("final directory status did not read persisted cancellation")
	}
	var generations, starts, cancellations, startEvents, cancellationEvents int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
	(SELECT count(*) FROM sso_providers.directory_sync_generations WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id='reference-directory-source' AND state='canceled' AND version=2),
	(SELECT count(*) FROM audit.records WHERE action='identity.sso.directory-sync-start' AND outcome=1),
	(SELECT count(*) FROM audit.records WHERE action='identity.sso.directory-sync-cancel' AND outcome=1),
	(SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.started.v1'),
	(SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.cancellation_requested.v1')`, otpTenant, referenceDirectoryOrganization, referenceDirectoryProvider).Scan(&generations, &starts, &cancellations, &startEvents, &cancellationEvents); err != nil || generations != 1 || starts != 1 || cancellations != 1 || startEvents != 1 || cancellationEvents != 1 {
		t.Fatal("directory retries duplicated or lost real protected effects", generations, starts, cancellations, startEvents, cancellationEvents, err)
	}
}
