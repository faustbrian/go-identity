//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const referenceDirectoryOrganization = "AAAAAAAAAAAAAAAAAAAAMA"
const referenceDirectoryProvider = "reference-directory-provider"
const referenceDirectoryConnection = "reference-directory-source"

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

func TestReferencePostgresDirectoryGroupApplyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, directorySync: true, directorySyncStandalone: true, directoryGroupApply: true,
	})
}

type referenceDirectoryPolicy struct{}

type referenceDirectorySCIMPolicy struct{}

func (referenceDirectorySCIMPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	if ctx.Err() != nil || d.Validate() != nil {
		return authorization.Decision{}, authorization.ErrDecisionUnavailable
	}
	outcome := authorization.Deny
	if d.PolicyRevision == 9 && d.Request.Tenant == otpTenant && d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == referenceDirectorySCIMActor {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: d.PolicyRevision}, nil
}

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
	if d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == referenceDirectorySCIMActor &&
		d.Request.Tenant == otpTenant && d.PolicyRevision == 9 {
		switch d.Request.Action {
		case "identity.sso.directory-sync-apply", "identity.sso.directory-sync-apply-role", "identity.sso.directory-sync-apply-mixed", authorization.Action(sso.DirectoryTeamMembershipOperation().OperationID),
			authorization.Action(sso.DirectoryUserAdmissionOperation().OperationID), authorization.Action(sso.DirectoryUserDeprovisionOperation().OperationID):
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		case "identity.sso.directory-sync-inspect-drift":
			if d.Request.Resource.Type == "sso.directory-generation" {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.sso.directory-sync-inspect-user-drift":
			if d.Request.Resource.Type == "sso.directory-generation" {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.sso.directory-sync-inspect-role-drift":
			if d.Request.Resource.Type == "sso.directory-generation" {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	return (referenceOrganizationRolesPolicy{}).Decide(ctx, d)
}

func (p referenceDirectoryPolicy) ObserveDirectorySyncAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	decision, err := p.Decide(ctx, d)
	return ssopg.ProviderUpdateAuthorizationEvidence{Context: d.Clone(), Decision: decision, ActorAuthorizationVersion: version, ValidUntil: d.Request.Environment.Time.Add(15 * time.Second)}, err
}

func (p referenceDirectoryPolicy) ObserveDirectoryGroupAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p.ObserveDirectorySyncAuthorization(ctx, d, version)
}

func (p referenceDirectoryPolicy) ObserveDirectoryUserAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p.ObserveDirectorySyncAuthorization(ctx, d, version)
}

func configureReferenceDirectoryGroupApply(t *testing.T, c *reference.StoreConfiguration, deps reference.ReferenceDependencies) referenceDirectorySCIMSource {
	t.Helper()
	keys := deps.EnvelopeKeys.(*keyring.Provider)
	source := newReferenceDirectorySCIMSource(t, deps.PostgreSQL, keys, scim.Scope{
		TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization, ProviderID: referenceDirectoryProvider, ConnectionID: referenceDirectoryConnection,
	}, referenceDirectorySCIMPolicy{}, 9, c.OTP.Store.GlobalAuthorityID)
	c.Organization.Core.Teams = organization.TeamConfig{Version: 1, LifecycleVersion: 1, MaximumTeams: 10, MaximumMembers: 100}
	c.DirectorySync.GroupSource = &reference.DirectoryGroupSourceConfiguration{SCIM: source.config, MaximumMembers: scim.DefaultGroupMembers}
	return source
}

func configureReferenceDirectorySync(t *testing.T, c *reference.StoreConfiguration, origin string, standalone bool) {
	t.Helper()
	c.Organization.SelectOrganizationID = func(ctx context.Context) (organization.ID, error) {
		return referenceDirectoryOrganization, ctx.Err()
	}
	c.DirectorySync = &reference.DirectorySyncConfiguration{TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization,
		ConnectionID: referenceDirectoryConnection, PolicyID: "reference-directory", KeyReference: "issue-envelope", Authorization: referenceDirectoryPolicy{}}
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

type referenceDirectoryApplyBinding func(context.Context, reference.DirectoryGroupApplyConfiguration) *reference.DirectoryGroupApplyService

type referenceDirectoryRoleJourney func(organizationTestHuman, referenceDirectoryProjection, [32]byte, func() referenceDirectoryProjection) [32]byte

type referenceDirectoryMixedJourney func(organizationTestHuman, referenceDirectoryProjection, [32]byte) [32]byte

func proveReferenceDirectorySyncHTTPS(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, cookies []*http.Cookie, csrf string, standalone bool, callerConfig kernel.CoordinatorConfig, groupSource, userSource *referenceDirectorySCIMSource, bind referenceDirectoryApplyBinding, bindUser func(context.Context, reference.DirectoryUserApplyConfiguration) *reference.DirectoryUserApplyService, roleJourney referenceDirectoryRoleJourney, mixedJourney referenceDirectoryMixedJourney) {
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
	if _, err := features.DirectoryGroupApply(); err == nil {
		t.Fatal("directory administration or source setup unexpectedly selected direct Group Apply")
	}
	if _, err := features.DirectoryUserApply(); err == nil {
		t.Fatal("directory administration or source setup unexpectedly selected direct User Apply")
	}
	var applied [32]byte
	var wantApplied uint64
	startingVersion := running.Version
	switch {
	case mixedJourney != nil:
		applied = mixedJourney(human, first, [32]byte(checkpoint))
		wantApplied = 4
	case roleJourney != nil:
		applied = roleJourney(human, first, [32]byte(checkpoint), func() referenceDirectoryProjection {
			return decode(call(http.MethodGet, statusPath, "", "", true, 200))
		})
		wantApplied = 2
	case groupSource != nil:
		applied = proveReferenceMappedGroupApply(t, ctx, f, features, human, *groupSource, first, [32]byte(checkpoint), bind, func() referenceDirectoryProjection {
			return decode(call(http.MethodGet, statusPath, "", "", true, 200))
		})
		wantApplied = 1
	case userSource != nil:
		applied = proveReferenceMappedUserApply(t, ctx, f, *userSource, first, [32]byte(checkpoint), bindUser, func() referenceDirectoryProjection {
			return decode(call(http.MethodGet, statusPath, "", "", true, 200))
		})
		wantApplied = 2
	}
	if wantApplied != 0 {
		running = decode(call(http.MethodGet, statusPath, "", "", true, 200))
		if running.Checkpoint != base64.RawURLEncoding.EncodeToString(applied[:]) || running.ReadCount != wantApplied || running.AppliedCount != wantApplied || running.RejectedCount != 0 || running.Version <= 1 {
			t.Fatal("browser status did not read the original direct Apply successor")
		}
		if mixedJourney != nil && running.Version != startingVersion+2 {
			t.Fatal("mixed replay advanced the HTTP generation beyond its single attachment and settlement", startingVersion, running.Version)
		}
	}
	call(http.MethodPost, "/v1/sso/directory-sync-cancel", fmt.Sprintf(`{"generationID":%q,"expectedVersion":%d}`, first.GenerationID, running.Version+1), "", true, 409)
	cancel := fmt.Sprintf(`{"generationID":%q,"expectedVersion":%d}`, first.GenerationID, running.Version)
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
	if final.State != "canceled" || final.Version != running.Version+1 || final.Checkpoint != running.Checkpoint || final.ReadCount != running.ReadCount || final.AppliedCount != running.AppliedCount || final.RejectedCount != 0 || final.ReconciliationRequired {
		t.Fatal("final directory status did not read persisted cancellation")
	}
	var generations, starts, cancellations, startEvents, cancellationEvents int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
	(SELECT count(*) FROM sso_providers.directory_sync_generations WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND state='canceled' AND version=$5),
	(SELECT count(*) FROM audit.records WHERE action='identity.sso.directory-sync-start' AND outcome=1),
	(SELECT count(*) FROM audit.records WHERE action='identity.sso.directory-sync-cancel' AND outcome=1),
	(SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.started.v1'),
	(SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.cancellation_requested.v1')`, otpTenant, referenceDirectoryOrganization, referenceDirectoryProvider, referenceDirectoryConnection, final.Version).Scan(&generations, &starts, &cancellations, &startEvents, &cancellationEvents); err != nil || generations != 1 || starts != 1 || cancellations != 1 || startEvents != 1 || cancellationEvents != 1 {
		t.Fatal("directory retries duplicated or lost real protected effects", generations, starts, cancellations, startEvents, cancellationEvents, err)
	}
}

func proveReferenceMappedGroupApply(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, human organizationTestHuman, source referenceDirectorySCIMSource, generation referenceDirectoryProjection, predecessor [32]byte, bind referenceDirectoryApplyBinding, status func() referenceDirectoryProjection) [32]byte {
	t.Helper()
	teams, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	team := organization.ID(id)
	created, err := teams.CreateTeam(ctx, organization.CreateTeamOperationRequest{Authentication: human.auth, IdempotencyKey: teamCRUDKey(t, "reference-directory-create-team"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: 1, TeamID: team, Name: "Provisioned team", CorrelationID: "directory-team"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("create genuine local target team", err)
	}
	member := source.createGroupEdge(t, ctx)
	target := identity.UserID(member.userID)
	admitted, err := teams.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: human.auth, IdempotencyKey: teamCRUDKey(t, "reference-directory-admit-source-user"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: 2, UserID: target, Role: organization.RoleMember, CorrelationID: "directory-source-admission"}, "127.0.0.1")
	if err != nil || admitted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("admit the actual SCIM-created identity to the organization", err)
	}
	emptyGroup, err := source.groups.Execute(ctx, scim.Request{
		Operation: scim.GroupCreate, Credential: source.bearer, ContentType: "application/scim+json",
		IdempotencyKey: "reference-directory-source-empty-group",
		Body:           []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Reference empty directory group","members":[]}`),
	})
	if err != nil {
		t.Fatal("create a second real source Group with no membership for the admitted User", err)
	}
	emptyGroupID := referenceDirectorySCIMResourceID(t, emptyGroup, http.StatusCreated)
	mapping := scimorganization.DirectoryMappingConfig{
		TenantID: member.scope.TenantID, OrganizationID: member.scope.OrganizationID, ProviderID: sso.ProviderID(member.scope.ProviderID),
		ConnectionID: member.scope.ConnectionID, MappingVersion: generation.MappingVersion,
		Groups: []scimorganization.DirectoryGroupTeamMapping{
			{GroupID: member.groupID, TeamID: team},
			{GroupID: emptyGroupID, TeamID: team},
		},
		Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: member.userID, UserID: target}},
	}
	policy := referenceDirectoryPolicy{}
	worker := bind(ctx, reference.DirectoryGroupApplyConfiguration{Mapping: mapping, Authorization: policy, ApplyAuthorization: policy})
	mapping.Members[0].UserID = human.user // The graph owns the installed mapping snapshot.
	command := commandIDForReference(t)
	delta, err := sso.NewDirectoryGroupMembershipDelta(command, member.groupID, member.userID, sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.DirectoryGroupApplyRequest{GenerationID: generation.GenerationID, ProviderID: sso.ProviderID(generation.ProviderID),
		MappingVersion: generation.MappingVersion, PredecessorCheckpoint: predecessor, Deltas: []sso.DirectoryDelta{delta}}
	if missing, err := worker.ObserveDrift(ctx, request); err != nil || missing.Kind != scimorganization.DirectoryMembershipDriftMissingSourceGrant || missing.LocalGrant {
		t.Fatal("direct drift inspection did not identify the missing attributed grant", missing.Kind, err)
	}
	emptyDelta, err := sso.NewDirectoryGroupMembershipDelta(commandIDForReference(t), emptyGroupID, member.userID, sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	batch := request
	batch.Deltas = []sso.DirectoryDelta{delta, emptyDelta}
	owner, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	type previewState struct {
		generation             referenceDirectoryProjection
		memberships            [2]organizationpg.DirectoryTeamMembershipObservation
		grants, audits, events int
		commands, claims       int
	}
	observeState := func() previewState {
		t.Helper()
		state := previewState{generation: status()}
		for i, groupID := range []string{member.groupID, emptyGroupID} {
			membership, err := owner.ObserveDirectoryTeamMembership(ctx, organizationpg.DirectoryTeamGrantScope{
				TenantID: member.scope.TenantID, OrganizationID: member.scope.OrganizationID,
				ProviderID: organization.ID(member.scope.ProviderID), ConnectionID: organization.ID(member.scope.ConnectionID),
				GroupID: organization.ID(groupID), TeamID: team, UserID: target,
			})
			if err != nil {
				t.Fatal("observe both exact source grants around Reference batch inspection", err)
			}
			state.memberships[i] = membership
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM outbox_messages),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM identity.identity_command_id_claims)`).Scan(&state.grants, &state.audits, &state.events, &state.commands, &state.claims); err != nil {
			t.Fatal("observe persisted protected effects around Reference batch inspection", err)
		}
		return state
	}
	beforePreview := observeState()
	for _, grant := range beforePreview.memberships {
		if grant.Source || grant.Local || grant.Version != 0 {
			t.Fatal("both Group targets must begin without source or local team grants")
		}
	}
	wantDrift := []scimorganization.DirectoryMembershipDrift{
		{Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant},
		{Kind: scimorganization.DirectoryMembershipDriftInSync},
	}
	if reports, err := worker.ObserveBatchDrift(ctx, batch); err != nil || !slices.Equal(reports, wantDrift) {
		t.Fatal("Reference batch drift did not distinguish the two actual source Groups in candidate order", err)
	}
	reversed := batch
	reversed.Deltas = []sso.DirectoryDelta{emptyDelta, delta}
	if reports, err := worker.ObserveBatchDrift(ctx, reversed); err != nil || !slices.Equal(reports, []scimorganization.DirectoryMembershipDrift{wantDrift[1], wantDrift[0]}) {
		t.Fatal("Reference batch drift did not retain reversed candidate order", err)
	}
	if after := observeState(); after != beforePreview {
		t.Fatal("Reference batch preview changed browser Status, either exact grant, or protected effects")
	}
	result, err := worker.Apply(ctx, request)
	if err != nil || len(result.ChildOutcomes) != 1 || result.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted || result.ChildOutcomes[0].Binding.ActorID != referenceDirectorySCIMActor || result.ChildOutcomes[0].Binding.UserID != target {
		t.Fatal("direct Apply did not settle the exact service-account child and target", err)
	}
	replayed, err := worker.Apply(ctx, request)
	if err != nil || len(replayed.ChildOutcomes) != 1 || replayed.ChildOutcomes[0].Binding != result.ChildOutcomes[0].Binding || replayed.ChildOutcomes[0].AuditEventID != result.ChildOutcomes[0].AuditEventID || replayed.Checkpoint != result.Checkpoint || result.Checkpoint == predecessor {
		t.Fatal("direct Apply did not replay the exact original receipt and checkpoint", err)
	}
	if stale, err := worker.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || stale != (scimorganization.DirectoryMembershipDrift{}) {
		t.Fatal("stale Reference predecessor yielded a drift report", stale.Kind, err)
	}
	afterApply := observeState()
	if afterApply.generation.Checkpoint != base64.RawURLEncoding.EncodeToString(result.Checkpoint[:]) ||
		afterApply.generation.ReadCount != 1 || afterApply.generation.AppliedCount != 1 || afterApply.generation.RejectedCount != 0 ||
		!afterApply.memberships[0].Source || afterApply.memberships[1].Source {
		t.Fatal("ordinary first-edge Apply did not settle only its exact grant and persisted browser checkpoint")
	}
	if stale, err := worker.ObserveBatchDrift(ctx, batch); !errors.Is(err, sso.ErrDirectoryReconciliation) || stale != nil {
		t.Fatal("stale Reference batch predecessor disclosed a report or partial prefix", err)
	}
	batch.PredecessorCheckpoint = result.Checkpoint
	if reports, err := worker.ObserveBatchDrift(ctx, batch); err != nil || !slices.Equal(reports, []scimorganization.DirectoryMembershipDrift{wantDrift[1], wantDrift[1]}) {
		t.Fatal("Reference batch inspection did not observe both settled exact Group attributions", err)
	}
	if after := observeState(); after != afterApply {
		t.Fatal("Reference settled or stale batch inspection changed Status, grants, or protected effects")
	}
	current := request
	current.PredecessorCheckpoint = result.Checkpoint
	if aligned, err := worker.ObserveDrift(ctx, current); err != nil || aligned.Kind != scimorganization.DirectoryMembershipDriftInSync || aligned.LocalGrant {
		t.Fatal("direct drift inspection did not see the committed source grant", aligned.Kind, err)
	}
	grant, err := owner.ObserveDirectoryTeamMembership(ctx, organizationpg.DirectoryTeamGrantScope{TenantID: member.scope.TenantID, OrganizationID: member.scope.OrganizationID,
		ProviderID: organization.ID(member.scope.ProviderID), ConnectionID: organization.ID(member.scope.ConnectionID), GroupID: organization.ID(member.groupID), TeamID: team, UserID: target})
	if err != nil || !grant.Source || grant.Version != 1 {
		t.Fatal("directory Apply did not retain the original scoped team grant", err)
	}
	return result.Checkpoint
}

func bindReferenceDirectoryGroupGraph(t *testing.T, ctx context.Context, selected reference.StoreConfiguration, deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig, apply reference.DirectoryGroupApplyConfiguration) *reference.DirectoryGroupApplyService {
	t.Helper()
	admin, source := *selected.DirectorySync, *selected.DirectorySync.GroupSource
	source.Apply = &apply
	admin.GroupSource = &source
	selected.DirectorySync = &admin
	selected.HTTPDirectorySync = nil // The direct graph never borrows a browser transport.
	stores, err := reference.ComposeStores(selected, deps)
	if err != nil {
		t.Fatal("compose a fresh direct worker graph on the installed primary", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := stores.Close(bounded); err != nil {
			t.Error("close the direct worker graph", err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, configs...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("initialize the direct graph without starting a migration or requiring a human session", err)
	}
	worker, err := features.DirectoryGroupApply()
	if err != nil {
		t.Fatal("obtain the direct executor", err)
	}
	return worker
}
