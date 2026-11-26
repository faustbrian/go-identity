//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresDirectoryUserApplyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, directorySync: true, directorySyncStandalone: true, directoryUserApply: true,
	})
}

func configureReferenceDirectoryUserApply(t *testing.T, c *reference.StoreConfiguration, deps reference.ReferenceDependencies) referenceDirectorySCIMSource {
	t.Helper()
	keys := deps.EnvelopeKeys.(*keyring.Provider)
	source := newReferenceDirectorySCIMSource(t, deps.PostgreSQL, keys, scim.Scope{
		TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization, ProviderID: referenceDirectoryProvider, ConnectionID: referenceDirectoryConnection,
	}, referenceDirectorySCIMPolicy{}, 9, c.OTP.Store.GlobalAuthorityID)
	c.DirectorySync.UserSource = &reference.DirectoryUserSourceConfiguration{SCIM: &source.config}
	return source
}

func proveReferenceMappedUserApply(t *testing.T, ctx context.Context, f liveStores, source referenceDirectorySCIMSource, generation referenceDirectoryProjection, predecessor [32]byte, bind func(context.Context, reference.DirectoryUserApplyConfiguration) *reference.DirectoryUserApplyService, status func() referenceDirectoryProjection) [32]byte {
	t.Helper()
	user := source.createUser(t, ctx, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ReferenceDirectoryMember","displayName":"Reference directory member","active":true}`)
	resourceID := referenceDirectorySCIMResourceID(t, user, http.StatusCreated)
	target := identity.UserID(resourceID)
	owner, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal("construct the actual organization authority reader", err)
	}
	query := organization.CredentialAuthorityQuery{TenantID: source.config.Scope.TenantID, OrganizationID: source.config.Scope.OrganizationID, ActorID: target}
	if _, err := owner.ObserveCredentialAuthority(ctx, query); err == nil {
		t.Fatal("SCIM User CRUD alone unexpectedly granted organization authority")
	}

	mapping := scimorganization.DirectoryUserMappingConfig{
		TenantID: source.config.Scope.TenantID, OrganizationID: source.config.Scope.OrganizationID,
		ProviderID: sso.ProviderID(source.config.Scope.ProviderID), ConnectionID: source.config.Scope.ConnectionID,
		MappingVersion: generation.MappingVersion,
		Members:        []scimorganization.DirectoryMemberUserMapping{{MemberID: resourceID, UserID: target}},
		AllowAdmission: true, AllowWithdrawal: true,
	}
	policy := referenceDirectoryPolicy{}
	membershipSource := organizationpg.DirectoryMembershipSource{
		TenantID: source.config.Scope.TenantID, OrganizationID: source.config.Scope.OrganizationID, UserID: target,
		ProviderID: organization.ID(source.config.Scope.ProviderID), ConnectionID: organization.ID(source.config.Scope.ConnectionID), ResourceID: organization.ID(resourceID),
	}
	recordID, err := membershipSource.RecordID()
	if err != nil {
		t.Fatal("identify the exact source-owned organization contribution", err)
	}
	apply := reference.DirectoryUserApplyConfiguration{
		Mapping: mapping, Authorization: policy, ApplyAuthorization: policy, MaximumMembers: 100, MaximumPerUser: 10,
	}
	worker := bind(ctx, apply)
	admissionCommand := commandIDForReference(t)
	admission, err := sso.NewDirectoryUserAdmissionDelta(admissionCommand, resourceID, string(user.ETag))
	if err != nil {
		t.Fatal("bind User admission to its exact active source revision", err)
	}
	request := ssopg.DirectoryUserApplyRequest{
		GenerationID: generation.GenerationID, ProviderID: sso.ProviderID(generation.ProviderID), MappingVersion: generation.MappingVersion,
		PredecessorCheckpoint: predecessor, Delta: admission,
	}
	type previewState struct {
		generation                     referenceDirectoryProjection
		attribution                    organizationpg.DirectoryMembershipAttribution
		actor                          organization.Member
		authorized                     bool
		grants, active, audits, events int
		commands, claims               int
	}
	observeState := func() previewState {
		t.Helper()
		state := previewState{generation: status()}
		attribution, err := owner.ObserveDirectoryMembershipAttribution(ctx, membershipSource)
		if err != nil {
			t.Fatal("observe the exact source-owned organization contribution", err)
		}
		state.attribution = attribution
		authority, authorityErr := owner.ObserveCredentialAuthority(ctx, query)
		if authorityErr != nil && !errors.Is(authorityErr, organization.ErrForbidden) {
			t.Fatal("observe effective organization authority around User inspection", authorityErr)
		}
		state.actor, state.authorized = authority.Actor, authorityErr == nil
		if err := f.pool.Raw().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM organization.directory_membership_grants),
		(SELECT count(*) FROM organization.directory_membership_grants WHERE active),
		(SELECT count(*) FROM audit.records),
		(SELECT count(*) FROM outbox_messages),
		(SELECT count(*) FROM identity.commands),
		(SELECT count(*) FROM identity.identity_command_id_claims)`).Scan(&state.grants, &state.active, &state.audits, &state.events, &state.commands, &state.claims); err != nil {
			t.Fatal("observe protected effects around direct User inspection", err)
		}
		return state
	}
	assertUnchanged := func(before previewState) {
		t.Helper()
		if after := observeState(); after != before {
			t.Fatal("User inspection changed browser Status, organization authority, source attribution, or protected effects")
		}
	}
	beforeAdmission := observeState()
	if missing, err := worker.ObserveDrift(ctx, request); err != nil || missing != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftMissingSourceGrant,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: user.ETag},
	}) {
		t.Fatal("direct User inspection did not report the active source's missing grant", err)
	}
	assertUnchanged(beforeAdmission)
	granted, err := worker.Apply(ctx, request)
	if err != nil || len(granted.ChildOutcomes) != 1 || granted.Checkpoint == predecessor || granted.Checkpoint == ([32]byte{}) {
		t.Fatal("direct User Apply did not settle the original admission and successor", err)
	}
	receipt := granted.ChildOutcomes[0]
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Binding.CommandID != admissionCommand ||
		receipt.Binding.TenantID != source.config.Scope.TenantID || receipt.Binding.UserID != target ||
		receipt.Binding.ActorKind != authorization.SubjectServiceAccount || receipt.Binding.ActorID != referenceDirectorySCIMActor ||
		receipt.Binding.OperationID != sso.DirectoryUserAdmissionOperation().OperationID || receipt.Binding.RecordID != recordID || receipt.Feature == nil ||
		receipt.Feature.Operation != sso.DirectoryUserAdmissionOperation() ||
		receipt.Feature.BeforeVersion != 0 || receipt.Feature.AfterVersion != 1 {
		t.Fatal("User admission lost its exact ordinary-member service-account receipt")
	}
	if replay, err := worker.Apply(ctx, request); err != nil || !reflect.DeepEqual(granted, replay) {
		t.Fatal("User admission did not replay the identical receipt and checkpoint", err)
	}
	member, err := owner.ObserveCredentialAuthority(ctx, query)
	if err != nil || member.Actor.UserID != target || member.Actor.Role != organization.RoleMember || !member.Actor.Active {
		t.Fatal("User admission did not grant actual ordinary organization authority", err)
	}
	afterAdmission := observeState()
	if afterAdmission.generation.Checkpoint != base64.RawURLEncoding.EncodeToString(granted.Checkpoint[:]) ||
		afterAdmission.generation.ReadCount != 1 || afterAdmission.generation.AppliedCount != 1 || afterAdmission.generation.RejectedCount != 0 ||
		!afterAdmission.authorized || !afterAdmission.attribution.Membership.ContributionActive {
		t.Fatal("ordinary admission did not settle the source grant and browser checkpoint exactly once")
	}
	if stale, err := worker.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || stale != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("stale User checkpoint disclosed a drift report", err)
	}
	assertUnchanged(afterAdmission)
	request.PredecessorCheckpoint = granted.Checkpoint
	if aligned, err := worker.ObserveDrift(ctx, request); err != nil || aligned != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftInSync,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: user.ETag},
	}) {
		t.Fatal("ordinary User admission did not converge the exact active source", err)
	}
	assertUnchanged(afterAdmission)

	inactive, err := source.native.Execute(ctx, scim.Request{
		Operation: scim.UserPatch, Credential: source.bearer, ResourceID: resourceID, IfMatch: user.ETag,
		ContentType: "application/scim+json",
		Body:        []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`),
	})
	if err != nil {
		t.Fatal("mark the actual source User inactive through SCIM PATCH", err)
	}
	if updated := referenceDirectorySCIMResourceID(t, inactive, http.StatusOK); updated != resourceID || inactive.ETag == user.ETag {
		t.Fatal("SCIM PATCH did not retain the source identity with a new revision")
	}
	stale, err := sso.NewDirectoryUserDeprovisionDelta(commandIDForReference(t), resourceID, string(user.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal("construct the stale source withdrawal", err)
	}
	request.PredecessorCheckpoint, request.Delta = granted.Checkpoint, stale
	beforeWithdrawal := observeState()
	if report, err := worker.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || report != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("stale User revision disclosed a drift report", err)
	}
	assertUnchanged(beforeWithdrawal)
	if denied, err := worker.Apply(ctx, request); err == nil || denied.Checkpoint != ([32]byte{}) {
		t.Fatal("a stale source revision settled User withdrawal", err)
	}
	if after, err := owner.ObserveCredentialAuthority(ctx, query); err != nil || after.Actor != member.Actor {
		t.Fatal("stale withdrawal changed the actual organization authority", err)
	}

	withdrawalCommand := commandIDForReference(t)
	withdrawal, err := sso.NewDirectoryUserDeprovisionDelta(withdrawalCommand, resourceID, string(inactive.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal("bind withdrawal to the exact inactive source revision", err)
	}
	request.Delta = withdrawal
	beforeWithdrawal = observeState()
	if unexpected, err := worker.ObserveDrift(ctx, request); err != nil || unexpected != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserInactive, Revision: inactive.ETag},
	}) {
		t.Fatal("explicit inactive User did not report its still-live exact source grant", err)
	}
	assertUnchanged(beforeWithdrawal)
	if !beforeWithdrawal.authorized || beforeWithdrawal.actor != member.Actor || !beforeWithdrawal.attribution.Membership.ContributionActive {
		t.Fatal("User inspection withdrew the effective organization authority before ordinary Apply")
	}
	withdrawn, err := worker.Apply(ctx, request)
	if err != nil || len(withdrawn.ChildOutcomes) != 1 || withdrawn.Checkpoint == granted.Checkpoint || withdrawn.Checkpoint == ([32]byte{}) {
		t.Fatal("fresh User withdrawal did not settle its original child and successor", err)
	}
	removed := withdrawn.ChildOutcomes[0]
	if removed.Validate() != nil || removed.Outcome != identity.CommitOutcomeCommitted || removed.Binding.CommandID != withdrawalCommand ||
		removed.Binding.TenantID != source.config.Scope.TenantID || removed.Binding.UserID != target || removed.Binding.ActorKind != authorization.SubjectServiceAccount ||
		removed.Binding.ActorID != referenceDirectorySCIMActor || removed.Binding.OperationID != sso.DirectoryUserDeprovisionOperation().OperationID ||
		removed.Binding.RecordID != recordID || removed.Feature == nil || removed.Feature.Operation != sso.DirectoryUserDeprovisionOperation() ||
		removed.Feature.BeforeVersion != 1 || removed.Feature.AfterVersion != 2 {
		t.Fatal("User withdrawal lost the exact original source-owned receipt")
	}
	if _, err := owner.ObserveCredentialAuthority(ctx, query); err == nil {
		t.Fatal("fresh User withdrawal retained scoped organization authority")
	}
	request.PredecessorCheckpoint = withdrawn.Checkpoint
	afterWithdrawal := observeState()
	if afterWithdrawal.generation.Checkpoint != base64.RawURLEncoding.EncodeToString(withdrawn.Checkpoint[:]) ||
		afterWithdrawal.generation.ReadCount != 2 || afterWithdrawal.generation.AppliedCount != 2 || afterWithdrawal.generation.RejectedCount != 0 ||
		afterWithdrawal.authorized || afterWithdrawal.attribution.Membership.ContributionActive {
		t.Fatal("ordinary withdrawal did not settle the inactive source and browser checkpoint exactly once")
	}
	if aligned, err := worker.ObserveDrift(ctx, request); err != nil || aligned != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftInSync,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserInactive, Revision: inactive.ETag},
	}) {
		t.Fatal("ordinary User withdrawal did not converge the exact inactive source", err)
	}
	assertUnchanged(afterWithdrawal)
	var global string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(source.config.Scope.TenantID), resourceID).Scan(&global); err != nil || global != "active" {
		t.Fatal("source withdrawal changed the global identity", err)
	}
	reconstructed := bind(ctx, apply)
	request.PredecessorCheckpoint = granted.Checkpoint
	if replay, err := reconstructed.Apply(ctx, request); err != nil || !reflect.DeepEqual(withdrawn, replay) {
		t.Fatal("reconstructed User worker did not replay the identical withdrawn receipt and checkpoint", err)
	}
	if _, err := owner.ObserveCredentialAuthority(ctx, query); err == nil {
		t.Fatal("withdrawal replay recreated scoped organization authority")
	}
	return withdrawn.Checkpoint
}

func bindReferenceDirectoryUserGraph(t *testing.T, ctx context.Context, selected reference.StoreConfiguration, deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig, apply reference.DirectoryUserApplyConfiguration) *reference.DirectoryUserApplyService {
	t.Helper()
	admin, source := *selected.DirectorySync, *selected.DirectorySync.UserSource
	source.Apply = &apply
	admin.UserSource = &source
	selected.DirectorySync = &admin
	selected.HTTPDirectorySync = nil
	stores, err := reference.ComposeStores(selected, deps)
	if err != nil {
		t.Fatal("compose a fresh direct User worker graph on the installed primary", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := stores.Close(bounded); err != nil {
			t.Error("close the direct User worker graph", err)
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
		t.Fatal("initialize the direct User graph without migration or human session", err)
	}
	worker, err := features.DirectoryUserApply()
	if err != nil {
		t.Fatal("obtain the native direct User executor", err)
	}
	return worker
}
