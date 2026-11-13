//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type organizationSourceFixture struct {
	native  nativeConsumerFixture
	service *apikeypg.Service
	owner   *organizationpg.Service
	id      organization.ID
	manager apikey.Authentication
	binding apikey.OrganizationSourceAuthorityBinding
}

func TestNativeOrganizationSourceFencesActualWorkAndFinalDeadline(t *testing.T) {
	f := authenticatedOrganizationSource(t)
	for _, mode := range []string{"current", "rollback", "final-deadline", "human-actor", "basic-client-actor", "different-key-actor", "foreign-tenant"} {
		t.Run(mode, func(t *testing.T) {
			observed, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "final-deadline" {
				observed.ValidUntil = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
			}
			scope := identity.CommandBinding{TenantID: f.binding.Owner.Spec().TenantID, ActorKind: authorization.SubjectAPIKey, ActorID: identity.ActorID(f.binding.KeyID)}
			mismatched := false
			switch mode {
			case "human-actor":
				scope.ActorKind, scope.ActorID, mismatched = authorization.SubjectUser, identity.ActorID(f.native.user), true
			case "basic-client-actor":
				scope.ActorKind, scope.ActorID, mismatched = authorization.SubjectServiceAccount, "configured-basic-client", true
			case "different-key-actor":
				scope.ActorID, mismatched = "another-api-key", true
			case "foreign-tenant":
				scope.TenantID, mismatched = "another-tenant", true
			}
			participant := &sourceFenceConsumer{service: f.service, organization: &observed, fail: mode == "rollback"}
			coordinator, work, command, participant := prepareSourceFenceParticipant(t, f.native, participant, scope, sourceFenceScopeProbePolicy{}, observed.Binding.KeyID, observed.Binding.AuthorityVersion, observed.ValidUntil)
			result, applyErr := coordinator.ApplyFeature(f.native.ctx, work, command)
			if !participant.invoked || participant.scopeErr != nil || participant.scope.UserID != "" || participant.scope.AnonymousFlowID == "" || participant.scope.ActorKind != scope.ActorKind || participant.scope.ActorID != scope.ActorID || participant.scope.TenantID != scope.TenantID {
				t.Fatal("actual Work invocation lost intended nonhuman/mismatched scope", participant.scopeErr)
			}
			if mismatched {
				var forbidden identity.ForbiddenError
				if !errors.As(participant.fenceErr, &forbidden) || !errors.As(applyErr, &forbidden) || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("source fence admitted another caller under permissive test operation policy", applyErr)
				}
				return
			}
			if mode == "rollback" {
				if participant.fenceErr != nil || applyErr == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("actual downstream rollback lost source validity or committed", applyErr)
				}
				return
			}
			if applyErr != nil {
				t.Fatal("actual organization source could not fence existing Work", applyErr)
			}
			if mode == "final-deadline" {
				timer := time.NewTimer(time.Until(observed.ValidUntil) + 10*time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-f.native.ctx.Done():
					t.Fatal(f.native.ctx.Err())
				}
			}
			committed, commitErr := coordinator.Commit(work, result)
			if mode == "current" {
				if commitErr != nil || committed.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("current org source did not commit", commitErr)
				}
			} else if commitErr == nil || committed.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("final commit renewed original organization freshness", commitErr)
			}
		})
	}
}

func authenticatedOrganizationSource(t *testing.T, policies ...func(authorization.Service) authorization.Service) organizationSourceFixture {
	t.Helper()
	f := setupNativeConsumer(t)
	installOrganizationKeyOwners(t, f)
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, config := organizationKeyOwners(t, f, organization.ID(id))
	for _, wrap := range policies {
		config.Authorization = wrap(config.Authorization)
	}
	create, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), ID: organization.ID(id), Slug: "source-integration", Name: "Source integration", CorrelationID: "org-source-create"}, "192.0.2.21")
	if err != nil {
		t.Fatal("prepare actual organization owner", err)
	}
	if result, err := org.Execute(f.ctx, create); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("create actual organization owner", err)
	}
	manager, managerID := f.register()
	add, err := org.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), OrganizationID: organization.ID(id), UserID: managerID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "org-source-second-owner"}, "192.0.2.21")
	if err != nil {
		t.Fatal("prepare actual second owner", err)
	}
	if result, err := org.Execute(f.ctx, add); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("admit actual second owner", err)
	}
	service, err := apikeypg.NewOrganizationService(f.pool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("organization-source-original-create"))
	issued, err := service.CreateOrganization(f.ctx, apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "source integration", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.21"}, OrganizationID: apikey.OrganizationID(id)})
	if err != nil {
		t.Fatal("genuine modern organization key issuance", err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("issued organization source record absent")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: record.ConfigurationID, ConfigurationRevision: record.ConfigurationRevision, Candidate: record.ID, Secret: secret, RequiredPermissions: []string{"invoice.read"}})
	if err != nil || verified.Result == nil || verified.Result.Owner.Spec().UserID != "" || verified.Result.Owner.Spec().OrganizationID != apikey.OrganizationID(id) {
		t.Fatal("real organization-key verification fabricated a USER", err)
	}
	binding, err := apikey.NewOrganizationSourceAuthorityBinding(*verified.Result, config.Configuration, time.Now().UTC())
	if err != nil {
		t.Fatal("snapshot actual authenticated organization root", err)
	}
	return organizationSourceFixture{native: f, service: service, owner: org, id: organization.ID(id), manager: manager, binding: binding}
}

type configurationBoundSourcePolicy struct {
	base              authorization.Service
	expected, matched atomic.Uint64
}

func (p *configurationBoundSourcePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	r := c.Request
	if r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "organization-api-key" && (r.Action == "invoice.read" || r.Action == "invoice.write") {
		value, present := r.Resource.Attributes["api-key.configuration-authority-version"].String()
		version, err := strconv.ParseUint(value, 10, 64)
		expected := p.expected.Load()
		if !present || err != nil || version == 0 || expected != 0 && version != expected {
			return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, ctx.Err()
		}
		p.matched.Add(1)
	}
	return p.base.Decide(ctx, c)
}

func TestNativeOrganizationSourceRetainsCurrentConfigurationPolicyAttribute(t *testing.T) {
	policy := &configurationBoundSourcePolicy{}
	f := authenticatedOrganizationSource(t, func(base authorization.Service) authorization.Service {
		policy.base = base
		return policy
	})
	if policy.matched.Load() == 0 {
		t.Fatal("actual source authentication did not exercise attribute-dependent permission policy")
	}
	policy.expected.Store(f.binding.ConfigurationAuthority.Version)
	before := policy.matched.Load()
	current, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
	if err != nil || current.ConfigurationAuthority.Version != f.binding.ConfigurationAuthority.Version || !slices.Equal(current.Grant, f.binding.Grant) || policy.matched.Load() <= before {
		t.Fatal("attribute-dependent native source policy lost actual current configuration authority", err)
	}
}

func TestNativeOrganizationSourceSurvivesCreatorRemovalAndDeniesRevokedRoot(t *testing.T) {
	f := authenticatedOrganizationSource(t)
	current, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
	if err != nil || current.Validate(f.binding, f.native.config.Configuration, time.Now().UTC()) != nil || current.Owner.Spec().OrganizationID != apikey.OrganizationID(f.id) || current.Owner.Spec().UserID != "" || !slices.Equal(current.Grant, f.binding.Grant) {
		t.Fatal("current organization source lost actual owner or immutable ceiling", err)
	}
	remove, err := f.owner.PrepareRemoveMember(f.native.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: f.manager.TenantID, Bearer: f.manager.Bearer}, CommandID: commandID(t), OrganizationID: f.id, UserID: f.native.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "org-source-remove-creator"}, "192.0.2.22")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.owner.Execute(f.native.ctx, remove); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("remove genuine creator membership", err)
	}
	afterRemoval, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
	if err != nil || afterRemoval.OrganizationVersion <= current.OrganizationVersion || afterRemoval.OrganizationCredentialVersion != current.OrganizationCredentialVersion || afterRemoval.Owner != current.Owner || !slices.Equal(afterRemoval.Grant, current.Grant) {
		t.Fatal("creator removal revoked otherwise-current organization source", err)
	}
	f.native.deniedGrant.Store(true)
	narrowed, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
	f.native.deniedGrant.Store(false)
	if err != nil || !slices.Equal(narrowed.Grant, []string{"invoice.read"}) || narrowed.Record.RootVersion != f.binding.RootVersion {
		t.Fatal("organization source did not intersect current permission policy", err)
	}
	deniedKey, _ := identity.NewIdempotencyKey([]byte("removed-creator-cannot-manage-source"))
	if _, err := f.service.Update(f.native.ctx, apikey.UpdateRequest{Authentication: f.native.caller, IdempotencyKey: deniedKey, KeyID: f.binding.KeyID, ExpectedVersion: afterRemoval.Record.Version, Name: "removed human", Permissions: slices.Clone(afterRemoval.Record.Grant), Network: "192.0.2.22"}); err == nil {
		t.Fatal("removed creator retained human management authority")
	}
	revokeKey, _ := identity.NewIdempotencyKey([]byte("remaining-manager-revokes-source"))
	if out, err := f.service.Revoke(f.native.ctx, apikey.Revocation{Authentication: f.manager, IdempotencyKey: revokeKey, KeyID: f.binding.KeyID, ExpectedVersion: afterRemoval.Record.Version, Network: "192.0.2.22"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("remaining actual manager could not revoke source", err)
	}
	if out, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding); err == nil || out.Record.ID != "" || len(out.Grant) != 0 {
		t.Fatal("revoked organization root retained source authority")
	}
}

func TestNativeOrganizationSourceOwnerWithdrawalDoesNotReviveEpoch(t *testing.T) {
	f := authenticatedOrganizationSource(t)
	observed, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding)
	if err != nil {
		t.Fatal("actual owner is not current before withdrawal injection", err)
	}
	// Failure injection uses the pre-extension lifecycle writer's real primary
	// shape. The owned trigger advances its credential epoch; this is not proof
	// of a newly executed public archive/MFA workflow.
	for _, state := range []string{"archived", "active"} {
		if _, err := f.native.pool.Raw().Exec(f.native.ctx, `UPDATE organization.organizations SET state=$3,version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, baselineTenant, string(f.id), state); err != nil {
			t.Fatal("inject actual owner primary withdrawal/restoration", err)
		}
		if out, err := f.service.ObserveOrganizationSourceAuthority(f.native.ctx, f.binding); err == nil || out.Record.ID != "" || len(out.Grant) != 0 {
			t.Fatal("owner withdrawal or restoration revived original credential epoch", state)
		}
		scope := identity.CommandBinding{TenantID: f.binding.Owner.Spec().TenantID, ActorKind: authorization.SubjectAPIKey, ActorID: identity.ActorID(f.binding.KeyID)}
		participant := &sourceFenceConsumer{service: f.service, organization: &observed}
		coordinator, work, command, participant := prepareSourceFenceParticipant(t, f.native, participant, scope, sourceFenceScopeProbePolicy{}, f.binding.KeyID, f.binding.AuthorityVersion, observed.ValidUntil)
		result, err := coordinator.ApplyFeature(f.native.ctx, work, command)
		if !participant.invoked || participant.fenceErr == nil || err == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("old observation survived actual owner fence withdrawal", state, err)
		}
	}
}
