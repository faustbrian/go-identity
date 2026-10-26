package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// OrganizationConfiguration opts into native explicit-organization membership
// over this graph's current verified-password bearer sessions. It enables no
// HTTP, teams or domain proofs. OwnerTransfer and Lifecycle independently
// select their native password-proof profiles, never HTTP routes. Core.Clock
// must be nil; the graph supplies its system clock. Counters selects protected
// PostgreSQL command admission in the existing risk schema, not a replacement
// risk evaluator. Custody retains the native original-key encryption profile.
// ConfigurationID and bounded, concurrent-safe ID callbacks must remain stable
// for original recovery. Change the configuration ID for material policy changes.
type OrganizationConfiguration struct {
	Core                 organization.Config
	Repository           organizationpg.Config
	Counters             riskpg.Config
	Custody              organizationpg.OperationCustodyConfig
	ConfigurationID      string
	SelectOrganizationID func(context.Context) (organization.ID, error)
	Invitations          *OrganizationInvitationConfiguration
	OwnerTransfer        *OrganizationOwnerTransferConfiguration
	Lifecycle            *OrganizationLifecycleConfiguration
}

// OrganizationLifecycleConfiguration selects the local native archive/restore
// profile using distinct real password action sources. Both must use the same
// explicit audience, bearer transport and no CSRF keys. Leave Core.Lifecycle
// zero; the graph injects its matching policy. No external cascade is selected.
type OrganizationLifecycleConfiguration struct {
	Archive, Restore passwordpg.ActionPrimaryConfig
}

// Format redacts retained primary configuration and keys.
func (OrganizationLifecycleConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.OrganizationLifecycleConfiguration(redacted)")
}

// MarshalJSON rejects export of deployment custody.
func (OrganizationLifecycleConfiguration) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects implicit export of deployment custody.
func (OrganizationLifecycleConfiguration) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// OrganizationOwnerTransferConfiguration selects native ownership transfer
// using this graph's real password-verification owner. Primary must select
// identity.organization.owner-transfer, an existing issuance audience and bearer
// transport with no CSRF keys. Its audience is injected into Core; callers must
// leave Core.OwnerTransferAudience empty to avoid competing configuration.
type OrganizationOwnerTransferConfiguration struct {
	Primary passwordpg.ActionPrimaryConfig
}

// OrganizationInvitationConfiguration additionally selects genuine intended-
// recipient invitations. Issuer and Preparation retain native capability keys;
// their clocks must be nil for graph injection. Delivery uses the graph's owned
// queue, templates and selected provider/policy versions. The supplied endpoint
// and scope key retain the native purpose/recipient/organization-bound link.
// No application contributor, store, renderer or workflow is accepted.
type OrganizationInvitationConfiguration struct {
	Policy                         organization.InvitationConfig
	Issuer                         issuerpg.IssuerConfig
	Preparation                    issuerpg.IssuancePreparationConfig
	ConfigurationID                string
	SelectInvitationID             func(context.Context) (organization.ID, error)
	TemplateID                     string
	TemplateVersion                uint32
	PolicyVersion, ProviderVersion uint64
	LocaleChain                    []string
	Endpoint                       string
	ScopeKey                       [32]byte
}

// Format redacts retained keys and deployment configuration.
func (OrganizationConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.OrganizationConfiguration(redacted)")
}

// MarshalJSON rejects serialization of deployment secrets.
func (OrganizationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects serialization of deployment secrets.
func (OrganizationConfiguration) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// Format redacts capability and delivery deployment configuration.
func (OrganizationInvitationConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.OrganizationInvitationConfiguration(redacted)")
}

// MarshalJSON rejects serialization of capability and delivery secrets.
func (OrganizationInvitationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects serialization of capability and delivery secrets.
func (OrganizationInvitationConfiguration) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

type organizationState struct {
	operations        *organizationpg.OperationService
	invitations       *organizationpg.InvitationService
	sender            *organizationpg.InvitationOperationService
	limits            capability.Limits
	maximum           time.Duration
	provider          uint64
	transferAudience  string
	transferProofs    *passwordpg.Repository
	lifecycle         *organizationpg.Service
	lifecycleProofs   *passwordpg.Repository
	lifecycleAudience string
}

func composeOrganization(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState, queue *deliverypg.EnqueueService, proofs *passwordVerificationState) (*organizationState, error) {
	if c.Organization == nil {
		return nil, nil
	}
	n := *c.Organization
	invalid := identity.InvalidInputError{Field: "reference_organization"}
	if c.OTP == nil || c.PasswordSignin == nil || sessions == nil || d.PostgreSQL == nil || c.Delivery == nil || queue == nil || n.Core.Clock != nil || n.Core.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || n.Counters.PolicyVersion != n.Core.PolicyVersion || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || !n.Counters.EnforceLockouts || n.Repository.MaximumDuration > n.Core.MaximumDuration || n.Core.Teams.MaximumTeams != 0 || n.Core.Domains.MaximumClaims != 0 || n.Core.DynamicRoles.Version != 0 || n.Core.Lifecycle != (organization.LifecycleConfig{}) || n.Core.OwnerTransferAudience != "" {
		return nil, invalid
	}
	// The native organization contributor currently admits this exact profile;
	// selecting another graph authenticator must not silently downgrade it.
	selection, err := sessionAdmissionSelection(c)
	if err != nil || selection.Verified == nil || c.PasswordSignin.MFA != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_profile"}
	}
	n.Core.Clock = clock.System{}
	e := c.Session.Native.Execution
	// DigestKey intentionally exposes no raw key/version accessor. A harmless
	// syntactically valid probe recovers only its public version for the native
	// contributor's retained-key index, as that constructor itself validates.
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	lookup := make(map[uint32]session.DigestKey, len(c.Session.Native.Validation.LookupKeys))
	for _, key := range c.Session.Native.Validation.LookupKeys {
		digest, err := probe.Digest(key, "validation")
		if err != nil {
			return nil, invalid
		}
		if _, exists := lookup[digest.KeyVersion]; exists {
			return nil, invalid
		}
		lookup[digest.KeyVersion] = key
	}
	admission := organizationpg.ContributorConfig{Session: e.Repository, Profile: *selection.Verified, LookupKeys: lookup, PolicyID: n.Core.PolicyID, PolicyVersion: n.Core.PolicyVersion, MaximumMembers: n.Core.MaximumMembers, MaximumPerUser: n.Core.MaximumPerUser, MaximumPerTenant: n.Core.MaximumPerTenant}
	if n.OwnerTransfer != nil {
		primary := n.OwnerTransfer.Primary
		if proofs == nil || proofs.native == nil || proofs.proofs == nil || primary.Action != string(organization.OwnerTransfer) || primary.Transport != session.CredentialBearer || len(primary.CSRFKeys) != 0 {
			return nil, identity.InvalidInputError{Field: "reference_organization_transfer"}
		}
		admission.OwnerTransferPrimary, err = passwordpg.NewActionPrimarySource(proofs.native, primary)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_organization_transfer_primary"}
		}
		n.Core.OwnerTransferAudience = primary.Audience
	}
	if n.Lifecycle != nil {
		archive, restore := n.Lifecycle.Archive, n.Lifecycle.Restore
		if proofs == nil || proofs.native == nil || proofs.proofs == nil || archive.Action != string(organization.Archive) || restore.Action != string(organization.Restore) || archive.Audience != restore.Audience || archive.Transport != session.CredentialBearer || restore.Transport != session.CredentialBearer || len(archive.CSRFKeys) != 0 || len(restore.CSRFKeys) != 0 {
			return nil, identity.InvalidInputError{Field: "reference_organization_lifecycle"}
		}
		admission.ArchivePrimary, err = passwordpg.NewActionPrimarySource(proofs.native, archive)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_organization_archive_primary"}
		}
		admission.RestorePrimary, err = passwordpg.NewActionPrimarySource(proofs.native, restore)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_organization_restore_primary"}
		}
		n.Core.Lifecycle = organization.LifecycleConfig{Version: 1, ProofAudience: archive.Audience}
		admission.Lifecycle = n.Core.Lifecycle
	}
	repository, err := organizationpg.NewRepository(d.PostgreSQL, n.Repository)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_repository"}
	}
	participant, err := organizationpg.NewContributor(repository, admission)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_admission"}
	}
	counters, err := riskpg.NewRepository(n.Counters)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_counters"}
	}
	domain, err := kernel.NewRepository(d.PostgreSQL, kernel.Config{MaximumDuration: n.Repository.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, invalid
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, invalid
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, participant})
	if err != nil {
		return nil, invalid
	}
	query := c.OTP.RequestKeys.Policy
	query.Clock = clock.System{}
	coordinatorConfig := c.OTP.Coordinator
	coordinatorConfig.QueryPolicy, coordinatorConfig.AdmissionPolicy = &query, &query
	coordinator, err := kernel.NewCoordinator(d.PostgreSQL, registry, coordinatorConfig)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_coordinator"}
	}
	service, err := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: n.Core, Sessions: sessions.reader, Authorization: query.Authorization, Risk: counters, Coordinator: coordinator, Registry: registry})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_service"}
	}
	operations, err := organizationpg.NewOperationService(service, organizationpg.OperationServiceConfig{ConfigurationID: n.ConfigurationID, Coordinator: coordinatorConfig, RequestKeys: c.OTP.RequestKeys, Custody: n.Custody, NewOrganizationID: n.SelectOrganizationID})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_operations"}
	}
	state := &organizationState{operations: operations, maximum: n.Core.MaximumDuration}
	if n.Lifecycle != nil {
		state.lifecycle, state.lifecycleProofs, state.lifecycleAudience = service, proofs.proofs, n.Core.Lifecycle.ProofAudience
	}
	if n.OwnerTransfer != nil {
		state.transferAudience, state.transferProofs = n.Core.OwnerTransferAudience, proofs.proofs
	}
	if n.Invitations == nil {
		return state, nil
	}
	i := *n.Invitations
	if i.Issuer.Crypto.Clock != nil || i.Preparation.Clock != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation_clock"}
	}
	i.Issuer.Crypto.Clock, i.Preparation.Clock = time.Now, time.Now
	crypto, err := envelope.NewService(d.EnvelopeKeys)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation_crypto"}
	}
	deliverer, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation_delivery"}
	}
	renderer, err := delivery.NewTemplateRenderer(c.Delivery.Templates)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation_templates"}
	}
	policy, ok := c.Delivery.Enqueue.Policies[i.PolicyVersion]
	if !ok || c.Delivery.Enqueue.Custody.ProviderProfiles[i.ProviderVersion].PolicyVersion != i.PolicyVersion {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation_policy"}
	}
	state.invitations, err = organizationpg.NewInvitationService(repository, organizationpg.InvitationServiceConfig{Core: n.Core, Invitation: i.Policy, Admission: admission, Sessions: sessions.reader, Authorization: query.Authorization, Coordinator: coordinatorConfig, Risk: counters, Issuer: i.Issuer, Preparation: i.Preparation, Delivery: organizationpg.InvitationDeliveryConfig{Owner: deliverer, Status: queue, Renderer: renderer, Policy: policy, PolicyVersion: i.PolicyVersion, ProviderVersion: i.ProviderVersion, StatusPolicyVersion: c.Delivery.Enqueue.PolicyVersion, TemplateID: i.TemplateID, TemplateVersion: i.TemplateVersion, LocaleChain: i.LocaleChain, Endpoint: i.Endpoint, ScopeKey: i.ScopeKey}})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation"}
	}
	state.sender, err = organizationpg.NewInvitationOperationService(state.invitations, organizationpg.InvitationOperationServiceConfig{ConfigurationID: i.ConfigurationID, RequestKeys: c.OTP.RequestKeys, Custody: n.Custody, NewInvitationID: i.SelectInvitationID})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_organization_invitation_sender"}
	}
	state.limits = i.Issuer.Crypto.Limits
	state.provider = i.ProviderVersion
	return state, nil
}
