package postgres

import (
	"context"
	"fmt"
	"io"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// OrganizationPermissionReductionStoreConfig selects one genuine organization
// and a distinct authorized maintenance service actor. The actor is not the key
// creator or a member. Provision its actual scoped authority and application
// policy separately; every operation rechecks them and fences mutation in Work.
type OrganizationPermissionReductionStoreConfig struct {
	TenantID             identity.TenantID
	OrganizationID       apikey.OrganizationID
	ActorID              identity.ActorID
	ActorPolicyNamespace string
}

// Format emits a constant redacted label without owner or service-policy identifiers.
func (OrganizationPermissionReductionStoreConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey/postgres.OrganizationPermissionReductionStoreConfig(redacted)")
}

// MarshalJSON rejects implicit export of trusted owner/actor configuration.
func (OrganizationPermissionReductionStoreConfig) MarshalJSON() ([]byte, error) {
	return nil, apikey.ErrDisclosure
}

// NewOrganizationPermissionReductionStore selects modern organization/Narrow
// maintenance using NewOrganizationService's real organization repository and
// existing coordinator. It owns no transaction, journal, pool or goroutine.
// Its borrowed primary must outlive use. USER constructors/defaults are unchanged.
func NewOrganizationPermissionReductionStore(primary *Service, c OrganizationPermissionReductionStoreConfig) (*PermissionReductionStore, error) {
	if primary == nil || primary.config == nil || primary.pool == nil || primary.pool.Raw() == nil || primary.organization == nil || primary.organization.repository == nil || primary.organizationID != "" {
		return nil, apikey.ErrInvalid
	}
	source := primary.config()
	profile := source.Configuration.Spec()
	if !scope(string(c.TenantID)) || !scope(string(c.OrganizationID)) || !scope(string(c.ActorID)) || !scope(c.ActorPolicyNamespace) || c.ActorPolicyNamespace == source.Profile.PolicyNamespace || profile.Algorithm != apikey.AlgorithmModernHMACSHA256 || profile.State != apikey.ConfigurationActive || profile.PermissionReduction != apikey.PermissionReductionNarrow || profile.Cache != apikey.CacheDisabled {
		return nil, apikey.ErrInvalid
	}
	return &PermissionReductionStore{primary: primary, config: PermissionReductionStoreConfig{TenantID: c.TenantID, ActorID: c.ActorID, ActorPolicyNamespace: c.ActorPolicyNamespace}, organizationID: c.OrganizationID}, nil
}

func (s *PermissionReductionStore) operation() identity.FeatureOperation {
	op := permissionReductionOperation()
	if s.organizationID != "" {
		op.SchemaID, op.SubjectRequirement = "apikey-permission-reduction-organization-v1", identity.FeatureSubjectAnonymousFlow
	}
	return op
}

func (s *PermissionReductionStore) owns(owner apikey.Owner) bool {
	o := owner.Spec()
	if o.TenantID != s.config.TenantID {
		return false
	}
	if s.organizationID != "" {
		return o.Kind == apikey.OwnerOrganization && o.OrganizationID == s.organizationID && o.UserID == ""
	}
	return o.Kind == apikey.OwnerUser && o.UserID == s.config.UserID
}

func currentOrganizationReductionAuthority(o apikey.OrganizationSourceAuthorityObservation) apikey.CurrentAuthority {
	return apikey.CurrentAuthority{Owner: o.Owner, OwnerActive: true, TenantActive: true, Permissions: slices.Clone(o.Grant), PolicyVersion: o.PolicyVersion, ConfigurationAuthority: o.ConfigurationAuthority, ReadStartedAt: o.ReadStartedAt, VerifiedAt: o.VerifiedAt, ValidUntil: o.ValidUntil}
}

func (p *reductionPhase) generateOrganization(ctx context.Context, generation uint64, record apikey.Record) (verificationSnapshot, error) {
	primary := p.store.primary
	observed, err := primary.ObserveOrganizationSourceAuthority(ctx, apikey.OrganizationSourceAuthorityBinding(sourceBindingForRecord(record, p.decision.ConfigurationAuthority)))
	if err != nil {
		return verificationSnapshot{}, err
	}
	actual, err := (apikey.ScopePolicy{}).DecidePermissionReduction(p.binding.CommandID, record, currentOrganizationReductionAuthority(observed), primary.config().Configuration, observed.VerifiedAt)
	if err != nil || !sameReductionDecision(actual, p.decision) {
		return verificationSnapshot{}, apikey.ErrDenied
	}
	wire, err := encodeRecord(record, primary.config().Configuration)
	if err != nil {
		return verificationSnapshot{}, err
	}
	owner := sourceOrganizationAuthority(observed)
	return verificationSnapshot{Schema: 1, Generation: generation, Binding: storedBinding(p.binding), Record: wire, GlobalVersion: observed.GlobalVersion, TenantVersion: observed.TenantVersion, PolicyVersion: observed.PolicyVersion, ConfigurationVersion: observed.ConfigurationAuthority.Version, Permissions: slices.Clone(observed.Grant), Started: observed.ReadStartedAt, Verified: observed.VerifiedAt, Until: observed.ValidUntil, Organization: &owner}, nil
}

func (p *reductionPhase) organizationObservation() (apikey.OrganizationSourceAuthorityObservation, error) {
	x := p.snapshot.Source
	primary := p.store.primary
	record, err := decodeRecord(x.Record, primary.config().Configuration)
	if err != nil || x.Schema != 1 || x.Generation != p.snapshot.Generation || x.Binding != storedBinding(p.binding) || x.Organization == nil || !p.store.owns(record.Owner) || record.ID != p.decision.KeyID || !exactTime(x.Started) || !exactTime(x.Verified) || !exactTime(x.Until) {
		return apikey.OrganizationSourceAuthorityObservation{}, identity.UnavailableError{}
	}
	org := x.Organization
	query := organization.CredentialAuthorityQuery{TenantID: p.binding.TenantID, OrganizationID: organization.ID(p.store.organizationID)}
	if org.Validate(query, org.VerifiedAt) != nil {
		return apikey.OrganizationSourceAuthorityObservation{}, identity.UnavailableError{}
	}
	configuration := apikey.ConfigurationAuthorityBinding{TenantID: p.binding.TenantID, ConfigurationID: record.ConfigurationID, Version: x.ConfigurationVersion}
	binding := apikey.OrganizationSourceAuthorityBinding(sourceBindingForRecord(record, configuration))
	o := apikey.OrganizationSourceAuthorityObservation{Binding: binding, Record: record, Owner: record.Owner, Grant: slices.Clone(x.Permissions), PolicyVersion: x.PolicyVersion, ConfigurationAuthority: configuration, GlobalVersion: x.GlobalVersion, TenantVersion: x.TenantVersion, OrganizationVersion: org.Version, OrganizationCredentialVersion: org.CredentialVersion, ReadStartedAt: x.Started, VerifiedAt: x.Verified, ValidUntil: x.Until, OrganizationReadStartedAt: org.ReadStartedAt, OrganizationVerifiedAt: org.VerifiedAt, OrganizationValidUntil: org.ValidUntil}
	if o.Validate(binding, primary.config().Configuration, x.Verified) != nil || o.PolicyVersion != primary.config().PolicyVersion {
		return apikey.OrganizationSourceAuthorityObservation{}, identity.UnavailableError{}
	}
	actual, err := (apikey.ScopePolicy{}).DecidePermissionReduction(p.binding.CommandID, record, currentOrganizationReductionAuthority(o), primary.config().Configuration, x.Verified)
	if err != nil || !sameReductionDecision(actual, p.decision) {
		return apikey.OrganizationSourceAuthorityObservation{}, identity.UnavailableError{}
	}
	return o, nil
}

func (p *reductionPhase) checkOrganization(ctx context.Context, w kernel.Work) error {
	observed, err := p.organizationObservation()
	if err != nil {
		return err
	}
	if p.applied {
		if p.result == nil {
			return identity.UnavailableError{}
		}
		observed.Record = *p.result
		observed.ConfigurationAuthority.Version++
		observed.Binding = apikey.OrganizationSourceAuthorityBinding(sourceBindingForRecord(observed.Record, observed.ConfigurationAuthority))
		observed.Grant = slices.Clone(p.result.Grant)
	}
	primary := p.store.primary
	if err := primary.requireOrganizationSourceOwner(ctx, w, p, observed); err != nil {
		return err
	}
	if err := p.requireActor(ctx, w); err != nil {
		return err
	}
	return primary.requireOrganizationSourceRecord(ctx, w, observed)
}
