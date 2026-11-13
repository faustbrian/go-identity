package postgres

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// ObserveOrganizationSourceAuthority reads one already-authenticated modern
// organization key through actual primary directory, configuration, key and
// organization owners. Select NewOrganizationService and its owners' histories
// first. Creator membership is not integration ownership; no USER or session is
// manufactured. Current permission policy uses the actual API-key subject and
// organization resource outside any Work/lock. No bearer authentication, debit,
// mutation or principal is introduced. Failures return a zero observation.
// The borrowed service/owners/pool must outlive the bounded call.
func (s *Service) ObserveOrganizationSourceAuthority(ctx context.Context, binding apikey.OrganizationSourceAuthorityBinding) (out apikey.OrganizationSourceAuthorityObservation, err error) {
	if s == nil || s.config == nil || ctx == nil {
		return out, apikey.ErrInvalid
	}
	if s.organization == nil || s.organization.repository == nil {
		return out, apikey.ErrDenied
	}
	configuration, err := s.selectedConfiguration(binding.ConfigurationAuthority.ConfigurationID, binding.ConfigurationRevision)
	if err != nil || binding.Validate(configuration) != nil {
		return out, apikey.ErrInvalid
	}
	s = s.withConfiguration(configuration)
	binding.Grant = slices.Clone(binding.Grant)
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = apikey.OrganizationSourceAuthorityObservation{}, identity.UnavailableError{}
		}
	}()
	started, err := s.primaryTime(ctx)
	if err != nil {
		return out, err
	}
	owner := binding.Owner.Spec()
	directoryQuery := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().Profile.GlobalAuthorityID, TenantID: owner.TenantID}
	directory, err := s.directory.GetDirectoryAuthority(ctx, directoryQuery)
	if err != nil || !directory.Enabled {
		return out, apikey.ErrDenied
	}
	configurationAuthority, err := s.configurationAuthority(ctx, owner.TenantID)
	if err != nil || configurationAuthority.Version < binding.ConfigurationAuthority.Version {
		return out, apikey.ErrDenied
	}
	record, err := s.currentRecord(ctx, owner.TenantID, binding.KeyID)
	if err != nil || !sourceRecordMatches(apikey.SourceAuthorityBinding(binding), record) || record.Owner != binding.Owner {
		return out, apikey.ErrDenied
	}
	query := organization.CredentialAuthorityQuery{TenantID: owner.TenantID, OrganizationID: organization.ID(owner.OrganizationID)}
	observed, err := s.organization.repository.ObserveCredentialAuthority(ctx, query)
	if err != nil || observed.CredentialVersion != owner.Version {
		return out, apikey.ErrDenied
	}
	// Reuse the existing native organization's exact key-policy context, not a
	// USER authorization namespace or the creator's scoped member authority.
	selected := *s
	selected.organizationID = owner.OrganizationID
	selected.organization = &organizationComposition{repository: s.organization.repository, observation: &observed}
	grant := make([]string, 0, len(binding.Grant))
	for _, permission := range binding.Grant {
		policyContext := selected.organizationDecision(owner.TenantID, authorization.SubjectAPIKey, string(binding.KeyID), permission, "")
		policyContext.Request.Resource.Attributes["api-key.configuration-authority-version"] = authorization.StringValue(strconv.FormatUint(configurationAuthority.Version, 10))
		decision, err := s.config().Authorization.Decide(ctx, policyContext)
		if err != nil || decision.Revision != authorization.Revision(s.config().PolicyVersion) || ctx.Err() != nil {
			return out, identity.UnavailableError{}
		}
		switch decision.Outcome {
		case authorization.Allow:
			grant = append(grant, permission)
		case authorization.Deny:
		default:
			return out, identity.UnavailableError{}
		}
	}
	verified, err := s.primaryTime(ctx)
	if err != nil {
		return out, err
	}
	profile := configuration.Spec()
	until := started.Add(20*time.Second - profile.ClockUncertainty - profile.DecisionRaceBudget).Truncate(time.Microsecond)
	until = minTime(until, minTime(binding.ExpiresAt, observed.ValidUntil))
	current := apikey.OrganizationSourceAuthorityObservation{Binding: binding, Record: record, Owner: record.Owner, Grant: grant, PolicyVersion: s.config().PolicyVersion, ConfigurationAuthority: configurationAuthority, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion, OrganizationVersion: observed.Version, OrganizationCredentialVersion: observed.CredentialVersion, ReadStartedAt: started, VerifiedAt: verified, ValidUntil: until}
	current.OrganizationReadStartedAt, current.OrganizationVerifiedAt, current.OrganizationValidUntil = observed.ReadStartedAt, observed.VerifiedAt, observed.ValidUntil
	if err := current.Validate(binding, configuration, verified); err != nil {
		return out, err
	}
	return current, nil
}

// RequireOrganizationSourceAuthority fences the exact observation during the
// invoking contributor's real Work. Command scope must retain the trusted tenant,
// actual API-key actor and a nonhuman anonymous flow, with no USER substitute.
// The composing owner separately binds that flow to its grant and caller. Call
// again at final commit, propagating every error. Lock order is directory SHARE,
// organization SHARE, configuration UPDATE, exact key UPDATE. No callback,
// transaction, journal or new authentication is created; post-wait database time
// cannot renew original freshness. Missing organization composition denies.
func (s *Service) RequireOrganizationSourceAuthority(ctx context.Context, w kernel.Work, participant kernel.FeatureExecutionContributor, observed apikey.OrganizationSourceAuthorityObservation) error {
	if s == nil || s.config == nil || ctx == nil || participant == nil {
		return apikey.ErrInvalid
	}
	if s.organization == nil || s.organization.repository == nil {
		return apikey.ErrDenied
	}
	configuration, err := s.selectedConfiguration(observed.Binding.ConfigurationAuthority.ConfigurationID, observed.Binding.ConfigurationRevision)
	if err != nil {
		return apikey.ErrDenied
	}
	s = s.withConfiguration(configuration)
	if observed.Validate(observed.Binding, configuration, observed.VerifiedAt) != nil || observed.PolicyVersion != s.config().PolicyVersion {
		return apikey.ErrDenied
	}
	binding, _, _, err := w.FeatureScope(participant)
	owner := observed.Binding.Owner.Spec()
	commandMatches := err == nil && binding.TenantID == owner.TenantID && binding.UserID == "" && binding.AnonymousFlowID != "" && binding.ActorKind == authorization.SubjectAPIKey && binding.ActorID == identity.ActorID(observed.Binding.KeyID)
	if !commandMatches {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	directory := kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().Profile.GlobalAuthorityID, TenantID: owner.TenantID}, GlobalVersion: observed.GlobalVersion, TenantVersion: observed.TenantVersion}
	if err := w.RequireActiveDirectoryAuthority(ctx, participant, directory); err != nil {
		return err
	}
	// Retain the org owner's exact original clock-domain projection. Its wall
	// clock must not receive a future primary-DB timestamp under allowed skew.
	organizationAuthority := sourceOrganizationAuthority(observed)
	if err := s.organization.repository.RequireCredentialAuthority(ctx, w, participant, organizationAuthority); err != nil {
		return err
	}
	if err := s.requireSourceConfiguration(ctx, w, apikey.SourceAuthorityBinding(observed.Binding), observed.ConfigurationAuthority); err != nil {
		return err
	}
	var wire []byte
	rows, err := w.Query(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3 AND organization_id=$4 FOR UPDATE`, string(owner.TenantID), configuration.Spec().ID, string(observed.Binding.KeyID), string(owner.OrganizationID))
	if err := scanSourceAuthorityRow(rows, err, &wire); err != nil {
		return err
	}
	want, err := encodeRecord(observed.Record, configuration)
	if err != nil || !bytes.Equal(wire, want) {
		return apikey.ErrDenied
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return observed.Validate(observed.Binding, configuration, now)
}

func sourceOrganizationAuthority(observed apikey.OrganizationSourceAuthorityObservation) organization.CredentialAuthorityObservation {
	owner := observed.Binding.Owner.Spec()
	return organization.CredentialAuthorityObservation{TenantID: owner.TenantID, OrganizationID: organization.ID(owner.OrganizationID), Version: observed.OrganizationVersion, CredentialVersion: observed.OrganizationCredentialVersion, ReadStartedAt: observed.OrganizationReadStartedAt, VerifiedAt: observed.OrganizationVerifiedAt, ValidUntil: observed.OrganizationValidUntil}
}
