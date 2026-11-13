package postgres

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func (s *Service) sourceAuthorizationScope(b apikey.SourceAuthorityBinding) authority.AuthorityScope {
	owner := b.Owner.Spec()
	return authority.AuthorityScope{
		TenantID:        authorization.TenantID(owner.TenantID),
		PolicyNamespace: s.config().Profile.PolicyNamespace,
		SubjectID:       authorization.SubjectID(owner.UserID),
	}
}

func sourceRecordMatches(b apikey.SourceAuthorityBinding, record apikey.Record) bool {
	rootMatches := record.ID == b.KeyID && record.RootID == b.RootID && record.RootVersion == b.RootVersion && record.AuthorityVersion == b.AuthorityVersion
	profileMatches := record.ConfigurationID == b.ConfigurationAuthority.ConfigurationID && record.ConfigurationRevision == b.ConfigurationRevision && record.Issuer == b.Issuer && record.Environment == b.Environment && record.Audience == b.Audience
	ownerMatches := record.Owner.SameIdentity(b.Owner) && record.Owner.Version() >= b.Owner.Version()
	if !rootMatches || !profileMatches || !ownerMatches || record.Status != apikey.KeyActive || !record.ExpiresAt.Equal(b.ExpiresAt) {
		return false
	}
	for _, permission := range b.Grant {
		if !slices.Contains(record.Grant, permission) {
			return false
		}
	}
	return true
}

// ObserveSourceAuthority reads current validity of one previously authenticated
// user-owned key in its exact selected profile. It authenticates no bearer or
// human actor, performs no debit or mutation and retains no secret. The caller
// separately proves its source credential and binds these facts to its exact
// operation/lineage. Only primary
// owners are used; errors return a zero observation without stale fallback.
// The service and its pool are borrowed and must outlive the bounded call.
func (s *Service) ObserveSourceAuthority(ctx context.Context, binding apikey.SourceAuthorityBinding) (out apikey.SourceAuthorityObservation, err error) {
	if s == nil || s.config == nil || ctx == nil {
		return out, apikey.ErrInvalid
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
			out, err = apikey.SourceAuthorityObservation{}, identity.UnavailableError{}
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
	if err != nil || !sourceRecordMatches(binding, record) {
		return out, apikey.ErrDenied
	}
	status, err := s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: owner.TenantID, UserID: owner.UserID})
	if err != nil || status.User.Status != identity.StatusActive {
		return out, apikey.ErrDenied
	}
	owner.Version = status.AuthorityVersion
	currentOwner, err := apikey.NewOwner(owner)
	if err != nil {
		return out, apikey.ErrDenied
	}
	policies, err := authority.NewAuthorityStore(s.pool.Raw(), s.config().MaximumDuration)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	policy, err := policies.Get(ctx, s.sourceAuthorizationScope(binding))
	if err != nil {
		return out, nativeError(ctx, err)
	}
	grant := make([]string, 0, len(binding.Grant))
	for _, permission := range binding.Grant {
		// The existing API-key policy resolves the owner's current permissions;
		// this user subject is not evidence of a human actor or session.
		decision, err := s.config().Authorization.Decide(ctx, s.decision(owner.TenantID, owner.UserID, permission, "api-key", record.ConfigurationID, ""))
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
	profile := s.config().Configuration.Spec()
	until := started.Add(20*time.Second - profile.ClockUncertainty - profile.DecisionRaceBudget).Truncate(time.Microsecond)
	if !binding.ExpiresAt.IsZero() {
		until = minTime(until, binding.ExpiresAt)
	}
	observation := apikey.SourceAuthorityObservation{
		Binding:                binding,
		Record:                 record,
		Owner:                  currentOwner,
		Grant:                  grant,
		PolicyVersion:          s.config().PolicyVersion,
		ConfigurationAuthority: configurationAuthority,
		GlobalVersion:          directory.GlobalVersion,
		TenantVersion:          directory.TenantVersion,
		UserVersion:            status.User.Version,
		UserAuthorityVersion:   status.AuthorityVersion,
		AuthorizationVersion:   policy.Version,
		ReadStartedAt:          started,
		VerifiedAt:             verified,
		ValidUntil:             until,
	}
	if err := observation.Validate(binding, s.config().Configuration, verified); err != nil {
		return out, err
	}
	return observation, nil
}

// RequireSourceAuthority fences one exact observation inside the invoking
// participant's existing Work. The command must retain the source's user owner
// and API-key actor, never a fabricated human actor. Call in preparation/apply
// and again at the final commit check; propagate every error. No transaction,
// journal, callbacks or source authentication is introduced.
// Locks follow the existing key owner: directory/user/scoped authorization,
// configuration UPDATE, then exact key UPDATE. The database-time check follows
// all waits and never renews the original observation's deadline.
func (s *Service) RequireSourceAuthority(ctx context.Context, w kernel.Work, participant kernel.FeatureExecutionContributor, observed apikey.SourceAuthorityObservation) error {
	if s == nil || s.config == nil || ctx == nil || participant == nil {
		return apikey.ErrInvalid
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
	commandMatches := err == nil && binding.TenantID == owner.TenantID && binding.UserID == owner.UserID && binding.ActorKind == authorization.SubjectAPIKey && binding.ActorID == identity.ActorID(observed.Binding.KeyID)
	if !commandMatches {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	directory := kernel.DirectoryAuthorityAdmission{
		Query:         kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().Profile.GlobalAuthorityID, TenantID: owner.TenantID},
		GlobalVersion: observed.GlobalVersion,
		TenantVersion: observed.TenantVersion,
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, participant, directory); err != nil {
		return err
	}
	status := identity.UserStatusRecord{
		User:             identity.User{ID: owner.UserID, TenantID: owner.TenantID, Status: identity.StatusActive, Version: observed.UserVersion},
		AuthorityVersion: observed.UserAuthorityVersion,
	}
	if err := w.RequireActiveUserStatus(ctx, participant, status); err != nil {
		return err
	}
	policy := kernel.UserAuthorizationAdmission{Scope: s.sourceAuthorizationScope(observed.Binding), Version: observed.AuthorizationVersion}
	if err := w.RequireActiveUserAuthorization(ctx, participant, policy); err != nil {
		return err
	}
	if err := s.requireSourceConfiguration(ctx, w, observed); err != nil {
		return err
	}
	var wire []byte
	rows, err := w.Query(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3 AND user_id=$4 FOR UPDATE`, string(owner.TenantID), configuration.Spec().ID, string(observed.Binding.KeyID), string(owner.UserID))
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

func (s *Service) requireSourceConfiguration(ctx context.Context, w kernel.Work, observed apikey.SourceAuthorityObservation) error {
	var version string
	var digest []byte
	var enabled bool
	rows, err := w.Query(ctx, `SELECT authority_version::text,configuration_digest,enabled FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2 FOR UPDATE`, string(observed.Binding.Owner.Spec().TenantID), s.config().Configuration.Spec().ID)
	if err := scanSourceAuthorityRow(rows, err, &version, &digest, &enabled); err != nil {
		return err
	}
	want, err := configurationDigest(s.config().Configuration)
	if err != nil || !enabled || version != strconv.FormatUint(observed.ConfigurationAuthority.Version, 10) || !bytes.Equal(digest, want[:]) {
		return apikey.ErrDenied
	}
	return nil
}

func scanSourceAuthorityRow(rows *kernel.WorkRows, err error, targets ...any) error {
	if err != nil {
		return err
	}
	if rows == nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return apikey.ErrDenied
	}
	if err := rows.Scan(targets...); err != nil {
		return err
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	return rows.Err()
}
