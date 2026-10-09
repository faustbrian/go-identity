package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// SessionServiceConfig selects an explicit single-factor stateful profile.
// Repository borrows a migrated PRIMARY pool; its read budget must not exceed
// Validation.MaximumDuration. Profile's audience must equal Validation's.
// Directory, user/status, identifier, credential, authorization and session
// migrations are required. Validation retains core clock/key/profile semantics.
// No application-written domain store, transaction or policy callback is used.
type SessionServiceConfig struct {
	Repository Config
	Profile    IdentifierAdmissionConfig
	Validation session.ServiceConfig
}

// Format redacts profile and key configuration.
func (SessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SessionServiceConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (SessionServiceConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSessionService composes the owned primary reader with core credential
// validation without IO. The caller closes its pool only after all operations
// finish. There are no goroutines, caches, writes or independently owned stores.
// This profile rejects anonymous, organization, MFA and passkey records until
// their native authority owners are composed; it never drops a dimension.
func NewSessionService(pool *database.Pool, c SessionServiceConfig) (*session.SessionService, error) {
	if !c.Profile.valid() || c.Profile.CredentialKind == identity.CredentialPasskey || c.Profile.Audience != c.Validation.Audience || c.Repository.MaximumDuration > c.Validation.MaximumDuration {
		return nil, session.ErrInvalidInput
	}
	native, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, err
	}
	policy, err := authority.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	profile := c.Profile
	profile.GlobalAuthorityID = strings.Clone(profile.GlobalAuthorityID)
	profile.PolicyNamespace = strings.Clone(profile.PolicyNamespace)
	profile.Audience = strings.Clone(profile.Audience)
	profile.AuthenticationMethod = strings.Clone(profile.AuthenticationMethod)
	profile.CredentialOwner = strings.Clone(profile.CredentialOwner)
	return session.NewSessionService(&primarySessionReader{native: native, domain: domain, policy: policy, profile: profile, clock: c.Validation.Clock}, c.Validation)
}

// Kept private: consumers configure the factory, not arbitrary owner readers.
type primarySessionReader struct {
	native  *Repository
	domain  *kernel.Repository
	policy  *authority.AuthorityStore
	profile IdentifierAdmissionConfig
	clock   session.IssuerClock
	otp     *OTPAdmissionConfig
}

var _ session.SessionReader = (*primarySessionReader)(nil)

func (r *primarySessionReader) ObserveSession(ctx context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
	if r == nil || r.native == nil || r.domain == nil || r.policy == nil || nilIssueDependency(r.clock) || ctx == nil || !scopeID(string(lookup.TenantID)) || len(lookup.Digests) < 1 || len(lookup.Digests) > 4 {
		return session.SessionObservation{}, session.ErrInvalidInput
	}
	for i, digest := range lookup.Digests {
		if digest.KeyVersion == 0 || digest.Sum == ([32]byte{}) {
			return session.SessionObservation{}, session.ErrInvalidInput
		}
		for _, previous := range lookup.Digests[:i] {
			if previous.KeyVersion == digest.KeyVersion {
				return session.SessionObservation{}, session.ErrInvalidInput
			}
		}
	}
	bounded, stop := context.WithTimeout(ctx, r.native.maximumDuration)
	defer stop()
	// This sample precedes even the first token lookup. Later contributing
	// owner reads and retries cannot restart its positive-evidence lifetime.
	start := r.clock.Now()
	if !sessionReadTime(start) {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	var stored StoredSession
	found := false
	for _, digest := range lookup.Digests {
		candidate, err := r.native.Lookup(bounded, lookup.TenantID, digest)
		if errors.Is(err, ErrRecordAbsent) {
			continue
		}
		if err != nil {
			return session.SessionObservation{}, err
		}
		if found {
			return session.SessionObservation{}, session.ErrUnauthenticated
		}
		stored, found = candidate, true
	}
	if !found || stored.Revoked || stored.FamilyRevoked {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	spec, err := stored.Session.Bindings()
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	if r.otp != nil {
		return r.observeOTP(bounded, stored, start)
	}
	binding := identity.CommandBinding{TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser}
	directory, credential, policy, err := sessionAdmissionBindings(r.profile, stored.Session, binding, spec.SessionID, spec.Version)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	currentDirectory, err := r.domain.GetDirectoryAuthority(bounded, directory.Query)
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	status, err := r.domain.GetStatus(bounded, identity.UserStatusQuery{TenantID: spec.TenantID, UserID: spec.UserID})
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	// Consume the existing public identifier owner, never duplicate its schema.
	// Its finite 128-record bound denies incomplete or corrupt projections.
	identifiers, err := r.domain.GetIdentifierState(bounded, identity.IdentifierQuery{TenantID: spec.TenantID, UserID: spec.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	currentCredential, err := r.domain.GetCredentialAuthority(bounded, identity.CredentialAuthorityQuery{TenantID: spec.TenantID, UserID: spec.UserID, CredentialID: credential.Credential.ID})
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	currentPolicy, err := r.policy.Get(bounded, policy.Scope)
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	now := r.clock.Now()
	if bounded.Err() != nil {
		return session.SessionObservation{}, readError(bounded, bounded.Err())
	}
	if !sessionReadTime(now) || now.Before(start) {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	if !currentDirectory.Enabled || !status.User.Status.AllowsAuthentication() || !identifiers.User.Status.AllowsAuthentication() || identity.CheckCredentialAuthority(currentCredential, credential.Credential, credential.CredentialAuthorityVersion, now) != nil {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	vector, _ := spec.Authority.Bindings()
	vector.Global.Version, vector.Tenant.Version = currentDirectory.GlobalVersion, currentDirectory.TenantVersion
	vector.User.Version, vector.Identifier.Version = status.AuthorityVersion, identifiers.AuthorityVersion
	vector.Credential.Version = currentCredential.AuthorityVersion
	vector.SessionFamily.Version, vector.Session.Version = stored.CurrentFamilyVersion, spec.Version
	vector.Authorization.Version = currentPolicy.Version
	current, err := session.NewAuthoritySnapshot(vector)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	until := start.Add(20 * time.Second)
	if !currentCredential.ExpiresAt.IsZero() && currentCredential.ExpiresAt.Before(until) {
		until = currentCredential.ExpiresAt
	}
	if !now.Before(until) {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	return session.SessionObservation{Session: stored.Session, Current: current, Active: true, ReadStartedAt: start.UTC(), ValidUntil: until.UTC()}, nil
}

func sessionReadTime(now time.Time) bool {
	return !now.IsZero() && now.UTC().Year() >= 1 && now.UTC().Year() <= 9999
}

func observationError(err error) error {
	var forbidden identity.ForbiddenError
	if errors.Is(err, identity.ErrUserAbsent) || errors.Is(err, authority.ErrAuthorityDenied) || errors.As(err, &forbidden) {
		return session.ErrUnauthenticated
	}
	return err
}
