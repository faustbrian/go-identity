package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
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
	return newPasswordSessionService(pool, c, false)
}

func newPasswordSessionService(pool *database.Pool, c SessionServiceConfig, mfa bool) (*session.SessionService, error) {
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
	cacheProfile := nativeAdmissionCacheProfile(c.Repository.Schema, profile.GlobalAuthorityID, profile.PolicyNamespace, profile.Audience, profile.AuthenticationMethod, string(profile.CredentialKind), profile.CredentialOwner)
	r := &primarySessionReader{native: native, domain: domain, policy: policy, profile: profile, clock: c.Validation.Clock, mfaPassword: mfa}
	if mfa {
		if profile.AuthenticationMethod != "password" || profile.CredentialKind != identity.CredentialPassword || profile.CredentialOwner != "identity/password" {
			return nil, session.ErrInvalidInput
		}
		r.mfaFactors, err = mfapg.NewTOTPSessionFactorReader(pool, c.Repository.MaximumDuration)
		if err != nil {
			return nil, session.ErrInvalidInput
		}
		r.mfaOTPFactors, err = mfapg.NewOTPSessionFactorReader(pool, c.Repository.MaximumDuration)
		if err != nil {
			return nil, session.ErrInvalidInput
		}
		cacheProfile = nativeAdmissionCacheProfile("native-mfa-password-totp-otp-recovery-session-v3", cacheProfile)
	}
	return session.NewProfileSessionService(r, c.Validation, session.AuthenticationVerified, cacheProfile)
}

// Canonical selected native authority and storage configuration is authenticated
// cache context, not a new validity vector. The envelope already binds issuer,
// environment, epoch and audience; deployments sharing those keys must still
// distinguish separate primary stores through that explicit deployment context.
func nativeAdmissionCacheProfile(fields ...string) string {
	encoded, _ := json.Marshal(fields) // A string slice has no failing JSON arm.
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Kept private: consumers configure the factory, not arbitrary owner readers.
type primarySessionReader struct {
	native            *Repository
	domain            *kernel.Repository
	policy            *authority.AuthorityStore
	profile           IdentifierAdmissionConfig
	clock             session.IssuerClock
	otp               *OTPAdmissionConfig
	magicLink         *MagicLinkAdmissionConfig
	mfaMagicLink      *MagicLinkAdmissionConfig
	mfaFactors        *mfapg.TOTPSessionFactorReader
	mfaOTPFactors     *mfapg.OTPSessionFactorReader
	mfaPassword       bool
	mfaPasswordReader *primarySessionReader
	passkey           *passkeySessionSelection
	passkeyReader     *primarySessionReader
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
	// MFA is an additional immutable dimension, not another authentication
	// kind. Dispatch it first: no single-factor reader may erase that dimension,
	// even when both magic-link profiles are selected by the same graph.
	if stored.Session.MFAAuthentication() != (session.MFAAuthentication{}) {
		if spec.Authentication.Kind == session.AuthenticationVerified && r.mfaPasswordReader != nil {
			return r.mfaPasswordReader.observeCredential(bounded, stored, start)
		}
		if spec.Authentication.Kind == session.AuthenticationVerified && r.mfaPassword && r.mfaFactors != nil {
			return r.observeCredential(bounded, stored, start)
		}
		if spec.Authentication.Kind != session.AuthenticationMagicLink || r.mfaMagicLink == nil || r.mfaFactors == nil {
			return session.SessionObservation{}, session.ErrUnauthenticated
		}
		return r.observeMFAMagicLink(bounded, stored, start)
	}
	if r.otp != nil && spec.Authentication.Kind == session.AuthenticationOTP {
		return r.observeOTP(bounded, stored, start)
	}
	if r.magicLink != nil && spec.Authentication.Kind == session.AuthenticationMagicLink {
		return r.observeMagicLink(bounded, stored, start)
	}
	vector, _ := spec.Authority.Bindings()
	if spec.Authentication.Proof.Method == "passkey" || vector.Passkey.Present {
		if r.passkeyReader != nil {
			return r.passkeyReader.observeCredential(bounded, stored, start)
		}
		if r.passkey == nil {
			return session.SessionObservation{}, session.ErrUnauthenticated
		}
		return r.observeCredential(bounded, stored, start)
	}
	if spec.Authentication.Kind != session.AuthenticationVerified || !r.profile.valid() {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	if r.mfaPassword {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	return r.observeCredential(bounded, stored, start)
}

func (r *primarySessionReader) observeCredential(bounded context.Context, stored StoredSession, start time.Time) (session.SessionObservation, error) {
	spec, err := stored.Session.Bindings()
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	binding := identity.CommandBinding{TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser}
	directory, credential, policy, err := sessionAdmissionBindings(r.profile, stored.Session, binding, spec.SessionID, spec.Version)
	if r.mfaPassword {
		directory, credential, policy, err = passwordMFASessionAdmission(r.profile, stored.Session, binding, spec.SessionID, spec.Version)
	}
	if r.passkey != nil {
		directory, credential, policy, err = passkeySessionAdmission(r.passkey.profile, stored.Session, binding)
	}
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
	var factorVersion uint64
	var passkeyObserved PasskeySessionAuthorityObservation
	if r.passkey != nil {
		passkeyObserved, err = r.passkey.authority.ObservePasskeySession(bounded, r.passkey.profile.RPNamespace, stored.Session)
		if err != nil {
			return session.SessionObservation{}, observationError(err)
		}
	}
	if r.mfaPassword {
		if r.mfaFactors == nil {
			return session.SessionObservation{}, session.ErrUnauthenticated
		}
		m, _ := stored.Session.MFAAuthentication().Bindings()
		if m.Method == "otp" {
			if r.mfaOTPFactors == nil {
				return session.SessionObservation{}, session.ErrUnauthenticated
			}
			factor, e := r.mfaOTPFactors.Read(bounded, spec.TenantID, spec.UserID, m.FactorID)
			if e != nil {
				return session.SessionObservation{}, observationError(e)
			}
			if factor.EnrollmentVersion != m.EnrollmentVersion {
				return session.SessionObservation{}, session.ErrUnauthenticated
			}
			factorVersion = factor.AuthorityVersion
		} else {
			factor, e := r.mfaFactors.Read(bounded, spec.TenantID, spec.UserID, m.FactorID)
			if e != nil {
				return session.SessionObservation{}, observationError(e)
			}
			if factor.EnrollmentVersion != m.EnrollmentVersion {
				return session.SessionObservation{}, session.ErrUnauthenticated
			}
			factorVersion = factor.AuthorityVersion
		}
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
	if r.mfaPassword {
		vector.Factor.Binding.Version = factorVersion
	}
	current, err := session.NewAuthoritySnapshot(vector)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	until := start.Add(20 * time.Second)
	if r.passkey != nil {
		var err error
		start, until, err = passkeyObservationBounds(passkeyObserved, start, now)
		if err != nil {
			return session.SessionObservation{}, err
		}
		vector.Passkey.Binding.Version = passkeyObserved.PasskeyVersion
		vector.Factor.Binding.Version = passkeyObserved.FactorVersion
		current, err = session.NewAuthoritySnapshot(vector)
		if err != nil {
			return session.SessionObservation{}, session.ErrUnavailable
		}
	}
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
