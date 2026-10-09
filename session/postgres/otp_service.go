package postgres

import (
	"context"
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

// OTPAdmissionConfig selects the exact trusted deployment, user authorization
// namespace and session audience. It admits only single-factor email/phone OTP
// records, without inventing a persistent credential reference. Organization,
// factor and passkey dimensions deny until their owners are composed. Zero is
// invalid; configuration is neither authentication nor a policy Allow decision.
type OTPAdmissionConfig struct {
	GlobalAuthorityID, PolicyNamespace, Audience string
}

func (c OTPAdmissionConfig) valid() bool {
	return (kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: "tenant"}).Validate() == nil &&
		(authority.AuthorityScope{TenantID: "tenant", PolicyNamespace: c.PolicyNamespace, SubjectID: "user"}).Validate() == nil && len(c.Audience) <= 256 && visibleAdmissionText(c.Audience)
}

// Format redacts correlated deployment configuration.
func (OTPAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPAdmissionConfig(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration export.
func (OTPAdmissionConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// OTPSessionServiceConfig selects the explicit native OTP stateful reader.
// Repository and Validation retain SessionServiceConfig's lifetime, ownership
// and finite read-budget rules. Install directory, user security, identifier,
// authorization and OTP-capable session migrations before use. No credential
// references, provider callbacks, alternate stores or transaction are accepted.
type OTPSessionServiceConfig struct {
	Repository Config
	Profile    OTPAdmissionConfig
	Validation session.ServiceConfig
}

// Format redacts profile and key configuration.
func (OTPSessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPSessionServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (OTPSessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewOTPSessionService composes the owned primary OTP reader without IO. The
// borrowed pool must be primary and outlive calls; the caller closes it. There
// are no goroutines, caches or writes. The original verified identifier and all
// current authority dimensions must still agree. Original OTP expiry is history,
// not an issued session's expiry. Existing NewSessionService stays proof-only;
// neither factory manufactures issuance or accepts the other method implicitly.
func NewOTPSessionService(pool *database.Pool, c OTPSessionServiceConfig) (*session.SessionService, error) {
	if !c.Profile.valid() || c.Profile.Audience != c.Validation.Audience || c.Repository.MaximumDuration > c.Validation.MaximumDuration {
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
	profile.GlobalAuthorityID, profile.PolicyNamespace, profile.Audience = strings.Clone(profile.GlobalAuthorityID), strings.Clone(profile.PolicyNamespace), strings.Clone(profile.Audience)
	return session.NewSessionService(&primarySessionReader{native: native, domain: domain, policy: policy, clock: c.Validation.Clock, otp: &profile}, c.Validation)
}

// This derives keys only. Current authority always comes from its primary owner.
func otpSessionAdmission(c OTPAdmissionConfig, record session.Session) (kernel.DirectoryAuthorityQuery, authority.AuthorityScope, error) {
	deny := func() (kernel.DirectoryAuthorityQuery, authority.AuthorityScope, error) {
		return kernel.DirectoryAuthorityQuery{}, authority.AuthorityScope{}, session.ErrUnauthenticated
	}
	s, err := record.Bindings()
	if err != nil || !c.valid() || s.Authentication.Kind != session.AuthenticationOTP || s.Audience != c.Audience {
		return deny()
	}
	if _, err := record.OTPAuthentication().Bindings(); err != nil {
		return deny()
	}
	a, err := s.Authority.Bindings()
	if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return deny()
	}
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: s.TenantID}
	keys, err := kernel.KernelAuthorityKeys(query, s.UserID)
	if err != nil {
		return deny()
	}
	sk, err := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return deny()
	}
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: c.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}
	pk, err := scope.Key()
	if err != nil || a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User.ScopeKey != keys.User || a.Identifier.ScopeKey != keys.Identifier || a.Credential.ScopeKey != keys.Credential || a.SessionFamily.ScopeKey != sk.Family || a.Session.ScopeKey != sk.Session || a.Authorization.ScopeKey != pk {
		return deny()
	}
	return query, scope, nil
}

func (r *primarySessionReader) observeOTP(ctx context.Context, stored StoredSession, start time.Time) (session.SessionObservation, error) {
	query, scope, err := otpSessionAdmission(*r.otp, stored.Session)
	if err != nil {
		return session.SessionObservation{}, err
	}
	s, _ := stored.Session.Bindings()
	p, _ := stored.Session.OTPAuthentication().Bindings()
	directory, err := r.domain.GetDirectoryAuthority(ctx, query)
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	identifiers, err := r.domain.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: s.TenantID, UserID: s.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	var canonical string
	for _, identifier := range identifiers.Identifiers {
		if identifier.ID == p.IdentifierID && identifier.Kind == p.IdentifierKind && identifier.Version == p.IdentifierVersion && identifier.Verified {
			canonical = identifier.CanonicalValue
		}
	}
	if canonical == "" || !directory.Enabled {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	// Reuse the identity owner for all three security epochs and exact verified
	// identifier. The session's actual user restricts resolution; an address
	// reassigned to another user can never retarget this session.
	recipient, err := r.domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: s.TenantID, UserID: s.UserID, Kind: p.IdentifierKind, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	if recipient.Suppressed || recipient.User.ID != s.UserID || recipient.Identifier.ID != p.IdentifierID || recipient.Identifier.Version != p.IdentifierVersion || recipient.Verification.IdentifierID != p.IdentifierID || recipient.Verification.Version != p.VerificationVersion || recipient.Verification.State != identity.VerificationVerified {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	policy, err := r.policy.Get(ctx, scope)
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	now := r.clock.Now()
	if ctx.Err() != nil {
		return session.SessionObservation{}, readError(ctx, ctx.Err())
	}
	if !sessionReadTime(now) || now.Before(start) {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	until := start.Add(20 * time.Second)
	if !now.Before(until) {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	a, _ := s.Authority.Bindings()
	a.Global.Version, a.Tenant.Version = directory.GlobalVersion, directory.TenantVersion
	a.User.Version, a.Identifier.Version, a.Credential.Version = recipient.UserAuthorityVersion, recipient.IdentifierAuthorityVersion, recipient.CredentialAuthorityVersion
	a.SessionFamily.Version, a.Session.Version, a.Authorization.Version = stored.CurrentFamilyVersion, s.Version, policy.Version
	current, err := session.NewAuthoritySnapshot(a)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	return session.SessionObservation{Session: stored.Session, Current: current, Active: true, ReadStartedAt: start.UTC(), ValidUntil: until.UTC()}, nil
}
