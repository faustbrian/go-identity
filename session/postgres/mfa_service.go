package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// MFAMagicLinkSessionServiceConfig explicitly selects original magic-link plus
// confirmed TOTP or recovery-code authentication. Recovery consumption is
// historical, not a requirement for another unused code. Single-factor factories
// remain disjoint. The
// primary pool outlives calls; install directory, authorization, MFA/TOTP and
// complete session histories. Validation retains its owned clock/key/budgets.
type MFAMagicLinkSessionServiceConfig struct {
	Repository Config
	Profile    MagicLinkAdmissionConfig
	Validation session.ServiceConfig
}

// NewMFAMagicLinkSessionService composes current primary owners without IO,
// writes, goroutines or caches. The original exact confirmed factor enrollment
// and generation remain mandatory; expired continuation/grant times are history
// after issuance, not renewed evidence or session expiry. Cache custody has a
// distinct MFA profile and cannot be promoted into a single-factor reader.
func NewMFAMagicLinkSessionService(pool *database.Pool, c MFAMagicLinkSessionServiceConfig) (*session.SessionService, error) {
	profile := OTPAdmissionConfig(c.Profile)
	if !profile.valid() || profile.Audience != c.Validation.Audience || c.Repository.MaximumDuration > c.Validation.MaximumDuration {
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
	authority, err := policy.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	factors, err := mfapg.NewTOTPSessionFactorReader(pool, c.Repository.MaximumDuration)
	if err != nil {
		return nil, session.ErrInvalidInput
	}
	p := MagicLinkAdmissionConfig{GlobalAuthorityID: strings.Clone(profile.GlobalAuthorityID), PolicyNamespace: strings.Clone(profile.PolicyNamespace), Audience: strings.Clone(profile.Audience)}
	r := &primarySessionReader{native: native, domain: domain, policy: authority, clock: c.Validation.Clock, mfaMagicLink: &p, mfaFactors: factors}
	cacheProfile := nativeAdmissionCacheProfile("native-mfa-magic-link-totp-recovery-session-v2", c.Repository.Schema, p.GlobalAuthorityID, p.PolicyNamespace, p.Audience)
	return session.NewProfileSessionService(r, c.Validation, session.AuthenticationMagicLink, cacheProfile)
}

func mfaMagicLinkSessionAdmission(c MagicLinkAdmissionConfig, record session.Session) (kernel.DirectoryAuthorityQuery, policy.AuthorityScope, error) {
	s, err := record.Bindings()
	m, me := record.MFAAuthentication().Bindings()
	primary, pe := record.MagicLinkAuthentication().Bindings()
	if err != nil || me != nil || pe != nil || !OTPAdmissionConfig(c).valid() || s.Audience != c.Audience || s.Authentication.Kind != session.AuthenticationMagicLink || m.Method != "totp" && m.Method != "recovery-code" || m.PrimaryCommandID != primary.CommandID {
		return kernel.DirectoryAuthorityQuery{}, policy.AuthorityScope{}, session.ErrUnauthenticated
	}
	key, err := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	if err != nil {
		return kernel.DirectoryAuthorityQuery{}, policy.AuthorityScope{}, session.ErrUnauthenticated
	}
	factor := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: key, Version: m.FactorAuthorityVersion}}
	return verifiedIdentifierSessionAdmissionWithFactor(OTPAdmissionConfig(c), s, factor)
}

func (r *primarySessionReader) observeMFAMagicLink(ctx context.Context, stored StoredSession, start time.Time) (session.SessionObservation, error) {
	q, scope, err := mfaMagicLinkSessionAdmission(*r.mfaMagicLink, stored.Session)
	if err != nil {
		return session.SessionObservation{}, err
	}
	s, _ := stored.Session.Bindings()
	m, _ := stored.Session.MFAAuthentication().Bindings()
	p, _ := stored.Session.MagicLinkAuthentication().Bindings()
	factor, err := r.mfaFactors.Read(ctx, s.TenantID, s.UserID, m.FactorID)
	if err != nil {
		return session.SessionObservation{}, observationError(err)
	}
	if factor.EnrollmentVersion != m.EnrollmentVersion {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	observed, err := r.observeVerifiedIdentifier(ctx, stored, start, q, scope, verifiedIdentifierProvenance{p.IdentifierID, identity.IdentifierEmail, p.IdentifierVersion, p.VerificationVersion})
	if err != nil {
		return session.SessionObservation{}, err
	}
	a, _ := observed.Current.Bindings()
	a.Factor.Binding.Version = factor.AuthorityVersion
	observed.Current, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	// Preserve original ReadStartedAt/ValidUntil; this owner read cannot renew it.
	return observed, nil
}

// Format redacts deployment and key configuration.
func (MFAMagicLinkSessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAMagicLinkSessionServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration export.
func (MFAMagicLinkSessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit export and map-key disclosure.
func (MFAMagicLinkSessionServiceConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
