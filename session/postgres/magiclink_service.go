package postgres

import (
	"context"
	"fmt"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// MagicLinkAdmissionConfig selects the trusted global authority, user policy
// namespace and audience for email-grant sessions. This single-factor profile
// rejects organization, factor and passkey projections until their actual owners
// are composed. Zero is invalid and configuration grants no authentication.
type MagicLinkAdmissionConfig struct{ GlobalAuthorityID, PolicyNamespace, Audience string }

// MagicLinkSessionServiceConfig selects the explicit native stateful magic-link
// reader. The borrowed primary pool outlives calls; the caller closes it. Install
// directory/user/identifier/authorization histories and MagicLinkMigrationSource
// before use. Validation owns key/clock/read budgets. No arbitrary domain store,
// proof authority, sender or persistent password credential is accepted.
type MagicLinkSessionServiceConfig struct {
	Repository Config
	Profile    MagicLinkAdmissionConfig
	Validation session.ServiceConfig
}

// NewMagicLinkSessionService composes real bounded primary owner reads without
// IO, goroutines, writes or caches. It checks the original verified address and
// every current authority dimension. Original grant expiry is historical after
// issuance, not the session's expiry. Password/OTP factories remain disjoint;
// this factory neither certifies token consumption nor manufactures a session.
func NewMagicLinkSessionService(pool *database.Pool, c MagicLinkSessionServiceConfig) (*session.SessionService, error) {
	return newPossessionSessionService(pool, OTPSessionServiceConfig{Repository: c.Repository, Profile: OTPAdmissionConfig(c.Profile), Validation: c.Validation}, true)
}

func magicLinkSessionAdmission(c MagicLinkAdmissionConfig, record session.Session) (kernel.DirectoryAuthorityQuery, authority.AuthorityScope, error) {
	s, err := record.Bindings()
	p, metaErr := record.MagicLinkAuthentication().Bindings()
	profile := OTPAdmissionConfig(c)
	if err != nil || metaErr != nil || !profile.valid() || s.Authentication.Kind != session.AuthenticationMagicLink || s.Audience != c.Audience || p.IdentifierID == "" {
		return kernel.DirectoryAuthorityQuery{}, authority.AuthorityScope{}, session.ErrUnauthenticated
	}
	return verifiedIdentifierSessionAdmission(profile, s)
}

func (r *primarySessionReader) observeMagicLink(ctx context.Context, stored StoredSession, start time.Time) (session.SessionObservation, error) {
	query, scope, err := magicLinkSessionAdmission(*r.magicLink, stored.Session)
	if err != nil {
		return session.SessionObservation{}, err
	}
	p, _ := stored.Session.MagicLinkAuthentication().Bindings()
	return r.observeVerifiedIdentifier(ctx, stored, start, query, scope, verifiedIdentifierProvenance{p.IdentifierID, identity.IdentifierEmail, p.IdentifierVersion, p.VerificationVersion})
}

// Format redacts correlated deployment configuration for every verb.
func (MagicLinkAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MagicLinkAdmissionConfig(redacted)"))
}

// MarshalJSON denies implicit correlated deployment export.
func (MagicLinkAdmissionConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts key and deployment configuration for every verb.
func (MagicLinkSessionServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MagicLinkSessionServiceConfig(redacted)"))
}

// MarshalJSON denies implicit key/deployment export.
func (MagicLinkSessionServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
