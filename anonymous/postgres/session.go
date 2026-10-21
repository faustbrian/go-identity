package anonymouspostgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// SessionServiceConfig explicitly selects anonymous lifecycle and session
// schemas on one borrowed PRIMARY pool. Both owner IO budgets must fit within
// Validation.MaximumDuration. Directory, anonymous kernel/lifecycle, session
// issuance and guest-policy histories must already be installed. Validation's
// clock and retained lookup keys keep the session owner's existing semantics.
// Applications supply configuration, not domain stores or authority readers.
type SessionServiceConfig struct {
	Repository Config
	Sessions   sessionpg.Config
	Profile    sessionpg.AnonymousAdmissionConfig
	Validation session.ServiceConfig
}

func (SessionServiceConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.SessionServiceConfig(redacted)"))
}
func (SessionServiceConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (SessionServiceConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// NewSessionService composes the actual lifecycle, kernel, session and policy
// primary owners with the existing anonymous-only core validator. Construction
// has no IO and owns no pool, goroutine, cache, transaction or token. The caller
// closes its pool only after calls finish. Reads are concurrent-safe, never
// create a credential reference and return only unprivileged anonymous custody;
// existing verified-user session APIs remain closed to this method.
func NewSessionService(pool *database.Pool, c SessionServiceConfig) (*session.AnonymousSessionService, error) {
	p := c.Profile
	if p.Audience != c.Validation.Audience ||
		(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.GlobalAuthorityID, TenantID: "tenant"}).Validate() != nil ||
		(policy.AuthorityScope{TenantID: "tenant", PolicyNamespace: p.PolicyNamespace, SubjectID: "user"}).Validate() != nil ||
		c.Repository.MaximumDuration > c.Validation.MaximumDuration || c.Sessions.MaximumDuration > c.Validation.MaximumDuration {
		return nil, anonymous.ErrInvalidInput
	}
	lifecycle, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	sessions, err := sessionpg.NewRepository(pool, c.Sessions)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	authority, err := policy.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	reader := &anonymousSessionReader{lifecycle: lifecycle, sessions: sessions, domain: domain, policy: authority, profile: p, clock: c.Validation.Clock, maximum: c.Validation.MaximumDuration}
	return session.NewAnonymousSessionService(reader, c.Validation)
}

// Kept private: applications select concrete owners through the factory, not a
// replacement observation store that could turn structural metadata into proof.
type anonymousSessionReader struct {
	lifecycle *Repository
	sessions  *sessionpg.Repository
	domain    *kernel.Repository
	policy    *policy.AuthorityStore
	profile   sessionpg.AnonymousAdmissionConfig
	clock     session.IssuerClock
	maximum   time.Duration
}

var _ session.SessionReader = (*anonymousSessionReader)(nil)

func (r *anonymousSessionReader) ObserveSession(ctx context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
	if r == nil || ctx == nil || r.lifecycle == nil || r.sessions == nil || r.domain == nil || r.policy == nil || r.clock == nil || r.maximum <= 0 || len(lookup.Digests) < 1 || len(lookup.Digests) > 4 {
		return session.SessionObservation{}, session.ErrInvalidInput
	}
	for j, digest := range lookup.Digests {
		if digest.KeyVersion == 0 || digest.Sum == ([32]byte{}) {
			return session.SessionObservation{}, session.ErrInvalidInput
		}
		for _, previous := range lookup.Digests[:j] {
			if previous.KeyVersion == digest.KeyVersion {
				return session.SessionObservation{}, session.ErrInvalidInput
			}
		}
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	// SI-05: sample BEFORE the first contributing lookup. Owner IO and later
	// lifecycle/policy reads must never begin another positive-evidence window.
	start := r.clock.Now()
	if !readInstant(start) {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	var stored sessionpg.StoredSession
	found := false
	for _, digest := range lookup.Digests {
		candidate, err := r.sessions.Lookup(bounded, lookup.TenantID, digest)
		if errors.Is(err, sessionpg.ErrRecordAbsent) {
			continue
		}
		if err != nil {
			return session.SessionObservation{}, anonymousObservationError(err)
		}
		if found {
			return session.SessionObservation{}, session.ErrUnauthenticated
		}
		stored, found = candidate, true
	}
	if !found || stored.Revoked || stored.FamilyRevoked {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	s, err := stored.Session.Bindings()
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	a, err := s.Authority.Bindings()
	if err != nil || s.TenantID != lookup.TenantID || s.Audience != r.profile.Audience || s.Authentication.Kind != session.AuthenticationAnonymous || a.Organization.Present || a.Factor.Present || a.Passkey.Present || stored.Session.MFAAuthentication() != (session.MFAAuthentication{}) {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: r.profile.GlobalAuthorityID, TenantID: s.TenantID}
	keys, err := kernel.KernelAuthorityKeys(query, s.UserID)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	sessionKeys, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	scope := policy.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: r.profile.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}
	policyKey, err := scope.Key()
	if err != nil || a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User.ScopeKey != keys.User || a.Identifier.ScopeKey != keys.Identifier || a.Credential.ScopeKey != keys.Credential || a.SessionFamily.ScopeKey != sessionKeys.Family || a.Session.ScopeKey != sessionKeys.Session || a.Authorization.ScopeKey != policyKey {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	directory, err := r.domain.GetDirectoryAuthority(bounded, query)
	if err != nil {
		return session.SessionObservation{}, anonymousObservationError(err)
	}
	user, err := r.domain.GetAnonymousAuthority(bounded, identity.UserStatusQuery{TenantID: s.TenantID, UserID: s.UserID})
	if err != nil {
		return session.SessionObservation{}, anonymousObservationError(err)
	}
	subject, err := r.lifecycle.Read(bounded, anonymous.SubjectQuery{TenantID: s.TenantID, UserID: s.UserID})
	if err != nil {
		return session.SessionObservation{}, anonymousObservationError(err)
	}
	currentPolicy, err := r.policy.Get(bounded, scope)
	if err != nil {
		return session.SessionObservation{}, anonymousObservationError(err)
	}
	now := r.clock.Now()
	if bounded.Err() != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	if !readInstant(now) || now.Before(start) {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	lifecycle, _ := subject.Record()
	if !directory.Enabled || !user.User.Status.AllowsAuthentication() || subject.RequireActive(s.TenantID, now) != nil || !s.Authentication.AnonymousAt.Equal(lifecycle.CreatedAt) {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	a.Global.Version, a.Tenant.Version = directory.GlobalVersion, directory.TenantVersion
	a.User.Version, a.Identifier.Version, a.Credential.Version = user.UserAuthorityVersion, user.IdentifierAuthorityVersion, user.CredentialAuthorityVersion
	a.SessionFamily.Version, a.Session.Version, a.Authorization.Version = stored.CurrentFamilyVersion, s.Version, currentPolicy.Version
	current, err := session.NewAuthoritySnapshot(a)
	if err != nil {
		return session.SessionObservation{}, session.ErrUnavailable
	}
	until := start.Add(20 * time.Second)
	if lifecycle.ExpiresAt.Before(until) {
		until = lifecycle.ExpiresAt
	}
	if !now.Before(until) {
		return session.SessionObservation{}, session.ErrUnauthenticated
	}
	return session.SessionObservation{Session: stored.Session, Current: current, Active: true, ReadStartedAt: start.UTC(), ValidUntil: until.UTC()}, nil
}

func readInstant(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

func anonymousObservationError(err error) error {
	var forbidden identity.ForbiddenError
	if errors.Is(err, anonymous.ErrSubjectAbsent) || errors.Is(err, identity.ErrUserAbsent) || errors.Is(err, policy.ErrAuthorityDenied) || errors.As(err, &forbidden) {
		return session.ErrUnauthenticated
	}
	return session.ErrUnavailable
}
