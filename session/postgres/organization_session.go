package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// OrganizationSessionAuthority is the narrow read/fence port implemented by
// the organization PostgreSQL owner. Observe must derive the exact tenant/org
// key and require current active organization and membership for the original
// session user. Require must compare its original positive epoch under retained
// organization/member locks in the given owner's existing Work. Neither may
// erase a selection, substitute another organization or renew original evidence.
//
// The implementation borrows the same primary database and honors ctx; it must
// not write, commit, retain Work or start goroutines. Missing/archived/removed or
// unknown authority denies. The caller separately authenticates bearer custody
// and checks every non-organization dimension. Independent calls are concurrent.
type OrganizationSessionAuthority interface {
	ObserveOrganizationSession(context.Context, session.Session) (OrganizationSessionAuthorityObservation, error)
	RequireOrganizationSession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, session.Session) error
}

// OrganizationSessionAuthorityObservation is current owner evidence, not a
// credential. Its exact organization ID/key must match the original selection;
// Authority.Version is the current positive organization aggregate epoch, not a
// membership or user-policy version. ReadStartedAt precedes all contributing IO
// and ValidUntil is exclusive, at most20s later. Copies cannot reset that bound.
type OrganizationSessionAuthorityObservation struct {
	OrganizationID            string
	Authority                 session.AuthorityBinding
	ReadStartedAt, ValidUntil time.Time
}

// OrganizationPasswordSessionAdmission opts into the owned organization fence
// for genuine single-factor password sessions. Profile must equal the selected
// password deployment/policy/audience; Authority is borrowed until calls finish.
// Unselected records retain ordinary password checks. MFA/passkey/other methods
// are not enabled or downgraded by this selection. Configuration is immutable
// and grants no authentication, membership or permission itself.
type OrganizationPasswordSessionAdmission struct {
	Profile   IdentifierAdmissionConfig
	Authority OrganizationSessionAuthority
}

func (p OrganizationPasswordSessionAdmission) valid() bool {
	return p.Profile.valid() && p.Profile.AuthenticationMethod == "password" && p.Profile.CredentialKind == identity.CredentialPassword && p.Profile.CredentialOwner == "identity/password" && !nilIssueDependency(p.Authority)
}

// Format redacts borrowed owner and deployment configuration.
func (OrganizationPasswordSessionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OrganizationPasswordSessionAdmission(redacted)"))
}

// MarshalJSON denies implicit configuration/borrowed-owner export.
func (OrganizationPasswordSessionAdmission) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func organizationSessionObservationBounds(original session.Session, o OrganizationSessionAuthorityObservation, start, now time.Time) (time.Time, time.Time, error) {
	s, err := original.Bindings()
	if err != nil {
		return time.Time{}, time.Time{}, session.ErrUnauthenticated
	}
	v, err := s.Authority.Bindings()
	if err != nil || !v.Organization.Present || o.OrganizationID != v.ActiveOrganizationID || o.Authority.ScopeKey != v.Organization.Binding.ScopeKey {
		return time.Time{}, time.Time{}, session.ErrUnauthenticated
	}
	return passkeyMappingObservationBounds(o.Authority.Version, o.ReadStartedAt, o.ValidUntil, start, now)
}
