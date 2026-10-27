package session

import (
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// SessionVersion is an exact positive session CAS version. Zero is invalid;
// observing a newer version does not renew an older admission or credential.
type SessionVersion uint64

// ActiveOrganizationSelection is trusted, non-secret selection intent for one
// exact session and tenant. SessionVersion is the expected source version.
// An empty OrganizationID clears selection and requires zero Authority. A
// present ID is bounded opaque ASCII and requires the organization's canonical
// scope and positive authority version. The organization owner must derive and
// validate that binding, active membership and lifecycle; these fields alone
// prove none of them. Selection is never permission or authentication.
type ActiveOrganizationSelection struct {
	SessionID      string
	TenantID       identity.TenantID
	SessionVersion SessionVersion
	OrganizationID string
	Authority      AuthorityBinding
}

// OrganizationSelectionCommandSpec projects immutable source and successor
// records for the organization owner's atomic active-set operation. Only the
// selected organization and exact session version/vector may change. No token,
// authority lease or transaction is conveyed by this projection.
type OrganizationSelectionCommandSpec struct {
	Binding           identity.CommandBinding
	Source, Successor Session
	Selection         ActiveOrganizationSelection
}

// OrganizationSelectionCommand freezes a neutral record transition. Zero is
// invalid; copies are concurrency-safe. The sole native organization command
// must enlist the session-owned CAS, membership/lifecycle admission and required
// effects in one coordinator transaction. Construction grants no authority.
type OrganizationSelectionCommand struct {
	state *OrganizationSelectionCommandSpec
}

// OrganizationSelectionOperation retains the logical organization's active-set
// ownership without importing it into the session module. Its native participant
// invokes a session-owned effect; this is not another session-owned operation
// or permission to dispatch a second feature in the protected transaction.
func OrganizationSelectionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.active-set", SchemaID: "organization-active-selection", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewOrganizationSelectionCommand constructs an exact self-session CAS without
// IO. Selection must name source's tenant, stable ID and current version; the
// command's human actor and effective user must match that source. The successor
// preserves lookup, family, original authentication/provenance, remember policy,
// activity and expiry. It increments only the session version and replaces or
// clears the organization dimension. Overflow and malformed/foreign input return
// ErrInvalidSessionCommand with no partial command. Native owners must separately
// require original authenticated custody and every current authority.
//
// Version-bound CSRF state is cleared, never copied to a new version. This
// constructor does not deliver replacement browser state; cookie composition
// must remain disabled until its own authorized replacement flow is selected.
func NewOrganizationSelectionCommand(b identity.CommandBinding, source Session, selection ActiveOrganizationSelection) (OrganizationSelectionCommand, error) {
	old, err := source.Bindings()
	if err != nil || b.ValidateFor(OrganizationSelectionOperation()) != nil || b.TenantID != old.TenantID || b.UserID != old.UserID || b.RecordID != old.SessionID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(old.UserID) || selection.TenantID != old.TenantID || selection.SessionID != old.SessionID || uint64(selection.SessionVersion) != old.Version || old.Version == ^uint64(0) {
		return OrganizationSelectionCommand{}, ErrInvalidSessionCommand
	}
	vector, err := old.Authority.Bindings()
	if err != nil || selection.OrganizationID == "" && selection.Authority != (AuthorityBinding{}) {
		return OrganizationSelectionCommand{}, ErrInvalidSessionCommand
	}
	next := old
	next.Version++
	vector.Session.Version = next.Version
	vector.ActiveOrganizationID = selection.OrganizationID
	vector.Organization = OptionalAuthorityBinding{}
	if selection.OrganizationID != "" {
		vector.Organization = OptionalAuthorityBinding{Present: true, Binding: selection.Authority}
	}
	next.Authority, err = NewAuthoritySnapshot(vector)
	if err != nil {
		return OrganizationSelectionCommand{}, ErrInvalidSessionCommand
	}
	successor, err := rebuildSession(next, source, CSRFState{})
	if err != nil {
		return OrganizationSelectionCommand{}, ErrInvalidSessionCommand
	}
	selection.SessionID = strings.Clone(selection.SessionID)
	selection.TenantID = identity.TenantID(strings.Clone(string(selection.TenantID)))
	selection.OrganizationID = strings.Clone(selection.OrganizationID)
	selection.Authority.ScopeKey = strings.Clone(selection.Authority.ScopeKey)
	return OrganizationSelectionCommand{&OrganizationSelectionCommandSpec{cloneCommandBinding(b), source, successor, selection}}, nil
}

// Bindings returns a caller-owned scalar projection. Mutating it cannot change
// the command. Source/successor remain immutable and are not live admissions.
func (c OrganizationSelectionCommand) Bindings() (OrganizationSelectionCommandSpec, error) {
	if c.state == nil {
		return OrganizationSelectionCommandSpec{}, ErrInvalidSessionCommand
	}
	return *c.state, nil
}

// ValidateAt checks only the original source's absolute/idle lifetime. It never
// refreshes activity or authenticates selection. The executor must retain the
// original positive-evidence deadline and independently fence current owners.
func (c OrganizationSelectionCommand) ValidateAt(now time.Time) error {
	if c.state == nil {
		return ErrInvalidSessionCommand
	}
	_, err := c.state.Source.Lifetime(now)
	return err
}

// Format redacts command scope for every formatting verb.
func (OrganizationSelectionCommand) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.OrganizationSelectionCommand(redacted)"))
}

// MarshalJSON rejects implicit command disclosure or reconstructed custody.
func (OrganizationSelectionCommand) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

// MarshalText rejects implicit command disclosure, including map-key encoding.
func (OrganizationSelectionCommand) MarshalText() ([]byte, error) {
	return nil, ErrSecretSerialization
}
