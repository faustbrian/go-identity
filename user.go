package identity

import (
	"time"
	"unicode/utf8"
)

// UserID identifies a directory user without encoding tenant or authority.
// It preserves an existing canonical ID, including a ULID, unchanged. Structural
// validation is not a substitute for the composition's canonical-ID policy.
// The empty value is invalid; IDs are case-sensitive and at most 128 bytes.
type UserID string

// TenantID is a case-sensitive tenant identity of at most 128 UTF-8 bytes.
// The empty value is invalid. A tenant ID is not proof of tenant access.
type TenantID string

// Status is the closed persisted identity lifecycle state. Its zero value and
// unknown values are invalid. Status is not a pending cascade/job state.
type Status string

const (
	// StatusActive is eligible for authentication, subject to other authorities.
	StatusActive Status = "active"
	// StatusSuspended denies authentication until an explicit restore command.
	StatusSuspended Status = "suspended"
	// StatusBanned denies authentication until an explicit authorized unban.
	StatusBanned Status = "banned"
	// StatusAnonymized is terminal for authentication and personal identity.
	StatusAnonymized Status = "anonymized"
	// StatusDeleted is terminal and must never be restored by import or policy.
	StatusDeleted Status = "deleted"
)

// Valid reports whether s is a registered lifecycle state.
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusSuspended, StatusBanned, StatusAnonymized, StatusDeleted:
		return true
	default:
		return false
	}
}

// AllowsAuthentication reports only lifecycle eligibility, not authentication
// or authorization. Unknown, blocked and terminal states fail closed. Elapsed
// ban/suspension time does not implicitly restore state or old credentials.
func (s Status) AllowsAuthentication() bool { return s == StatusActive }

// User is a versioned directory projection. Repository/UnitOfWork owns writes;
// callers treat returned values as immutable snapshots. Validation grants no
// access, changes no state and does not confirm lifecycle cascade completion.
type User struct {
	ID       UserID
	TenantID TenantID
	Status   Status
	Version  uint64
}

// InvalidInputError classifies an invalid identity input without retaining its
// value. Field is a fixed schema field name, never user-supplied data. Error's
// text is deliberately constant, including for cross-tenant mismatches.
type InvalidInputError struct{ Field string }

// Error returns the stable redacted validation diagnostic.
func (InvalidInputError) Error() string { return "identity: invalid input" }

// Validate checks a user projection against the exact expected tenant. It
// rejects malformed/oversized IDs, unknown statuses and zero versions without
// rewriting identifiers. It is structural validation only; canonical-ID policy,
// authoritative lookup, freshness and caller authorization remain separate.
func (u User) Validate(tenant TenantID) error {
	if !validDirectoryID(string(u.ID)) {
		return InvalidInputError{Field: "user_id"}
	}
	if !validDirectoryID(string(tenant)) || !validDirectoryID(string(u.TenantID)) || u.TenantID != tenant {
		return InvalidInputError{Field: "tenant_id"}
	}
	if !u.Status.Valid() {
		return InvalidInputError{Field: "status"}
	}
	if u.Version == 0 {
		return InvalidInputError{Field: "version"}
	}
	return nil
}

// StatusTransition permits one explicit directed edge. ReasonRequired applies
// to a validated command reason, not to authority or proof supplied by a caller.
type StatusTransition struct {
	From           Status
	To             Status
	ReasonRequired bool
}

// StatusPolicy describes allowed lifecycle transitions and retention bounds.
// Configure it before use and do not mutate it or its slice during concurrent
// reads. Consumers retaining configuration must own a deep copy. A false reason
// requirement and zero reuse cooldown are explicit valid choices. Zero policy
// is invalid; no implicit default edges or duration limits are applied.
type StatusPolicy struct {
	AllowedTransitions      []StatusTransition
	MaximumSuspension       time.Duration
	IdentifierReuseCooldown time.Duration
	BanRequiresReason       bool
}

// Validate checks all configuration before any transition decision. There must
// be 1..32 distinct edges, a positive suspension maximum up to 87,600 hours and
// a nonnegative reuse cooldown up to the same bound. Self edges, unknown states,
// deleted outgoing edges and anonymized edges other than deletion are invalid.
func (p StatusPolicy) Validate() error {
	const maximumDuration = 87600 * time.Hour
	if len(p.AllowedTransitions) == 0 || len(p.AllowedTransitions) > 32 {
		return InvalidInputError{Field: "allowed_transitions"}
	}
	if p.MaximumSuspension <= 0 || p.MaximumSuspension > maximumDuration {
		return InvalidInputError{Field: "maximum_suspension"}
	}
	if p.IdentifierReuseCooldown < 0 || p.IdentifierReuseCooldown > maximumDuration {
		return InvalidInputError{Field: "identifier_reuse_cooldown"}
	}
	for i, edge := range p.AllowedTransitions {
		if !edge.From.Valid() || !edge.To.Valid() || edge.From == edge.To || edge.From == StatusDeleted || edge.From == StatusAnonymized && edge.To != StatusDeleted {
			return InvalidInputError{Field: "allowed_transitions"}
		}
		for _, previous := range p.AllowedTransitions[:i] {
			if edge.From == previous.From && edge.To == previous.To {
				return InvalidInputError{Field: "allowed_transitions"}
			}
		}
	}
	return nil
}

// CheckTransition checks one proposed edge without changing a user or granting
// authority. hasReason must come from the validated command. A zero restriction
// duration means indefinite suspension/ban; positive duration is allowed only
// for those target states and never exceeds MaximumSuspension. The command
// owner must separately authorize, version-fence, persist and acknowledge all
// required cascades before a terminal status is reported complete.
func (p StatusPolicy) CheckTransition(from, to Status, hasReason bool, restriction time.Duration) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !from.Valid() || !to.Valid() {
		return InvalidInputError{Field: "status"}
	}
	if restriction < 0 || restriction > p.MaximumSuspension || restriction > 0 && to != StatusSuspended && to != StatusBanned {
		return InvalidInputError{Field: "restriction_duration"}
	}
	for _, edge := range p.AllowedTransitions {
		if edge.From == from && edge.To == to {
			if !hasReason && (edge.ReasonRequired || to == StatusBanned && p.BanRequiresReason) {
				return InvalidInputError{Field: "reason"}
			}
			return nil
		}
	}
	return InvalidInputError{Field: "status_transition"}
}

func validDirectoryID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}
