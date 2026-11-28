// Package impersonation provides immutable request binding and deterministic
// pending-to-approved transitions. It authenticates nobody and grants no access.
// An adapter must authorize current actors and targets and atomically persist
// version-fenced grants, distinct approvals, keyed outcomes and required effects.
package impersonation

import (
	"crypto/sha256"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// Error is a stable, redacted decision classification. It never retains input.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrInvalidInput rejects malformed, zero or unsupported input.
	ErrInvalidInput Error = "impersonation: invalid input"
	// ErrConflict rejects stale versions, terminal grants and mismatched intent.
	ErrConflict Error = "impersonation: conflict"
	// ErrExpired rejects decisions at or after the fixed approval deadline.
	ErrExpired Error = "impersonation: expired"
)

// MaximumDuration is the M24 reference profile's requested-session limit.
// REFERENCE_PROFILE.md selects fifteen minutes, not the broader catalog limit.
const MaximumDuration = 15 * time.Minute

// ApprovalLifetime is the selected M24 request-to-decision window. Approval
// never renews it; it is not a session lifetime or evidence of authorization.
const ApprovalLifetime = 15 * time.Minute

// Actor is an immutable real user/tenant binding, not authentication evidence.
// Its zero value is invalid; no identifier normalization is performed.
type Actor struct {
	tenant identity.TenantID
	user   identity.UserID
}

// NewActor preserves identifiers under identity's structural validation rules.
func NewActor(tenant identity.TenantID, user identity.UserID) (Actor, error) {
	if err := (identity.User{ID: user, TenantID: tenant, Status: identity.StatusActive, Version: 1}).Validate(tenant); err != nil {
		return Actor{}, ErrInvalidInput
	}
	return Actor{tenant: tenant, user: user}, nil
}

// Tenant returns the exact tenant partition, without establishing access.
func (a Actor) Tenant() identity.TenantID { return a.tenant }

// User returns the exact real user identifier.
func (a Actor) User() identity.UserID { return a.user }

// Target binds the exact target account version checked by the adapter.
// It does not establish eligibility; zero is invalid.
type Target struct {
	actor   Actor
	version uint64
}

// NewTarget validates identity syntax and a nonzero directory version.
func NewTarget(tenant identity.TenantID, user identity.UserID, version uint64) (Target, error) {
	actor, err := NewActor(tenant, user)
	if err != nil || version == 0 {
		return Target{}, ErrInvalidInput
	}
	return Target{actor: actor, version: version}, nil
}

// Tenant returns the bound tenant partition.
func (t Target) Tenant() identity.TenantID { return t.actor.tenant }

// User returns the bound target account identifier.
func (t Target) User() identity.UserID { return t.actor.user }

// Version returns the exact directory account version requiring revalidation.
func (t Target) Version() uint64 { return t.version }

// Policy binds a selected policy identity, revision and required approval count.
// Its zero value is invalid. It authorizes nobody and does not establish that
// eligible distinct approvals exist; actual enforcement belongs to the adapter.
type Policy struct {
	id                string
	version           uint64
	requiredApprovals int
}

// NewPolicy selects a case-sensitive policy ID and nonzero revision requiring
// one distinct approval. It is exactly equivalent to NewPolicyWithQuorum(id,
// version, 1), including the historical v1 request binding.
func NewPolicy(id string, version uint64) (Policy, error) {
	return NewPolicyWithQuorum(id, version, 1)
}

// NewPolicyWithQuorum selects a case-sensitive policy ID, nonzero revision and
// 1..32 required distinct approvals. This immutable requirement does not enable
// multi-approval enforcement: the adapter must select this policy, authorize
// eligible distinct approvers and persist their decisions atomically.
func NewPolicyWithQuorum(id string, version uint64, required int) (Policy, error) {
	if _, err := NewActor(identity.TenantID(id), "policy"); err != nil || version == 0 || required < 1 || required > 32 {
		return Policy{}, ErrInvalidInput
	}
	return Policy{id: id, version: version, requiredApprovals: required}, nil
}

// ID returns the exact policy identity.
func (p Policy) ID() string { return p.id }

// Version returns the exact policy revision.
func (p Policy) Version() uint64 { return p.version }

// RequiredApprovals returns the selected requirement, not a count of existing
// approvals or authority to activate. It returns zero for the invalid zero policy.
func (p Policy) RequiredApprovals() int {
	return p.requiredApprovals
}

// Scope is an immutable sorted set of 1..64 distinct permissions. Each is
// 1..128 printable ASCII bytes, without spaces. Zero is invalid. Permissions
// remain case-sensitive; sorting changes only order, never permission spelling.
type Scope struct{ permissions []string }

// NewScope bounds all input before allocation, rejects duplicates and copies
// ownership. Sorting gives equivalent permission sets one stable binding.
func NewScope(permissions []string) (Scope, error) {
	if len(permissions) == 0 || len(permissions) > 64 {
		return Scope{}, ErrInvalidInput
	}
	for _, permission := range permissions {
		if len(permission) == 0 || len(permission) > 128 {
			return Scope{}, ErrInvalidInput
		}
		for i := range len(permission) {
			if permission[i] < 0x21 || permission[i] > 0x7e {
				return Scope{}, ErrInvalidInput
			}
		}
	}
	owned := slices.Clone(permissions)
	slices.Sort(owned)
	for i := 1; i < len(owned); i++ {
		if owned[i] == owned[i-1] {
			return Scope{}, ErrInvalidInput
		}
	}
	return Scope{permissions: owned}, nil
}

// Permissions returns a caller-owned sorted copy, never mutable intent storage.
func (s Scope) Permissions() []string { return slices.Clone(s.permissions) }

// Reason owns 1..1024 valid UTF-8 bytes containing non-whitespace content.
// It is sensitive: implicit formatting and serialization never disclose text.
// Its unkeyed digest is a binding, not anonymization or an authorization token.
type Reason struct{ text string }

// NewReason bounds bytes before processing and preserves exact accepted text.
func NewReason(text string) (Reason, error) {
	if len(text) == 0 || len(text) > 1024 || !utf8.ValidString(text) || strings.TrimSpace(text) == "" {
		return Reason{}, ErrInvalidInput
	}
	return Reason{text: text}, nil
}

// StorageText explicitly exposes sensitive text for authorized protected
// persistence only. Do not log it or return it to a target or public response.
func (r Reason) StorageText() string { return r.text }

// Digest returns SHA-256 of exact text; zero Reason still has no valid authority.
func (r Reason) Digest() [32]byte { return sha256.Sum256([]byte(r.text)) }

// String redacts the sensitive reason in ordinary formatting.
func (Reason) String() string { return "[redacted impersonation reason]" }

// GoString redacts the sensitive reason in Go-syntax formatting.
func (r Reason) GoString() string { return r.String() }

// GrantID is the canonical unpadded base64url encoding of a nonzero 128-bit
// value. The adapter
// generates it using cryptographic randomness and owns uniqueness; zero is invalid.
type GrantID string

func validGrantID(id GrantID) bool {
	_, err := identity.ParseCommandID(string(id))
	return err == nil
}

// Status is the complete closed lifecycle vocabulary. Recognizing a status
// does not expose a transition to it. Unspecified and unknown values fail closed.
type Status string

const (
	StatusUnspecified     Status = ""
	StatusRequested       Status = "requested"
	StatusPendingApproval Status = "pending_approval"
	StatusApproved        Status = "approved"
	StatusActive          Status = "active"
	StatusStopped         Status = "stopped"
	StatusExpired         Status = "expired"
	StatusDenied          Status = "denied"
	StatusRevoked         Status = "revoked"
)

// Valid recognizes only specified lifecycle states, not approval or access.
func (s Status) Valid() bool {
	switch s {
	case StatusRequested, StatusPendingApproval, StatusApproved, StatusActive, StatusStopped, StatusExpired, StatusDenied, StatusRevoked:
		return true
	default:
		return false
	}
}
