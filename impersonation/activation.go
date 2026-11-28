package impersonation

import (
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ActivationInput binds a proposed activation to the approved grant and current
// adapter-validated actor, target, policy and ordinary parent session. These
// values are data, not proof of authentication or authorization. At must be the
// adapter's trusted current clock; ParentExpiresAt is the parent's effective
// expiry, including idle and absolute limits, not a client-supplied lifetime.
type ActivationInput struct {
	GrantID              GrantID
	ExpectedVersion      uint64
	Approval             Approval
	Actor                Actor
	CurrentTarget        Target
	CurrentPolicy        Policy
	ParentSessionID      string
	ParentSessionVersion uint64
	ParentExpiresAt      time.Time
	At                   time.Time
}

// ActiveBindings is an explicit caller-owned projection of immutable activation
// metadata. It contains no reason or bearer credential and grants no access.
// ExpiresAt is exclusive and cannot exceed the approved duration or parent's
// effective lifetime. GrantVersion is the new active version, not version two.
type ActiveBindings struct {
	GrantID              GrantID
	GrantVersion         uint64
	TenantID             identity.TenantID
	ActorID              identity.UserID
	TargetID             identity.UserID
	TargetVersion        uint64
	Scope                Scope
	Policy               Policy
	StartedAt            time.Time
	ExpiresAt            time.Time
	ParentSessionID      string
	ParentSessionVersion uint64
}

// ActiveSession is immutable activation metadata, not an ordinary session,
// authentication proof or bearer. Its zero value is invalid. Only Activate
// constructs it; adapters must persist and check authoritative state on every
// use, then intersect current actor authority and target-effective permissions.
type ActiveSession struct{ bindings ActiveBindings }

// String prevents implicit diagnostics from traversing private lineage.
func (ActiveSession) String() string { return "[redacted impersonation active session]" }

// GoString applies the same redaction to Go-syntax diagnostics.
func (s ActiveSession) GoString() string { return s.String() }

// Bindings returns an owned projection. Mutating it or its scope permissions
// cannot alter retained metadata. The projection itself establishes no access.
func (s ActiveSession) Bindings() ActiveBindings {
	b := s.bindings
	b.Scope.permissions = slices.Clone(b.Scope.permissions)
	return b
}

// Activate validates one pure approved-to-active transition from version two to
// three, preserving original intent and exact retained approval. It authenticates
// nobody, issues no credential, performs no I/O and mutates no input. The caller
// must authenticate the original ordinary actor with current password+TOTP and
// original CSRF, revalidate actor/approver authority, target eligibility and
// policy, prohibit recursive impersonation, and atomically persist a single
// winner with its effects. Repeating this operation on an active snapshot
// conflicts; keyed durable recovery belongs to the adapter.
//
// ErrInvalidInput rejects malformed parent/actor/time data or time before the
// retained decision; ErrConflict rejects stale state or mismatched bindings;
// ErrExpired rejects activation at or after either exclusive deadline. Failures
// return zero values. UTC output times omit monotonic clock data for persistence.
func Activate(grant Grant, input ActivationInput) (Grant, ActiveSession, error) {
	if input.Actor.user == "" || !validParentSessionID(input.ParentSessionID) || input.ParentSessionVersion == 0 || input.ParentExpiresAt.IsZero() || input.At.IsZero() {
		return Grant{}, ActiveSession{}, ErrInvalidInput
	}
	if grant.status != StatusApproved || grant.version != 2 || input.GrantID != grant.id || input.ExpectedVersion != grant.version {
		return Grant{}, ActiveSession{}, ErrConflict
	}
	if input.Approval != grant.approval || input.Approval.grantID != grant.id || input.Approval.requestVersion != 1 || input.Approval.requestDigest != grant.request.digest {
		return Grant{}, ActiveSession{}, ErrConflict
	}
	request := grant.request.input
	if input.Actor != request.Actor || input.CurrentTarget != request.Target || input.CurrentPolicy != request.Policy {
		return Grant{}, ActiveSession{}, ErrConflict
	}
	if input.At.Before(grant.approval.at) {
		return Grant{}, ActiveSession{}, ErrInvalidInput
	}
	if !input.At.Before(grant.expiresAt) || !input.At.Before(input.ParentExpiresAt) {
		return Grant{}, ActiveSession{}, ErrExpired
	}

	startedAt := input.At.Round(0).UTC()
	expiresAt := startedAt.Add(request.Duration)
	if input.ParentExpiresAt.Before(expiresAt) {
		expiresAt = input.ParentExpiresAt.Round(0).UTC()
	}
	grant.status = StatusActive
	grant.version++
	session := ActiveSession{bindings: ActiveBindings{
		GrantID: grant.id, GrantVersion: grant.version, TenantID: request.Tenant,
		ActorID: request.Actor.user, TargetID: request.Target.actor.user,
		TargetVersion: request.Target.version, Scope: request.Scope, Policy: request.Policy,
		StartedAt: startedAt, ExpiresAt: expiresAt, ParentSessionID: input.ParentSessionID,
		ParentSessionVersion: input.ParentSessionVersion,
	}}
	return grant, session, nil
}

// Native session SessionSpec uses 1..128 printable non-space ASCII bytes, not
// the narrower random identifier format used by grant IDs. The parent is
// supplied from authenticated native state; its syntax never establishes trust.
func validParentSessionID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}
