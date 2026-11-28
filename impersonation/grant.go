package impersonation

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// RequestInput transfers validated immutable values into a bound intent. The
// adapter must independently enforce current actor/target policy and freshness.
type RequestInput struct {
	Tenant   identity.TenantID
	Actor    Actor
	Target   Target
	Scope    Scope
	Reason   Reason
	Duration time.Duration
	Policy   Policy
}

// Request is immutable exact intent. Its zero value is invalid. Digest includes
// tenant, actor, target/version, scope, reason digest, duration, policy ID/version
// and required approval count.
type Request struct {
	input  RequestInput
	digest [32]byte
}

// String prevents implicit diagnostics from traversing sensitive private intent.
func (Request) String() string { return "[redacted impersonation request]" }

// GoString applies the same redaction to Go-syntax diagnostics.
func (r Request) GoString() string { return r.String() }

// NewRequest validates a same-tenant distinct actor/target and the selected
// bounded policy. It performs no authorization and creates no durable state.
func NewRequest(input RequestInput) (Request, error) {
	if input.Actor.user == "" || input.Target.version == 0 || input.Tenant != input.Actor.tenant || input.Tenant != input.Target.actor.tenant || input.Actor.user == input.Target.actor.user {
		return Request{}, ErrInvalidInput
	}
	// The product RequestCommand contract starts at one second; the selected
	// M24 reference policy tightens its upper bound to fifteen minutes.
	if input.Policy.version == 0 || len(input.Scope.permissions) == 0 || input.Reason.text == "" || input.Duration < time.Second || input.Duration > MaximumDuration {
		return Request{}, ErrInvalidInput
	}
	request := Request{input: input}
	request.digest = requestDigest(input)
	return request, nil
}

// Input returns a copy of the immutable typed request values for protected
// persistence/reconstruction. Scope retains private immutable backing storage.
func (r Request) Input() RequestInput { return r.input }

// Digest returns a versioned canonical intent binding, not a keyed command
// fingerprint, secret or authority. Persist it with the original typed inputs.
// One-approval policies retain the historical v1 binding; counts above one use
// a separate v2 domain and encode the count after the policy revision.
func (r Request) Digest() [32]byte { return r.digest }

// Tenant returns the bound tenant partition.
func (r Request) Tenant() identity.TenantID { return r.input.Tenant }

// Actor returns the original real actor binding.
func (r Request) Actor() Actor { return r.input.Actor }

// Target returns the exact target account/version binding.
func (r Request) Target() Target { return r.input.Target }

// Scope returns the immutable canonical permission set.
func (r Request) Scope() Scope { return r.input.Scope }

// Reason returns the redacted reason value; raw access is explicit.
func (r Request) Reason() Reason { return r.input.Reason }

// Duration returns requested session duration, not any issued lifetime.
func (r Request) Duration() time.Duration { return r.input.Duration }

// Policy returns the bound policy identity, revision and approval requirement.
func (r Request) Policy() Policy { return r.input.Policy }

func requestDigest(input RequestInput) [32]byte {
	h := sha256.New()
	if input.Policy.RequiredApprovals() == 1 {
		writeString(h, "identity.impersonation.request.binding.v1")
	} else {
		writeString(h, "identity.impersonation.request.binding.v2")
	}
	writeString(h, string(input.Tenant))
	writeString(h, string(input.Actor.user))
	writeString(h, string(input.Target.actor.user))
	writeUint(h, input.Target.version)
	writeUint(h, uint64(len(input.Scope.permissions)))
	for _, permission := range input.Scope.permissions {
		writeString(h, permission)
	}
	reasonDigest := input.Reason.Digest()
	_, _ = h.Write(reasonDigest[:])
	writeUint(h, uint64(input.Duration))
	writeString(h, input.Policy.id)
	writeUint(h, input.Policy.version)
	if input.Policy.RequiredApprovals() > 1 {
		writeUint(h, uint64(input.Policy.RequiredApprovals()))
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func writeString(h hash.Hash, value string) {
	writeUint(h, uint64(len(value)))
	_, _ = h.Write([]byte(value))
}
func writeUint(h hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

// Grant is an immutable versioned snapshot, not a bearer credential or store.
// Pending, approved and active snapshots can be constructed in this profile.
type Grant struct {
	id          GrantID
	request     Request
	status      Status
	version     uint64
	requestedAt time.Time
	expiresAt   time.Time
	approval    Approval
	approvals   []Approval
}

// String prevents implicit diagnostics from traversing a sensitive request.
func (Grant) String() string { return "[redacted impersonation grant]" }

// GoString applies the same redaction to Go-syntax diagnostics.
func (g Grant) GoString() string { return g.String() }

// NewPendingGrant creates a version-one pending snapshot at supplied trusted
// time. The caller must persist it atomically with keyed outcome and effects.
// Times are UTC without monotonic clock data for exact persistence round trips.
func NewPendingGrant(id GrantID, request Request, at time.Time) (Grant, error) {
	if !validGrantID(id) || request.input.Actor.user == "" || at.IsZero() {
		return Grant{}, ErrInvalidInput
	}
	at = at.Round(0).UTC()
	return Grant{id: id, request: request, status: StatusPendingApproval, version: 1, requestedAt: at, expiresAt: at.Add(ApprovalLifetime)}, nil
}

// ID returns the stable grant identifier, never authority to use the grant.
func (g Grant) ID() GrantID { return g.id }

// Request returns the immutable original intent.
func (g Grant) Request() Request { return g.request }

// Status returns the exact snapshot state; zero is unspecified.
func (g Grant) Status() Status { return g.status }

// Version returns the version requiring atomic persistence comparison.
func (g Grant) Version() uint64 { return g.version }

// RequestedAt returns the original trusted creation time.
func (g Grant) RequestedAt() time.Time { return g.requestedAt }

// ExpiresAt returns the exclusive decision/activation deadline, never extended
// by approval or activation. ActiveSession.Bindings exposes the active expiry.
func (g Grant) ExpiresAt() time.Time { return g.expiresAt }

// Approvals returns a caller-owned snapshot in decision order. A partial list
// does not satisfy the selected quorum or establish authorization. Each decision
// retains the actual pending version against which it was applied.
func (g Grant) Approvals() []Approval {
	return append([]Approval(nil), g.approvals...)
}

// ApprovalInput proposes one decision against an exact pending grant/request.
// At must be the adapter's trusted current clock, not a client-supplied time.
type ApprovalInput struct {
	GrantID         GrantID
	ExpectedVersion uint64
	Request         Request
	Approver        Actor
	Reason          Reason
	At              time.Time
}

// Approval is an immutable decision for one grant/request version. Persist it
// in a distinct approval row; it is not a journal, credential or reusable proof.
type Approval struct {
	grantID        GrantID
	requestVersion uint64
	requestDigest  [32]byte
	approver       Actor
	reason         Reason
	at             time.Time
}

// String prevents implicit diagnostics from traversing a sensitive reason.
func (Approval) String() string { return "[redacted impersonation approval]" }

// GoString applies the same redaction to Go-syntax diagnostics.
func (a Approval) GoString() string { return a.String() }

// GrantID returns the exact owner grant.
func (a Approval) GrantID() GrantID { return a.grantID }

// RequestVersion returns the pending version against which the decision applied.
func (a Approval) RequestVersion() uint64 { return a.requestVersion }

// RequestDigest returns the original complete intent binding.
func (a Approval) RequestDigest() [32]byte { return a.requestDigest }

// Approver returns the real distinct administrator identity.
func (a Approval) Approver() Actor { return a.approver }

// Reason returns the sensitive approval reason with explicit protected access.
func (a Approval) Reason() Reason { return a.reason }

// At returns trusted decision time without monotonic data.
func (a Approval) At() time.Time { return a.at }

// Approve checks deterministic bindings and returns new snapshots without
// mutation, authorization, sessions or effects. The adapter must authenticate
// both ordinary password+TOTP admins fresh within 15 minutes, prohibit recursive
// impersonation, check original CSRF and current target/actor/scoped policy,
// then compare-and-swap version and persist the distinct row/effects atomically.
// Repeats conflict here; durable keyed retries must recover the original result.
// Each decision advances the version once, retaining pending status below the
// selected quorum and approving exactly at quorum without renewing the deadline.
func Approve(grant Grant, input ApprovalInput) (Grant, Approval, error) {
	if input.Approver.user == "" || input.Reason.text == "" || input.At.IsZero() {
		return Grant{}, Approval{}, ErrInvalidInput
	}
	required := grant.request.input.Policy.RequiredApprovals()
	if grant.status != StatusPendingApproval || grant.version != uint64(len(grant.approvals))+1 || len(grant.approvals) >= required {
		return Grant{}, Approval{}, ErrConflict
	}
	if input.GrantID != grant.id || input.ExpectedVersion != grant.version || input.Request.digest != grant.request.digest {
		return Grant{}, Approval{}, ErrConflict
	}
	if input.Approver.tenant != grant.request.input.Tenant || input.Approver.user == grant.request.input.Actor.user || input.Approver.user == grant.request.input.Target.actor.user {
		return Grant{}, Approval{}, ErrConflict
	}
	for _, previous := range grant.approvals {
		if input.Approver == previous.approver {
			return Grant{}, Approval{}, ErrConflict
		}
	}
	if input.At.Before(grant.requestedAt) {
		return Grant{}, Approval{}, ErrInvalidInput
	}
	if !input.At.Before(grant.expiresAt) {
		return Grant{}, Approval{}, ErrExpired
	}
	approval := Approval{grantID: grant.id, requestVersion: grant.version, requestDigest: grant.request.digest, approver: input.Approver, reason: input.Reason, at: input.At.Round(0).UTC()}
	grant.approvals = append(grant.Approvals(), approval)
	if len(grant.approvals) == required {
		grant.status = StatusApproved
	}
	grant.version++
	grant.approval = approval
	return grant, approval, nil
}
