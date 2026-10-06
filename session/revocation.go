package session

import identity "github.com/faustbrian/go-identity"

// RevokeFamilyCommandSpec targets exactly Binding.RecordID's family owned by
// Binding.UserID in Binding.TenantID. ExpectedVersion is a positive current
// family version with a representable successor. It grants no authorization.
// Revocation retains historical session snapshots and never issues a bearer.
type RevokeFamilyCommandSpec struct {
	Binding         identity.CommandBinding
	ExpectedVersion uint64
}

// RevokeFamilyOperation identifies the native storage transition, not an HTTP
// endpoint or the user-wide RevokeAll operation. Its security action is
// identity.session.revoke; its lifecycle event is session_family.revoked.v1.
func RevokeFamilyOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.revoke-family", SchemaID: "session-family-revoke", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewRevokeFamilyCommand prepares an immutable exact-scope revocation. Zero and
// MaxUint64 versions fail rather than wrapping authority. A durable owner must
// authorize the operation and atomically compare current ownership/version,
// retain the tombstone, and commit the required audit/lifecycle/receipt. An
// absent, stale or already-revoked target does not permit a new transition;
// exact command replay belongs to the sole durable coordinator.
func NewRevokeFamilyCommand(b identity.CommandBinding, expected uint64) (SessionCommand, error) {
	if b.ValidateFor(RevokeFamilyOperation()) != nil || expected == 0 || expected == ^uint64(0) {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	return SessionCommand{revokeFamily: &RevokeFamilyCommandSpec{Binding: cloneCommandBinding(b), ExpectedVersion: expected}}, nil
}

// RevokeFamily returns an owned scalar native projection. False means another
// command variant or zero. This projection is preparation, never proof that
// revocation committed or that a caller can inspect or manage another account.
func (c SessionCommand) RevokeFamily() (RevokeFamilyCommandSpec, bool) {
	if c.revokeFamily == nil || c.issue != nil || c.revokeOne != nil || c.revokeSet != nil {
		return RevokeFamilyCommandSpec{}, false
	}
	return *c.revokeFamily, true
}
