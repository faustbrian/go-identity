package session

import identity "github.com/faustbrian/go-identity"

// RevokeOneCommandSpec targets one exact session with its original complete
// authority snapshot and positive version. Binding.RecordID is the session ID,
// never the family ID. This structural projection grants no caller authority.
// A durable owner must compare current ownership/version and revoke only this
// session, leaving sibling records and family authority unchanged.
type RevokeOneCommandSpec struct {
	Binding identity.CommandBinding
	Session Session
}

// RevokeOneOperation identifies the single-session native transition. It is
// distinct from family revocation and carries no execution or HTTP authority.
func RevokeOneOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.revoke-one", SchemaID: "session-revoke-one", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewRevokeOneCommand binds an immutable original target record to the exact
// tenant, effective user and session. Its version must have a representable
// successor. Structural records, including expired records, are not admission:
// the owning service must independently authenticate the caller and authorize
// the target, then recheck all applicable current authorities atomically with
// revocation, audit, lifecycle and retained command recovery. No fresh-login
// requirement is added here. Public logout idempotency belongs to the service;
// neither a missing nor an already-revoked row permits a second transition.
func NewRevokeOneCommand(b identity.CommandBinding, s Session) (SessionCommand, error) {
	spec, err := s.Bindings()
	if err != nil || b.ValidateFor(RevokeOneOperation()) != nil || b.TenantID != spec.TenantID || b.UserID != spec.UserID || b.RecordID != spec.SessionID || spec.Version == ^uint64(0) {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	return SessionCommand{revokeOne: &RevokeOneCommandSpec{Binding: cloneCommandBinding(b), Session: s}}, nil
}

// RevokeOne returns a caller-owned scalar projection preserving the original
// immutable session. False means zero or another command variant. It is never
// evidence that revocation committed or that the caller owns the target.
func (c SessionCommand) RevokeOne() (RevokeOneCommandSpec, bool) {
	if c.revokeOne == nil || c.issue != nil || c.revokeFamily != nil {
		return RevokeOneCommandSpec{}, false
	}
	return *c.revokeOne, true
}
