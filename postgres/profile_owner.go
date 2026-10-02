package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// ProfileUnitOfWork is the opt-in durable profile command composition behind
// identity.ProfileService. It reuses the sole Coordinator and its typed
// audit/outbox phases. It does not authenticate direct callers, own the pool,
// run callbacks inside a transaction, or start background work. Immutable
// composition supports concurrent calls; zero is invalid.
type ProfileUnitOfWork struct{ owner *CreationUnitOfWork }

var _ identity.UnitOfWork = (*ProfileUnitOfWork)(nil)

// NewProfileUnitOfWork requires the exact enlisted Repository with a selected
// frozen ProfileSchema. Retention configuration has the same semantics as the
// creation composition. No I/O occurs. The existing creation-only API remains
// unchanged; this composition accepts profile commands only.
func NewProfileUnitOfWork(c *Coordinator, r *Repository, config CreationUnitOfWorkConfig) (*ProfileUnitOfWork, error) {
	owner, err := NewCreationUnitOfWork(c, r, config)
	if err != nil {
		return nil, err
	}
	if _, ok := r.attributeSchemas[r.profileSchema]; !ok {
		return nil, invalidProfileQuery()
	}
	return &ProfileUnitOfWork{owner: owner}, nil
}

// Execute persists an admitted self-profile mutation, audit, lifecycle and
// immutable receipt together. Replay resolves before current-state CAS. Empty
// name/image are omitted; additional values replace individual named fields.
// A stale/blocked write closes with an audited NotCommitted outcome. Ambiguous
// closure stays Unknown; preserve command identity and use Recover.
func (o *ProfileUnitOfWork) Execute(ctx context.Context, command identity.Command) (identity.CommandResult, error) {
	if o == nil || o.owner == nil {
		return identity.CommandResult{}, coordinatorError()
	}
	if _, ok := command.UpdateProfile(); !ok {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "profile_command"}
	}
	return o.owner.execute(ctx, command, true)
}

// Recover observes the original self-scoped profile receipt, never infers
// success from current profile state and never reapplies a mutation. Current
// authorization and output redaction belong to identity.ProfileService.
func (o *ProfileUnitOfWork) Recover(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	if o == nil || o.owner == nil || q.OperationID != "identity.profile.update" {
		return identity.CommandResult{}, coordinatorError()
	}
	return o.owner.recover(ctx, q, true)
}

// Format prevents dependency and command disclosure.
func (ProfileUnitOfWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProfileUnitOfWork(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition.
func (ProfileUnitOfWork) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }
