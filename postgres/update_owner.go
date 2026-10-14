package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// UserUpdateUnitOfWork composes durable administrative typed-field updates
// behind identity.UserUpdateAdminService. It owns no policy, pool, goroutine or
// second transaction protocol. Immutable composition is safe for concurrent
// calls; each call uses the sole Coordinator's exact enlisted Repository and
// audit/lifecycle phases. Zero is invalid. Direct calls grant no authority.
type UserUpdateUnitOfWork struct{ owner *CreationUnitOfWork }

var _ identity.UnitOfWork = (*UserUpdateUnitOfWork)(nil)

// NewUserUpdateUnitOfWork validates existing typed composition without I/O.
// Schemas are selected by each command's exact registered ID/version; enabling
// the independent self-profile feature is unnecessary. Retention configuration
// has the creation owner's positive-version semantics. No callbacks are run.
func NewUserUpdateUnitOfWork(c *Coordinator, r *Repository, config CreationUnitOfWorkConfig) (*UserUpdateUnitOfWork, error) {
	owner, err := NewCreationUnitOfWork(c, r, config)
	if err != nil {
		return nil, err
	}
	if len(r.attributeSchemas) == 0 {
		return nil, attributeStorageError()
	}
	return &UserUpdateUnitOfWork{owner: owner}, nil
}

// Execute atomically persists admitted field replacements, one aggregate
// successor, protected audit, lifecycle and original receipt. Replay precedes
// the locked version/status fence. Omitted fields and lifecycle status remain
// unchanged; deleted/anonymized users cannot be mutated or resurrected. SQL
// failures roll back all prefixes; ambiguous closure remains Unknown. Only
// administrative attribute commands are accepted; preserve IDs for recovery.
func (o *UserUpdateUnitOfWork) Execute(ctx context.Context, command identity.Command) (identity.CommandResult, error) {
	if o == nil || o.owner == nil {
		return identity.CommandResult{}, coordinatorError()
	}
	if _, ok := command.UpdateUser(); !ok {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "update_command"}
	}
	return o.owner.execute(ctx, command, "identity.user.update-admin")
}

// Recover observes the exact original administrative receipt, never reapplies
// fields or fabricates success from current state. The core service owns current
// authorization and redaction. Expired pending commands need every original
// frozen participant's negative evidence; missing evidence remains unresolved.
func (o *UserUpdateUnitOfWork) Recover(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	if o == nil || o.owner == nil {
		return identity.CommandResult{}, coordinatorError()
	}
	return o.owner.recover(ctx, q, "identity.user.update-admin")
}

// Format prevents disclosure of runtime composition and dependencies.
func (UserUpdateUnitOfWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.UserUpdateUnitOfWork(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition.
func (UserUpdateUnitOfWork) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }
