package anonymous

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// SubjectQuery selects an exact primary anonymous partition. It is structural
// correlation, not possession, current session authority or disclosure policy.
type SubjectQuery struct {
	TenantID identity.TenantID
	UserID   identity.UserID
}

// Validate preserves exact scoped identifiers without normalization or lookup.
func (q SubjectQuery) Validate() error {
	if _, err := identity.ParseSubjectID(string(q.UserID)); err != nil {
		return ErrInvalidInput
	}
	if (identity.User{TenantID: q.TenantID, ID: q.UserID, Status: identity.StatusActive, Version: 1}).Validate(q.TenantID) != nil {
		return ErrInvalidInput
	}
	return nil
}

// Store reads current anonymous-owned lifecycle metadata from the primary.
// Implementations preserve terminal states, original times and positive epochs;
// absence is ErrSubjectAbsent, not proof of rollback or permission to recreate.
// Calls honor bounded contexts, support concurrent independent reads and grant
// no public disclosure or verified authority. Ordinary kernel/session data stay
// with their existing owners. No cache may renew this primary evidence.
type Store interface {
	Read(context.Context, SubjectQuery) (AnonymousSubject, error)
}

// UnitOfWork reuses identity's exact durable command/recovery protocol. The
// anonymous adapter binds a closed native invocation to that existing owner;
// this alias creates no transaction, participant registry or recovery authority.
type UnitOfWork = identity.UnitOfWork

const ErrSubjectAbsent Error = "identity.anonymous.subject_absent"
