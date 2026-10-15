package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
)

// UserAuthorizationAdmission binds one user-domain authorization lifecycle epoch.
// Scope.SubjectID must equal the immutable command's effective UserID, not its
// actor or workload. Scope.PolicyNamespace comes from trusted native composition
// and must own user-ID uniqueness. Version is a positive full-width counter,
// independent of policy revision. Native adapters must freeze every field into
// their keyed command before reservation and compare that intent at execution.
// This structural input is neither authentication proof nor an Allow decision.
type UserAuthorizationAdmission struct {
	Scope   authority.AuthorityScope
	Version uint64
}

// Format redacts correlated admission input from diagnostics.
func (UserAuthorizationAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.UserAuthorizationAdmission(redacted)")
}

// MarshalJSON rejects accidental export of correlated admission input.
func (UserAuthorizationAdmission) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// RequireActiveUserAuthorization compares a command-bound user's exact current
// authorization epoch during the exact native participant's active invocation.
// It borrows the original coordinator transaction through WorkRows and retains
// the owner's share lock until commit or abort. Earlier caller/Work deadlines
// win. Missing or unequal epochs deny uniformly; malformed scope or invocation
// is InvalidInput; storage failures are redacted Unavailable. Every failure on
// live Work poisons it, even if the participant ignores the error.
//
// This explicitly user-only profile never substitutes actor/workload identity or
// claims organization authority. It does not bootstrap, advance an epoch, decide
// policy, refresh validity evidence, consume proof or issue a session. The native
// adapter still needs its policy decision and all other applicable authority and
// atomic proof phases. Work remains serial and cannot be retained after invocation.
func (w Work) RequireActiveUserAuthorization(ctx context.Context, p FeatureExecutionContributor, expected UserAuthorizationAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	binding, _, _, err := w.FeatureScope(p)
	if err != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.requireActiveUserAuthorization(ctx, binding, expected)
}

func (w Work) requireActiveUserAuthorization(ctx context.Context, binding identity.CommandBinding, expected UserAuthorizationAdmission) error {
	if expected.Scope.Validate() != nil || expected.Version == 0 || string(expected.Scope.TenantID) != string(binding.TenantID) || string(expected.Scope.SubjectID) != string(binding.UserID) {
		return w.fail(ctx, invalidWork())
	}
	// The existing owner consumes the generation-bound cursor directly; no raw
	// connection, duplicate owner SQL or independent transaction is introduced.
	err := authority.RequireAuthority(ctx, w, expected.Scope, expected.Version, time.Minute)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, authority.ErrAuthorityDenied):
		err = identity.ForbiddenError{}
	case errors.Is(err, authority.ErrInvalidAuthority):
		err = invalidWork()
	}
	return w.fail(ctx, err)
}
