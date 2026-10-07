package postgres

import (
	"context"
	"fmt"
	"io"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// UserAuthorityAdmission freezes three independently owned user security
// epochs. All must be positive and authenticated as original command intent;
// none is the aggregate User.Version. This is not authentication or a proof.
type UserAuthorityAdmission struct {
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
}

// Format redacts correlated authority input from diagnostics.
func (UserAuthorityAdmission) Format(s fmt.State, _ rune) {
	io.WriteString(s, "postgres.UserAuthorityAdmission(redacted)")
}

// MarshalJSON rejects accidental export of correlated admission input.
func (UserAuthorityAdmission) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// RequireActiveUserAuthority compares the command-bound user's active status
// and all three original security epochs without requiring a credential. Only
// the exact native feature participant's live invocation may call it. The
// primary share lock lasts until coordinator commit or abort; aggregate user
// version is deliberately not an authority epoch. Missing, inactive or stale
// state denies uniformly and every live failure poisons Work, even if ignored.
// A returned invocation cannot poison a later invocation sharing its Work.
// This does not decide policy, authenticate a bearer, renew original authority,
// or replace credential-specific admission when a credential is present.
func (w Work) RequireActiveUserAuthority(ctx context.Context, p FeatureExecutionContributor, expected UserAuthorityAdmission) error {
	if w.state == nil || w.state.featureInvocation == nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return w.fail(ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	return otpAuthorityFailure(ctx, w, w.requireActiveUserAuthority(ctx, b, expected))
}

func (w Work) requireActiveUserAuthority(ctx context.Context, b identity.CommandBinding, expected UserAuthorityAdmission) error {
	if !queryScopeText(string(b.TenantID)) || !queryScopeText(string(b.UserID)) || expected.UserAuthorityVersion == 0 || expected.IdentifierAuthorityVersion == 0 || expected.CredentialAuthorityVersion == 0 {
		return w.fail(ctx, invalidWork())
	}
	// Passwordless users need no credential reference. Lock the same primary
	// user row used by lifecycle writers, retaining it through transaction end.
	rows, err := w.Query(ctx, `SELECT status,authority_version::text,identifier_version::text,credential_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return w.fail(ctx, identity.ForbiddenError{})
	}
	var status, user, identifier, credential string
	err = rows.Scan(&status, &user, &identifier, &credential)
	if err != nil {
		rows.Close()
		return err
	}
	if rows.Next() {
		rows.Close()
		return w.fail(ctx, identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	values := [3]string{user, identifier, credential}
	want := [3]uint64{expected.UserAuthorityVersion, expected.IdentifierAuthorityVersion, expected.CredentialAuthorityVersion}
	stale := false
	for i, raw := range values {
		value, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
			return w.fail(ctx, identity.UnavailableError{})
		}
		stale = stale || value != want[i]
	}
	if status != string(identity.StatusActive) || stale {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
