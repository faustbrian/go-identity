package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// These private storage phases do not authorize execution. The enclosing
// protected owner must validate provider proof, current actor session/policy and
// risk, consume one-use inputs, stage required effects, and own final closure.
// Public Begin remains closed for canonical link commands until that composition
// exists. There is no second transaction, journal or provider-owned link store.
func lockAccountLinkState(ctx context.Context, w Work, change identity.AccountLinkChange) (identity.AccountLinkState, time.Time, error) {
	zero := identity.AccountLinkState{}
	if err := w.usable(); err != nil {
		return zero, time.Time{}, err
	}
	fail := func(err error) (identity.AccountLinkState, time.Time, error) {
		return zero, time.Time{}, w.fail(w.state.ctx, err)
	}
	if ctx == nil || change.Mode != identity.AccountLinkExplicit || change.Account.TenantID != w.state.binding.TenantID || change.Account.UserID != w.state.binding.UserID || w.state.rows != nil {
		return fail(invalidWork())
	}
	if _, err := identity.AccountLinkIntentDigest(change); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	rows, err := w.Query(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(change.Account.TenantID), string(change.Account.UserID))
	if err != nil {
		return zero, time.Time{}, err
	}
	found := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail(err)
	}
	if !found {
		return fail(identity.ForbiddenError{})
	}
	// configureKernelWork serializes native tenant writers, including absence.
	// Retain exact candidate/tombstone and live collision rows as well; do not
	// lock or scan every retained account in an owner's unbounded history.
	rows, err = w.Query(ctx, `SELECT account_id FROM identity.accounts
 WHERE tenant_id=$1 AND (account_id=$2 OR (linked AND subject_key=sha256(convert_to(
 octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text||octet_length($5::text)::text||':'||$5::text,'UTF8'))))
 ORDER BY account_id LIMIT 2 FOR UPDATE`, string(change.Account.TenantID), string(change.Account.ID), change.Account.Provider, change.Account.Issuer, change.Account.Subject)
	if err != nil {
		return zero, time.Time{}, err
	}
	for rows.Next() {
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail(err)
	}
	deadline, _ := w.state.ctx.Deadline()
	bounded, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(w.state.ctx, cancel)
	defer func() { stop(); cancel() }()
	// Owned internal reads use the SAME transaction and Work lifetime. Both
	// collectors enforce their fixed 101/129 row bounds and metadata limits.
	state, err := readAccountLinkState(bounded, w.state.tx, identity.AccountLinkQuery{Account: change.Account, Mode: change.Mode})
	if err != nil {
		return fail(err)
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return zero, time.Time{}, err
	}
	return state, now, nil
}

// persistAccountLinkMutation writes only a pure transition calculated from the
// locked partition above. Every prefix is provisional in the original Work.
// Candidate history can advance only with its exact immutable tuple/version;
// neither an absent-key race nor a foreign tombstone can transfer ownership.
func persistAccountLinkMutation(ctx context.Context, w Work, change identity.AccountLinkChange, next identity.AccountLinkMutation) error {
	if err := w.usable(); err != nil {
		return err
	}
	fail := func(err error) error { return w.fail(w.state.ctx, err) }
	a := change.Account
	if ctx == nil || change.Mode != identity.AccountLinkExplicit || a.TenantID != w.state.binding.TenantID || a.UserID != w.state.binding.UserID || next.Account != a || next.Access.User.TenantID != a.TenantID || next.Access.User.ID != a.UserID || next.Access.User.Version != change.ExpectedUserVersion+1 || next.SocialLinkVersion != change.ExpectedSocialLinkVersion+1 || next.AddsCredential != (change.Method != nil) {
		return fail(invalidWork())
	}
	expectedCredentials := change.ExpectedCredentialVersion
	if next.AddsCredential {
		expectedCredentials++
	}
	if next.CredentialVersion != expectedCredentials {
		return fail(invalidWork())
	}
	n, err := w.Exec(ctx, `UPDATE identity.users SET version=$4::numeric,credential_version=$5::numeric
 WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$3::numeric AND credential_version=$6::numeric`, string(a.TenantID), string(a.UserID), change.ExpectedUserVersion, next.Access.User.Version, next.CredentialVersion, change.ExpectedCredentialVersion)
	if err != nil {
		return err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	args := []any{string(a.TenantID), string(a.UserID), string(a.ID), a.Provider, a.Issuer, a.Subject, a.Version, next.SocialLinkVersion}
	if change.ExpectedAccountVersion == 0 {
		n, err = w.Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 VALUES($1,$2,$3,$4,$5,$6,sha256(convert_to(octet_length($4::text)::text||':'||$4::text||octet_length($5::text)::text||':'||$5::text||octet_length($6::text)::text||':'||$6::text,'UTF8')),$7::numeric,$8::numeric,true)
 ON CONFLICT DO NOTHING`, args...)
	} else {
		args = append(args, change.ExpectedAccountVersion, change.ExpectedSocialLinkVersion)
		n, err = w.Exec(ctx, `UPDATE identity.accounts SET version=$7::numeric,social_link_version=$8::numeric,linked=true
 WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND provider=$4 AND issuer=$5 AND subject=$6
 AND version=$9::numeric AND social_link_version=$10::numeric AND NOT linked`, args...)
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	if change.ExpectedAccountVersion != 0 {
		// Associations describe current access, not immutable credential history.
		// ApplyAccountUnlink removes target methods; a fresh link must not attach
		// its previous disabled credentials again merely by reusing the account ID.
		// Keep every credential-reference tombstone and its version non-reassignable.
		if _, err := w.Exec(ctx, `DELETE FROM identity.account_credentials m USING identity.credential_references c
 WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.account_id=$3
 AND c.tenant_id=m.tenant_id AND c.user_id=m.user_id AND c.credential_id=m.credential_id AND c.kind=3 AND NOT c.enabled`, string(a.TenantID), string(a.UserID), string(a.ID)); err != nil {
			return err
		}
	}
	if m := change.Method; m != nil {
		var expiry any
		if !m.ExpiresAt.IsZero() {
			expiry = m.ExpiresAt
		}
		n, err = w.Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled,expires_at)
 VALUES($1,$2,$3,$4,$5,$6::numeric,$7,$8) ON CONFLICT DO NOTHING`, string(a.TenantID), string(a.UserID), string(m.Credential.ID), int16(m.Credential.Kind), m.Credential.Owner, m.Credential.Version, m.Usable, expiry)
		if err != nil {
			return err
		}
		if n != 1 {
			return fail(identity.ConflictError{})
		}
		n, err = w.Exec(ctx, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, string(a.TenantID), string(a.UserID), string(m.Credential.ID), string(a.ID))
		if err != nil {
			return err
		}
		if n != 1 {
			return fail(identity.ConflictError{})
		}
	}
	return w.usable()
}
