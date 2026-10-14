package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// ReadPreAuth loads the exact original private projection from the borrowed
// primary transaction. It checks physical index/record agreement but not active
// state, expiry, cookie possession, reservation or user authority. IDs alone
// cannot authenticate a flow. The native owner must freeze/verify original
// request intent and cookie, then invoke locked admission in the same unit.
// Retained reserved/terminal records remain structural historical data only.
// No time is sampled, validity renewed, lock acquired or callback invoked.
// Missing scope is Forbidden; corrupt/storage failures are Unavailable;
// malformed/nil inputs are InvalidInput. All errors are redacted and bounded.
func ReadPreAuth[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, tenant identity.TenantID, id identity.PreAuthTransactionID) (session.PreAuthTransaction, error) {
	if ctx == nil || nilSessionHandle(q) || !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !scopeID(string(tenant)) {
		return session.PreAuthTransaction{}, identity.InvalidInputError{Field: "session_preauth"}
	}
	if _, err := identity.ParsePreAuthTransactionID(string(id)); err != nil {
		return session.PreAuthTransaction{}, identity.InvalidInputError{Field: "session_preauth"}
	}
	bounded, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return session.PreAuthTransaction{}, readError(bounded, bounded.Err())
	}
	rows, err := q.Query(bounded, `SELECT record,issued_at,expires_at,digest_version,digest,issued_version::text FROM `+pgx.Identifier{c.Schema}.Sanitize()+`.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(tenant), string(id))
	if err != nil {
		return session.PreAuthTransaction{}, readError(bounded, err)
	}
	if nilSessionHandle(rows) {
		return session.PreAuthTransaction{}, identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil || bounded.Err() != nil {
			return session.PreAuthTransaction{}, readError(bounded, err)
		}
		return session.PreAuthTransaction{}, identity.ForbiddenError{}
	}
	var payload, digest []byte
	var issued, expires, version string
	var keyVersion int64
	if err = rows.Scan(&payload, &issued, &expires, &keyVersion, &digest, &version); err != nil {
		return session.PreAuthTransaction{}, readError(bounded, err)
	}
	if rows.Next() {
		return session.PreAuthTransaction{}, identity.UnavailableError{}
	}
	if err = rows.Err(); err != nil || bounded.Err() != nil {
		return session.PreAuthTransaction{}, readError(bounded, err)
	}
	record, err := decodePreAuth(payload)
	if err != nil {
		return session.PreAuthTransaction{}, identity.UnavailableError{}
	}
	s, _ := record.Bindings()
	if s.Binding.Intent.TenantID != tenant || s.Binding.ID != id || s.Binding.IssuedAt.Format(storedTimeLayout) != issued || s.Binding.ExpiresAt.Format(storedTimeLayout) != expires || keyVersion != int64(s.Cookie.KeyVersion) || subtle.ConstantTimeCompare(digest, s.Cookie.Sum[:]) != 1 || version != strconv.FormatUint(s.Version, 10) {
		return session.PreAuthTransaction{}, identity.UnavailableError{}
	}
	return record, nil
}

// RequireReservedPreAuth performs read-only exact-owner admission under a share
// lock until the original transaction closes. The complete original binding,
// reservation command/fingerprint/generation and exclusive primary expiry must
// still match. It neither compares an OTP nor consumes/meters/renews the flow.
// The owning sealed callback checks all other current authority and must abort
// or poison on any error; zero/data-only custody grants no execution authority.
func RequireReservedPreAuth[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, record session.PreAuthTransaction, use PreAuthUse) error {
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, record)
	if err != nil {
		return err
	}
	defer stop()
	if !use.valid(s) {
		return identity.InvalidInputError{Field: "session_preauth_use"}
	}
	return lockPreAuth(bounded, q, c, record, s, canonical, &use, false)
}

// RebindPreAuth transfers only an exact reserved predecessor to its immediate
// positive successor generation under exclusion. The original record, version,
// cookie, policy and timeline remain unchanged; it never compares/meters a code,
// reactivates state or consumes a flow. Current primary expiry is checked after
// locking. Terminal, mismatched, skipped and overflowing ownership deny.
//
// This is a native SQL operation, NOT takeover/noncommit authorization. The
// owner must derive predecessor and successor from the coordinator's live
// sealed takeover invocation and abort on any error. A lease timeout, caller
// generation or connection failure cannot independently authorize invocation.
// No journal, transaction closure, release mechanism or callback is introduced.
func RebindPreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, previous PreAuthUse, next uint64) error {
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, record)
	if err != nil {
		return err
	}
	defer stop()
	if !previous.valid(s) || previous.Generation == ^uint64(0) || next != previous.Generation+1 {
		return identity.InvalidInputError{Field: "session_preauth_use"}
	}
	if err = lockPreAuth(bounded, q, c, record, s, canonical, &previous, true); err != nil {
		return err
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(previous.Command.CommandID))
	count, err := q.Exec(bounded, `UPDATE `+pgx.Identifier{c.Schema}.Sanitize()+`.preauth_transactions SET generation=$3::numeric WHERE tenant_id=$1 AND flow_id=$2 AND state='reserved' AND version=$4::numeric AND command_id=$5 AND fingerprint=$6 AND generation=$7::numeric`, string(s.Binding.Intent.TenantID), string(s.Binding.ID), strconv.FormatUint(next, 10), strconv.FormatUint(s.Version+1, 10), command, previous.Fingerprint[:], strconv.FormatUint(previous.Generation, 10))
	return preAuthWriteResult(bounded, count, err)
}
