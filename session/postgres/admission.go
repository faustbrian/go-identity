package postgres

import (
	"bytes"
	"context"
	"reflect"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// SessionRows is the synchronous borrowed cursor contract implemented by pgx
// Rows and identity's generation-bound WorkRows. Close releases only this
// result; it must not terminalize the original transaction.
type SessionRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

// SessionQueryer preserves the native owner's narrower row type without raw
// connection escape. Protected operations require the original primary
// transaction, never a replica or autocommit pool. The owning participant must
// fence its scope/lifetime and poison or abort on every returned error.
type SessionQueryer[R SessionRows] interface {
	Query(context.Context, string, ...any) (R, error)
}

// RequireSession compares the exact frozen session record and active family
// under share locks retained until the original primary transaction closes.
// It checks database time after lock acquisition against original absolute and
// idle expiry. Expected must be frozen in the owning command before reservation;
// no caller input, cache promotion or retry may replace that record. An earlier
// context/Work deadline wins; Config supplies a finite maximum read budget.
//
// This checks only session-owned state, not current global, tenant, user,
// credential, authorization, organization, factor or passkey authority. The
// owning workflow must check every applicable authority and authentic proof,
// and recheck temporal validity before commit. Success creates no validity
// evidence, freshness renewal, bearer, session or authorization decision.
// Missing, revoked, expired or unequal records return redacted Forbidden;
// malformed inputs are InvalidInput and corrupt/storage failures Unavailable.
// Cancellation/deadline classifications are preserved. It never retains a
// cursor/transaction, begins/closes a transaction, writes or invokes callbacks.
func RequireSession[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, expected session.Session) error {
	if ctx == nil || nilSessionHandle(q) || !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return identity.InvalidInputError{Field: "session_admission"}
	}
	spec, err := expected.Bindings()
	if err != nil {
		return identity.InvalidInputError{Field: "session_admission"}
	}
	canonical, expiry, err := encodeRecord(expected)
	if err != nil {
		return identity.InvalidInputError{Field: "session_admission"}
	}
	bounded, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	if bounded.Err() != nil {
		return readError(bounded, bounded.Err())
	}
	schema := pgx.Identifier{c.Schema}.Sanitize()
	// Require both physical index and complete immutable record agreement. A
	// matching positive version on a different user/family/digest is never enough.
	rows, err := q.Query(bounded, `SELECT s.record::text FROM `+schema+`.sessions s JOIN `+schema+`.families f USING(tenant_id,family_id,user_id)
 WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.session_id=$3 AND s.family_id=$4
 AND s.version=$5::numeric AND s.family_version=$6::numeric AND f.version=$6::numeric
 AND s.digest_version=$7 AND s.digest=$8 AND s.expires_at=$9
 AND s.state='active' AND f.state='active' FOR SHARE OF s,f`, string(spec.TenantID), string(spec.UserID), spec.SessionID, spec.FamilyID, strconv.FormatUint(spec.Version, 10), strconv.FormatUint(spec.FamilyVersion, 10), int64(spec.Lookup.KeyVersion), spec.Lookup.Sum[:], expiry)
	if err != nil {
		return readError(bounded, err)
	}
	if nilSessionHandle(rows) {
		return identity.UnavailableError{}
	}
	var payload []byte
	err = readSessionAdmission(rows, &payload)
	rows.Close()
	if err != nil {
		return admissionError(bounded, err)
	}
	stored, err := decodeRecord(payload)
	if err != nil {
		return identity.UnavailableError{}
	}
	encoded, _, err := encodeRecord(stored)
	if err != nil {
		return identity.UnavailableError{}
	}
	if !bytes.Equal(canonical, encoded) {
		return identity.ForbiddenError{}
	}
	// A timestamp evaluated in the locking SELECT can precede a lock wait.
	// Read the authoritative clock only after both locks have been acquired.
	clockRows, err := q.Query(bounded, `SELECT clock_timestamp()`)
	if err != nil {
		return readError(bounded, err)
	}
	if nilSessionHandle(clockRows) {
		return identity.UnavailableError{}
	}
	var now time.Time
	err = readSessionAdmission(clockRows, &now)
	clockRows.Close()
	if err != nil {
		return admissionError(bounded, err)
	}
	if bounded.Err() != nil {
		return readError(bounded, bounded.Err())
	}
	lifetime, err := expected.Lifetime(now)
	if err != nil || !now.Before(lifetime.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func readSessionAdmission[R SessionRows](rows R, target any) error {
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	if err := rows.Scan(target); err != nil {
		return err
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	return rows.Err()
}

func admissionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return readError(ctx, err)
	}
	switch err.(type) {
	case identity.ForbiddenError, identity.UnavailableError:
		return err
	}
	return identity.UnavailableError{}
}

// Reflection validates literal/typed nil only; it never discovers or wires
// behavior. Row ownership and transaction fencing remain with the caller.
func nilSessionHandle(v any) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	}
	return false
}
