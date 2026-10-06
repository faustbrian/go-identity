package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/otp"
	"github.com/jackc/pgx/v5"
)

// Private native persistence, not a verifier or current-flow authority. The
// dedicated key must be retained across reissues and code-key rotations. Public
// callbacks/configuration and explicit deployment binding are not activated yet.
type lockoutProfile struct{ key [32]byte }
type lockoutIdentity struct {
	kind   string
	digest [32]byte
}
type lockoutRow struct {
	identity lockoutIdentity
	version  uint64
}
type lockedLockouts struct {
	schema, tenant string
	rows           []lockoutRow
}

func (lockoutProfile) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.LockoutProfile(redacted)"))
}
func (lockoutProfile) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (lockoutProfile) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (lockedLockouts) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.LockedLockouts(redacted)"))
}
func (lockedLockouts) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (lockedLockouts) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

func newLockoutProfile(key [32]byte) (lockoutProfile, error) {
	if key == ([32]byte{}) {
		return lockoutProfile{}, ErrInvalidConfiguration
	}
	return lockoutProfile{key: key}, nil
}

func (p lockoutProfile) binding() [32]byte {
	m := hmac.New(sha256.New, p.key[:])
	_, _ = m.Write([]byte("identity-otp-lockout-key-binding-v1\x00"))
	return [32]byte(m.Sum(nil))
}

// Abuse identities intentionally exclude challenge, purpose, flow, policy,
// generation and code-key version. Neither resending nor switching purpose
// creates a new subject/destination budget. Pre-account flows use destination
// only; changing a subject still preserves the same destination lockout.
func (p lockoutProfile) identities(scope otp.DigestScopeSpec) ([]lockoutIdentity, error) {
	if p.key == ([32]byte{}) {
		return nil, ErrInvalidConfiguration
	}
	if _, err := otp.NewDigestScope(scope); err != nil {
		return nil, ErrInvalidCommand
	}
	derive := func(kind, channel, value string) lockoutIdentity {
		data := []byte("identity-otp-shared-lockout-v1\x00")
		for _, s := range []string{scope.TenantID, kind, channel, value} {
			data = binary.BigEndian.AppendUint16(data, uint16(len(s)))
			data = append(data, s...)
		}
		defer clear(data)
		m := hmac.New(sha256.New, p.key[:])
		_, _ = m.Write(data)
		return lockoutIdentity{kind: kind, digest: [32]byte(m.Sum(nil))}
	}
	ids := []lockoutIdentity{derive("destination", string(scope.Channel), scope.Destination.Value())}
	if scope.SubjectID != "" {
		ids = append(ids, derive("subject", "", scope.SubjectID))
	}
	return ids, nil
}

func (p lockoutProfile) requireKey(ctx context.Context, query challengeQuery, schema string) error {
	rows, err := query(ctx, `SELECT key_binding FROM `+schema+`.lockout_key_binding WHERE singleton=true FOR SHARE`)
	if err != nil {
		return challengeFailure(ctx)
	}
	if rows == nil {
		return ErrUnavailable
	}
	defer rows.Close()
	var stored []byte
	if !rows.Next() || rows.Scan(&stored) != nil || rows.Next() || rows.Err() != nil {
		return challengeFailure(ctx)
	}
	expected := p.binding()
	if !hmac.Equal(expected[:], stored) {
		return ErrUnavailable
	}
	return ctx.Err()
}

// Issuance precreates absence under primary uniqueness before any challenge.
// Existing rows are never reset; a changed key cannot seed another namespace.
func (p lockoutProfile) initializeLockouts(ctx context.Context, query challengeQuery, exec challengeExec, schema string, scope otp.DigestScopeSpec) error {
	if ctx == nil || query == nil || exec == nil || !validSchema(schema) {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ids, err := p.identities(scope)
	if err != nil {
		return err
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if err := p.requireKey(ctx, query, quoted); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := exec(ctx, `INSERT INTO `+quoted+`.lockouts(tenant_id,kind,scope_digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, scope.TenantID, id.kind, id.digest[:]); err != nil {
			return challengeFailure(ctx)
		}
	}
	return ctx.Err()
}

// Lock all shared scope rows in canonical destination/subject order before the
// challenge. No absent-row success, unmetered comparison or clock before a lock
// wait is allowed. Keep these locks until the coordinator's transaction ends.
func (p lockoutProfile) loadLockouts(ctx context.Context, query challengeQuery, schema string, scope otp.DigestScopeSpec) (lockedLockouts, time.Time, error) {
	bad := func(err error) (lockedLockouts, time.Time, error) { return lockedLockouts{}, time.Time{}, err }
	if ctx == nil || query == nil || !validSchema(schema) {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	ids, err := p.identities(scope)
	if err != nil {
		return bad(err)
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if err := p.requireKey(ctx, query, quoted); err != nil {
		return bad(err)
	}
	locked := lockedLockouts{schema: quoted, tenant: scope.TenantID}
	var deadlines []time.Time
	for _, id := range ids {
		rows, err := query(ctx, `SELECT version::text,blocked_until FROM `+quoted+`.lockouts WHERE tenant_id=$1 AND kind=$2 AND scope_digest=$3 FOR UPDATE`, scope.TenantID, id.kind, id.digest[:])
		if err != nil {
			return bad(challengeFailure(ctx))
		}
		if rows == nil {
			return bad(ErrUnavailable)
		}
		var version string
		var until *time.Time
		if !rows.Next() {
			e := rows.Err()
			rows.Close()
			if e != nil {
				return bad(challengeFailure(ctx))
			}
			return bad(ErrInvalidCommand)
		}
		e := rows.Scan(&version, &until)
		extra := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if e != nil || extra || rowErr != nil {
			return bad(challengeFailure(ctx))
		}
		v, e := strconv.ParseUint(version, 10, 64)
		if e != nil || v == 0 || strconv.FormatUint(v, 10) != version || until != nil && !nativeTime(*until) {
			return bad(ErrUnavailable)
		}
		locked.rows = append(locked.rows, lockoutRow{identity: id, version: v})
		if until != nil {
			deadlines = append(deadlines, *until)
		}
	}
	clock, err := query(ctx, `SELECT clock_timestamp()`)
	if err != nil {
		return bad(challengeFailure(ctx))
	}
	if clock == nil {
		return bad(ErrUnavailable)
	}
	var now time.Time
	if !clock.Next() || clock.Scan(&now) != nil || clock.Next() || clock.Err() != nil {
		clock.Close()
		return bad(challengeFailure(ctx))
	}
	clock.Close()
	if !nativeTime(now) {
		return bad(ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	for _, until := range deadlines {
		if now.Before(until) {
			return bad(ErrInvalidCommand)
		}
	}
	return locked, now, nil
}

// Only a newly counted wrong-exhaustion decision may invoke this projection.
// Persist it with the challenge count, audit and stable denied result in the
// same coordinator transaction. Correct checks/exhaustion never call it.
func extendLockouts(ctx context.Context, exec challengeExec, locked lockedLockouts, now time.Time, after time.Duration) error {
	if ctx == nil || exec == nil || locked.schema == "" || len(locked.rows) < 1 || len(locked.rows) > 2 || !nativeTime(now) || after <= 0 || after > 24*time.Hour || after%time.Microsecond != 0 || !nativeTime(now.Add(after)) {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, row := range locked.rows {
		if row.version == ^uint64(0) {
			return ErrInvalidCommand
		}
		n, err := exec(ctx, `UPDATE `+locked.schema+`.lockouts SET blocked_until=GREATEST(blocked_until,$4::timestamptz),version=$5::numeric WHERE tenant_id=$1 AND kind=$2 AND scope_digest=$3 AND version=$6::numeric`, locked.tenant, row.identity.kind, row.identity.digest[:], now.Add(after), strconv.FormatUint(row.version+1, 10), strconv.FormatUint(row.version, 10))
		if err != nil {
			return challengeFailure(ctx)
		}
		if n != 1 {
			return ErrInvalidCommand
		}
	}
	return ctx.Err()
}
