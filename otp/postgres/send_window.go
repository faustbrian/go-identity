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

// A family omits per-challenge, flow, target and rotating digest-key identities:
// changing those cannot restore a send allowance. Its separate HMAC domain uses
// the already pinned stable abuse key, never a raw destination or code key.
func (p lockoutProfile) sendIdentity(scope otp.DigestScopeSpec) ([32]byte, error) {
	if p.key == ([32]byte{}) {
		return [32]byte{}, ErrInvalidCommand
	}
	if _, err := otp.NewDigestScope(scope); err != nil {
		return [32]byte{}, ErrInvalidCommand
	}
	h := hmac.New(sha256.New, p.key[:])
	_, _ = h.Write([]byte("identity-otp-send-family-v1\x00"))
	for _, value := range []string{scope.TenantID, string(scope.Purpose), scope.SubjectID, string(scope.Channel), scope.Destination.Value()} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// nextSendWindow proposes a rolling (now-hour, now] history from a locked
// primary snapshot. It grants no issue/delivery authority and does not mutate
// the snapshot. Bounded history survives policy revisions without refilling.
func nextSendWindow(profile otp.CodeProfile, sent []time.Time, now time.Time) ([]time.Time, error) {
	p, err := profile.Bindings()
	if err != nil || !nativeTime(now) || len(sent) > 10 || p.TTL%time.Microsecond != 0 || p.ResendInterval%time.Microsecond != 0 {
		return nil, ErrInvalidCommand
	}
	for i, at := range sent {
		if !nativeTime(at) || at.After(now) || i > 0 && (!at.After(sent[i-1]) || at.Sub(sent[i-1]) < 30*time.Second) {
			return nil, ErrInvalidCommand
		}
	}
	if len(sent) > 0 && now.Sub(sent[len(sent)-1]) < p.ResendInterval {
		return nil, ErrInvalidCommand
	}
	start := 0
	cutoff := now.Add(-time.Hour)
	for start < len(sent) && !sent[start].After(cutoff) {
		start++
	}
	if len(sent)-start >= int(p.MaximumSends) {
		return nil, ErrInvalidCommand
	}
	next := make([]time.Time, len(sent)-start+1)
	copy(next, sent[start:])
	next[len(next)-1] = now.UTC()
	return next, nil
}

type lockedSendFamily struct {
	schema, tenant string
	digest         [32]byte
	purpose        otp.Purpose
	version        uint64
	sent           []time.Time
}

func (lockedSendFamily) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.send-family(redacted)"))
}

// Initialization is private issuance work. The caller must first admit the
// original flow and lock shared abuse rows in their established order. Neither
// helper can open a transaction or commit; exact replay belongs to coordinator.
func (p lockoutProfile) initializeSendFamily(ctx context.Context, query challengeQuery, exec challengeExec, schema string, scope otp.DigestScopeSpec) error {
	if ctx == nil || query == nil || exec == nil || !validSchema(schema) {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	digest, err := p.sendIdentity(scope)
	if err != nil {
		return err
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if err := p.requireKey(ctx, query, quoted); err != nil {
		return err
	}
	if _, err := exec(ctx, `INSERT INTO `+quoted+`.send_families(tenant_id,scope_digest) VALUES($1,$2) ON CONFLICT DO NOTHING`, scope.TenantID, digest[:]); err != nil {
		return challengeFailure(ctx)
	}
	return ctx.Err()
}

func (p lockoutProfile) loadSendFamily(ctx context.Context, query challengeQuery, schema string, scope otp.DigestScopeSpec) (lockedSendFamily, error) {
	if ctx == nil || query == nil || !validSchema(schema) {
		return lockedSendFamily{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return lockedSendFamily{}, err
	}
	digest, err := p.sendIdentity(scope)
	if err != nil {
		return lockedSendFamily{}, err
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	if err := p.requireKey(ctx, query, quoted); err != nil {
		return lockedSendFamily{}, err
	}
	rows, err := query(ctx, `SELECT version::text,sent_at FROM `+quoted+`.send_families WHERE tenant_id=$1 AND scope_digest=$2 FOR UPDATE`, scope.TenantID, digest[:])
	if err != nil {
		return lockedSendFamily{}, challengeFailure(ctx)
	}
	if rows == nil {
		return lockedSendFamily{}, ErrUnavailable
	}
	defer rows.Close()
	var version string
	var sent []time.Time
	if !rows.Next() {
		if rows.Err() != nil {
			return lockedSendFamily{}, challengeFailure(ctx)
		}
		return lockedSendFamily{}, ErrInvalidCommand
	}
	if rows.Scan(&version, &sent) != nil || rows.Next() || rows.Err() != nil || len(sent) > 10 {
		return lockedSendFamily{}, challengeFailure(ctx)
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != version {
		return lockedSendFamily{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return lockedSendFamily{}, err
	}
	return lockedSendFamily{schema: quoted, tenant: scope.TenantID, digest: digest, purpose: scope.Purpose, version: v, sent: sent}, nil
}

// The caller samples database time AFTER obtaining the family lock. The CAS
// also enforces cooldown against primary time at the write. It must commit this
// proposal with challenge insertion, replacement, audit, encrypted delivery and
// journal result in the SAME coordinator transaction, or roll every part back.
func persistSendWindow(ctx context.Context, exec challengeExec, row lockedSendFamily, profile otp.CodeProfile, now time.Time) error {
	p, err := profile.Bindings()
	if ctx == nil || exec == nil || row.schema == "" || row.tenant == "" || row.digest == ([32]byte{}) || row.version == 0 || row.version == ^uint64(0) || err != nil || p.Purpose != row.purpose {
		return ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := nextSendWindow(profile, row.sent, now)
	if err != nil {
		return err
	}
	n, err := exec(ctx, `UPDATE `+row.schema+`.send_families SET sent_at=$4,version=$5::numeric WHERE tenant_id=$1 AND scope_digest=$2 AND version=$3::numeric AND $6::timestamptz<=clock_timestamp() AND (cardinality(sent_at)=0 OR sent_at[cardinality(sent_at)]+$7::bigint*interval '1 microsecond'<=clock_timestamp())`, row.tenant, row.digest[:], strconv.FormatUint(row.version, 10), next, strconv.FormatUint(row.version+1, 10), now, p.ResendInterval.Microseconds())
	if err != nil {
		return challengeFailure(ctx)
	}
	if n != 1 {
		return ErrInvalidCommand
	}
	return ctx.Err()
}
