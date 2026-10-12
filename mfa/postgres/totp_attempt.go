package mfapostgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// LockedTOTPAttempt borrows current factor/continuation locks during one native
// counted-denial callback. It is not successful factor proof or permission to
// consume a child or issue a session. Copies share serial-use custody and the
// single provisional charge. No handle remains usable after callback return.
type LockedTOTPAttempt struct{ custody func() *lockedTOTPAttempt }
type lockedTOTPAttempt struct {
	work         kernel.MFATOTPAttemptWork
	owner        kernel.MFATOTPAttemptContributor
	binding      kernel.MFATOTPAttemptBinding
	metadata     TOTPFactorMetadata
	continuation mfa.PartialAuthContinuation
	now          time.Time
	spent        bool
}

// Format prevents diagnostic export of callback authority and factor identity.
func (LockedTOTPAttempt) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.LockedTOTPAttempt(redacted)"))
}

// MarshalJSON rejects implicit authority export.
func (LockedTOTPAttempt) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit authority export.
func (LockedTOTPAttempt) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

func (a LockedTOTPAttempt) live() (*lockedTOTPAttempt, error) {
	if a.custody == nil {
		return nil, invalidAuthority()
	}
	s := a.custody()
	if s == nil || s.spent {
		return nil, invalidAuthority()
	}
	b, err := s.work.Binding(s.owner)
	if err != nil || b != s.binding {
		return nil, invalidAuthority()
	}
	return s, nil
}

// VerificationState returns fenced factor metadata and primary database time
// only while the original native callback is live. The MFA owner compares the
// original opaque code using an already decrypted owned secret; no provider IO
// or caller callback is permitted while locks are held. This is not a proof.
func (a LockedTOTPAttempt) VerificationState() (TOTPFactorMetadata, time.Time, error) {
	s, err := a.live()
	if err != nil {
		return TOTPFactorMetadata{}, time.Time{}, err
	}
	return s.metadata, s.now, nil
}

type totpAttemptSQL struct {
	query func(context.Context, string, []any, ...any) error
	exec  func(context.Context, string, ...any) (int64, error)
}

func nativeTOTPAttemptSQL(w kernel.MFATOTPAttemptWork) totpAttemptSQL {
	return totpAttemptSQL{query: func(ctx context.Context, q string, args []any, dest ...any) error {
		rows, err := w.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err = rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		if err = rows.Scan(dest...); err != nil {
			return err
		}
		if rows.Next() {
			return identity.UnavailableError{}
		}
		return rows.Err()
	}, exec: w.Exec}
}

// LockTOTPAttempt rechecks the reader's complete encrypted factor fence and
// original continuation under the exact live registered native owner. Locks are
// acquired account, factor authority, continuation, then factor, and held by the
// sole coordinator. Missing/stale/foreign/expired authority denies. No secret is
// decrypted, no attempt is spent, no successful replay advances, and no child or
// session is consumed here. The owner must separately fence current policy and
// original primary-proof authority. No transaction or retry is started.
func LockTOTPAttempt(ctx context.Context, w kernel.MFATOTPAttemptWork, owner kernel.MFATOTPAttemptContributor, snapshot TOTPFactorSnapshot) (LockedTOTPAttempt, error) {
	if ctx == nil {
		return LockedTOTPAttempt{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return LockedTOTPAttempt{}, err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return LockedTOTPAttempt{}, err
	}
	c, now, err := lockTOTPAttempt(ctx, nativeTOTPAttemptSQL(w), b, snapshot)
	if err != nil {
		return LockedTOTPAttempt{}, err
	}
	m, _ := snapshot.Metadata()
	s := &lockedTOTPAttempt{work: w, owner: owner, binding: b, metadata: m, continuation: c, now: now}
	return LockedTOTPAttempt{custody: func() *lockedTOTPAttempt { return s }}, nil
}

// RecordTOTPAttemptDenial provisionally charges exactly one shared attempt for
// the locked original continuation after the native owner actually denies the
// opaque TOTP code. It advances version and revokes on exhaustion without
// touching encrypted factor/replay, child consumption or sessions. The caller
// must return MFAAttemptDenied to the sole coordinator; audit, journal and the
// charge commit together there. Any error must abort, never be ignored. Copies
// cannot charge twice; this handle is serial-use and invalidated after success.
func RecordTOTPAttemptDenial(ctx context.Context, w kernel.MFATOTPAttemptWork, owner kernel.MFATOTPAttemptContributor, a LockedTOTPAttempt) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := a.live()
	if err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil || w != s.work || b != s.binding {
		return invalidAuthority()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = spendTOTPAttempt(ctx, nativeTOTPAttemptSQL(w), s.continuation, now); err != nil {
		return err
	}
	s.spent = true
	return nil
}

func attemptStoreError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	return identity.UnavailableError{}
}

func lockTOTPAttempt(ctx context.Context, sql totpAttemptSQL, b kernel.MFATOTPAttemptBinding, snapshot TOTPFactorSnapshot) (mfa.PartialAuthContinuation, time.Time, error) {
	deny := func() (mfa.PartialAuthContinuation, time.Time, error) {
		return mfa.PartialAuthContinuation{}, time.Time{}, identity.ForbiddenError{}
	}
	if snapshot.custody == nil {
		return deny()
	}
	f := snapshot.custody()
	m := f.metadata
	p := b.Plan
	if m.TenantID != b.Command.TenantID || m.UserID != p.UserID || string(m.ContinuationID) != string(p.ID) || m.ContinuationVersion != p.ContinuationVersion || m.ScopeDigest != p.ScopeDigest || m.FactorAuthorityVersion != p.FactorVersion || p.PolicyVersion == 0 {
		return deny()
	}
	c, now, err := lockTOTPAttemptContinuation(ctx, sql, b)
	if err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, err
	}
	var stored []byte
	var ev, rv, algorithm, issuer string
	var last *string
	var digits, period, skew int16
	err = sql.query(ctx, `SELECT encrypted_secret,enrollment_version::text,row_version::text,last_step::text,algorithm,digits,period_seconds,skew_steps,issuer FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL FOR UPDATE`, []any{string(m.TenantID), string(m.UserID), m.FactorID}, &stored, &ev, &rv, &last, &algorithm, &digits, &period, &skew, &issuer)
	defer clear(stored)
	if err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, attemptStoreError(ctx, err)
	}
	if ev != strconv.FormatUint(m.EnrollmentVersion, 10) || rv != strconv.FormatUint(m.RowVersion, 10) || !bytes.Equal(stored, f.wire) || algorithm != m.Profile.Algorithm || issuer != m.Profile.Issuer || int64(digits) != int64(m.Profile.Digits) || time.Duration(period)*time.Second != m.Profile.Period || int64(skew) != int64(m.Profile.AllowedSkewSteps) || (last != nil) != m.Replay.Used || last != nil && *last != strconv.FormatUint(m.Replay.LastStep, 10) {
		return deny()
	}
	if err := sql.query(ctx, `SELECT clock_timestamp()`, nil, &now); err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, attemptStoreError(ctx, err)
	}
	if c.RequirePending(now) != nil {
		return deny()
	}
	return c, now.UTC(), nil
}

// Shared authoritative account/continuation fences do not require a fabricated
// factor snapshot. Both ordinary wrong-code and absent-factor denial use them.
func lockTOTPAttemptContinuation(ctx context.Context, sql totpAttemptSQL, b kernel.MFATOTPAttemptBinding) (mfa.PartialAuthContinuation, time.Time, error) {
	deny := func() (mfa.PartialAuthContinuation, time.Time, error) {
		return mfa.PartialAuthContinuation{}, time.Time{}, identity.ForbiddenError{}
	}
	p := b.Plan
	args := []any{string(b.Command.TenantID), string(p.UserID)}
	var status string
	if err := sql.query(ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, args, &status); err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, attemptStoreError(ctx, err)
	}
	if status != "active" {
		return deny()
	}
	var fv string
	var active int32
	if err := sql.query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, args, &fv, &active); err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, attemptStoreError(ctx, err)
	}
	if fv != strconv.FormatUint(p.FactorVersion, 10) || active < 1 || active > 64 {
		return deny()
	}
	var wire, digest []byte
	var state int16
	var version, source string
	var maximum, remaining int32
	var issued, expires, now time.Time
	err := sql.query(ctx, `SELECT c.original_scope,c.scope_digest,c.state,c.version::text,c.max_attempts,c.attempts_remaining,c.source_preauth_id,c.issued_at,c.expires_at,clock_timestamp()
FROM identity_mfa.continuations c
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.purpose=c.origin_purpose AND j.command_id=c.origin_command_id
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.continuation_id=$3
AND j.state='committed' AND NOT k.retired AND k.fingerprint=c.origin_fingerprint AND j.generation=c.origin_generation FOR UPDATE OF c`, []any{string(b.Command.TenantID), string(p.UserID), string(p.ID)}, &wire, &digest, &state, &version, &maximum, &remaining, &source, &issued, &expires, &now)
	defer clear(wire)
	if err != nil {
		return mfa.PartialAuthContinuation{}, time.Time{}, attemptStoreError(ctx, err)
	}
	if !bytes.Equal(digest, p.ScopeDigest[:]) || version != strconv.FormatUint(p.ContinuationVersion, 10) || maximum <= 0 || remaining <= 0 {
		return deny()
	}
	c, err := decodeContinuationScope(wire, p.ScopeDigest, mfa.ContinuationState(state), p.ContinuationVersion, uint32(remaining))
	if err != nil {
		return deny()
	}
	s, err := c.Bindings()
	if err != nil || s.TenantID != b.Command.TenantID || s.SubjectID != identity.SubjectID(p.UserID) || string(s.ID) != string(p.ID) || string(s.SourcePreAuthID) != source || source != b.Command.AnonymousFlowID || s.PolicyVersion != p.PolicyVersion || s.FactorVersion != p.FactorVersion || s.MaxAttempts != uint32(maximum) || !s.IssuedAt.Equal(issued) || !s.ExpiresAt.Equal(expires) || !slices.Contains(s.AllowedMethods, "totp") || c.RequirePending(now) != nil {
		return deny()
	}
	return c, now.UTC(), nil
}

func spendTOTPAttempt(ctx context.Context, sql totpAttemptSQL, c mfa.PartialAuthContinuation, now time.Time) error {
	s, err := c.Bindings()
	if err != nil {
		return invalidAuthority()
	}
	next, err := c.RecordAttempt("totp", now, s.Version)
	if err != nil {
		return err
	}
	n, _ := next.Bindings()
	digest, _ := c.ScopeDigest()
	count, err := sql.exec(ctx, `UPDATE identity_mfa.continuations SET state=$4,version=$5::numeric,attempts_remaining=$6 WHERE tenant_id=$1 AND continuation_id=$2 AND user_id=$3 AND scope_digest=$7 AND version=$8::numeric AND state=$9 AND attempts_remaining=$10 AND expires_at>clock_timestamp()`, string(s.TenantID), string(s.ID), string(s.SubjectID), int16(n.State), strconv.FormatUint(n.Version, 10), int32(n.AttemptsRemaining), digest[:], strconv.FormatUint(s.Version, 10), int16(s.State), int32(s.AttemptsRemaining))
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
