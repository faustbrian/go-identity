package mfapostgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// LockedRecoveryCompletion retains actual unused-code comparison custody inside
// the exact protected MFA Apply. It is not reusable factor proof. Copies share
// one serial-use burn and the borrowed Work's lifetime; returned handles deny.
type LockedRecoveryCompletion struct {
	custody func() *lockedRecoveryCompletion
}
type lockedRecoveryCompletion struct {
	work         kernel.Work
	owner        kernel.MFACompletionContributor
	command      identity.Command
	binding      kernel.MFARecoveryAttemptBinding
	continuation mfa.PartialAuthContinuation
	row          recoveryCodeRow
	recorded     bool
}

// Format redacts credential and borrowed transaction authority.
func (LockedRecoveryCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.LockedRecoveryCompletion(redacted)"))
}

// MarshalJSON rejects borrowed custody export.
func (LockedRecoveryCompletion) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects borrowed custody export.
func (LockedRecoveryCompletion) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// LockRecoveryCompletion compares the original opaque code under current shared
// account/factor/continuation and active-set locks during protected Apply, after
// the coordinator provisionally consumes the child. Correct counted probing is
// never reused as proof. Missing, consumed or changed custody denies. The owner
// separately fences policy, original primary/browser and risk before calling.
// No attempt, code or session is mutated and no transaction/callback is started.
func LockRecoveryCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, keys RecoveryVerificationKeys) (LockedRecoveryCompletion, error) {
	if ctx == nil {
		return LockedRecoveryCompletion{}, invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return LockedRecoveryCompletion{}, err
	}
	b, p, err := w.MFACompletionConsumption(owner)
	if err != nil || b.Command.OperationID != "identity.mfa.recovery-use" {
		return LockedRecoveryCompletion{}, invalidAuthority()
	}
	code, ok := command.RecoveryCode()
	if !ok {
		return LockedRecoveryCompletion{}, invalidAuthority()
	}
	binding := kernel.MFARecoveryAttemptBinding{Command: b.Command, Plan: p, Fingerprint: b.Fingerprint, Generation: b.Generation}
	c, _, row, matched, err := lockRecovery(ctx, recoveryWorkStore(w.Query, w.Exec), binding, keys, code)
	if err != nil {
		return LockedRecoveryCompletion{}, err
	}
	if !matched {
		return LockedRecoveryCompletion{}, identity.ForbiddenError{}
	}
	s := &lockedRecoveryCompletion{work: w, owner: owner, command: command, binding: binding, continuation: c, row: row}
	return LockedRecoveryCompletion{custody: func() *lockedRecoveryCompletion { return s }}, nil
}

// RecordRecoveryCompletion burns the same just-compared unused code and completes
// its original continuation, spending one shared attempt even on the final
// allowed attempt. Set versions, child, session, audit and risk must commit or
// roll back together through the sole coordinator. Foreign, returned, repeated
// or stale custody denies. Every error must abort; no independent commit occurs.
func RecordRecoveryCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, a LockedRecoveryCompletion) error {
	if ctx == nil || a.custody == nil {
		return invalidAuthority()
	}
	s := a.custody()
	if s == nil || s.recorded || w != s.work {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, s.command); err != nil {
		return err
	}
	b, p, err := w.MFACompletionConsumption(owner)
	if err != nil || b.Command != s.binding.Command || b.Fingerprint != s.binding.Fingerprint || b.Generation != s.binding.Generation || p != s.binding.Plan {
		return invalidAuthority()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := completeRecovery(ctx, recoveryWorkStore(w.Query, w.Exec).sql, s.continuation, s.row, b.Command, now); err != nil {
		return err
	}
	s.recorded = true
	return nil
}

func completeRecovery(ctx context.Context, sql totpAttemptSQL, c mfa.PartialAuthContinuation, row recoveryCodeRow, command identity.CommandBinding, now time.Time) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m := row.set
	s, err := c.Bindings()
	if err != nil || row.consumed || command.OperationID != "identity.mfa.recovery-use" || command.TenantID != s.TenantID || m.TenantID != s.TenantID || m.UserID != identity.UserID(s.SubjectID) || command.AnonymousFlowID != string(s.SourcePreAuthID) || m.RowVersion == 0 || m.RowVersion == math.MaxUint64 || s.Version == math.MaxUint64 || row.index >= m.CodeCount || c.RequirePending(now) != nil {
		return identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(command.CommandID))
	if err != nil || len(id) != 16 {
		return invalidAuthority()
	}
	next, err := c.RecordAttempt("recovery-code", now, s.Version)
	if err != nil {
		return err
	}
	n, _ := next.Bindings()
	n.State = mfa.Completed
	if _, err := mfa.NewPartialAuthContinuation(n); err != nil {
		return err
	}
	digest, err := c.ScopeDigest()
	if err != nil {
		return err
	}
	count, err := sql.exec(ctx, `UPDATE identity_mfa.recovery_sets SET row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND set_id=$3 AND factor_id=$4 AND set_version=$5::numeric AND row_version=$6::numeric AND state=2 AND key_version=$7 AND code_count=$8`, string(m.TenantID), string(m.UserID), m.SetID, m.FactorID, strconv.FormatUint(m.SetVersion, 10), strconv.FormatUint(m.RowVersion, 10), int64(m.KeyVersion), int32(m.CodeCount))
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	count, err = sql.exec(ctx, `UPDATE identity_mfa.recovery_codes SET consumed_command_id=$5,consumed_purpose='identity.mfa.recovery-use',consumed_at=clock_timestamp() WHERE tenant_id=$1 AND set_id=$2 AND code_index=$3 AND digest=$4 AND consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL`, string(m.TenantID), m.SetID, int32(row.index), row.digest[:], id)
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	count, err = sql.exec(ctx, `UPDATE identity_mfa.continuations SET state=3,version=$4::numeric,attempts_remaining=$5 WHERE tenant_id=$1 AND continuation_id=$2 AND user_id=$3 AND scope_digest=$6 AND version=$7::numeric AND state=$8 AND attempts_remaining=$9 AND expires_at>clock_timestamp()`, string(s.TenantID), string(s.ID), string(s.SubjectID), strconv.FormatUint(n.Version, 10), int32(n.AttemptsRemaining), digest[:], strconv.FormatUint(s.Version, 10), int16(s.State), int32(s.AttemptsRemaining))
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

// RequireRecordedRecoveryCompletion confirms the actual provisional code burn
// and continuation completion in this same protected invocation. It returns
// original non-secret set/scope correlation and the durable primary command for
// native session mapping, not reusable proof. Unrecorded, foreign, returned,
// changed or expired custody denies. Current primary/policy/session authority
// and rollback on every error remain required; this read creates no transaction.
func RequireRecordedRecoveryCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, a LockedRecoveryCompletion) (mfa.ContinuationSpec, RecoverySetMetadata, identity.CommandID, error) {
	deny := func(err error) (mfa.ContinuationSpec, RecoverySetMetadata, identity.CommandID, error) {
		return mfa.ContinuationSpec{}, RecoverySetMetadata{}, "", err
	}
	if ctx == nil || a.custody == nil {
		return deny(invalidAuthority())
	}
	s := a.custody()
	if s == nil || !s.recorded || w != s.work || command != s.command {
		return deny(invalidAuthority())
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return deny(err)
	}
	b, p, err := w.MFACompletionConsumption(owner)
	if err != nil || b.Command != s.binding.Command || b.Fingerprint != s.binding.Fingerprint || b.Generation != s.binding.Generation || p != s.binding.Plan {
		return deny(invalidAuthority())
	}
	original, err := s.continuation.Bindings()
	if err != nil {
		return deny(err)
	}
	m := s.row.set
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.Command.CommandID))
	if err != nil {
		return deny(invalidAuthority())
	}
	var primary []byte
	var now time.Time
	err = recoveryWorkStore(w.Query, w.Exec).sql.query(ctx, `SELECT c.origin_command_id,clock_timestamp()
FROM identity_mfa.continuations c
JOIN identity_mfa.recovery_sets r ON r.tenant_id=c.tenant_id AND r.user_id=c.user_id
JOIN identity_mfa.recovery_codes k ON k.tenant_id=r.tenant_id AND k.set_id=r.set_id
JOIN identity_mfa.totp_factors t ON t.tenant_id=r.tenant_id AND t.user_id=r.user_id AND t.factor_id=r.factor_id
JOIN identity_mfa.factor_authorities f ON f.tenant_id=c.tenant_id AND f.user_id=c.user_id
JOIN identity.users u ON u.tenant_id=c.tenant_id AND u.user_id=c.user_id
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.command_id=c.origin_command_id AND j.purpose=c.origin_purpose
JOIN identity.identity_command_id_claims q ON q.command_id=j.command_id AND q.tenant_id=j.tenant_id AND q.purpose=j.purpose
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.continuation_id=$3 AND r.set_id=$4
AND c.state=3 AND c.version=$5::numeric AND c.attempts_remaining=$6 AND c.scope_digest=$7
AND r.state=2 AND r.set_version=$8::numeric AND r.row_version=$9::numeric AND r.factor_id=$10 AND r.key_version=$11 AND r.code_count=$12
AND k.code_index=$13 AND k.digest=$14 AND k.consumed_command_id=$15 AND k.consumed_purpose='identity.mfa.recovery-use' AND k.consumed_at IS NOT NULL
AND t.state=2 AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL AND t.enrollment_version=$17::numeric
AND f.version=$16::numeric AND f.active_factors BETWEEN 1 AND 64 AND u.status='active'
AND j.state='committed' AND NOT q.retired AND q.fingerprint=c.origin_fingerprint AND j.generation=c.origin_generation
AND c.expires_at>clock_timestamp()`, []any{string(m.TenantID), string(m.UserID), string(original.ID), m.SetID, strconv.FormatUint(original.Version+1, 10), int32(original.AttemptsRemaining - 1), p.ScopeDigest[:], strconv.FormatUint(m.SetVersion, 10), strconv.FormatUint(m.RowVersion+1, 10), m.FactorID, int64(m.KeyVersion), int32(m.CodeCount), int32(s.row.index), s.row.digest[:], id, strconv.FormatUint(original.FactorVersion, 10), strconv.FormatUint(m.FactorEnrollmentVersion, 10)}, &primary, &now)
	if err != nil {
		return deny(attemptStoreError(ctx, err))
	}
	if len(primary) != 16 || s.continuation.RequirePending(now) != nil {
		return deny(identity.ForbiddenError{})
	}
	primaryID, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(primary))
	if err != nil {
		return deny(invalidAuthority())
	}
	return original, m, primaryID, nil
}
