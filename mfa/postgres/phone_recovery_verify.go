package mfapostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// PhoneRecoveryTOTPAttempt classifies actual cryptographic comparison only in
// its original live OTP owner callback. It is not consuming proof and carries no
// replay counter. Copies expire when the callback returns; no attempt budget is
// owned here. The OTP owner alone debits its existing SMS budget on denial.
type PhoneRecoveryTOTPAttempt struct {
	custody func() phoneRecoveryTOTPAttempt
}
type phoneRecoveryTOTPAttempt struct {
	work     kernel.OTPAttemptWork
	owner    kernel.OTPAttemptContributor
	binding  kernel.OTPAttemptBinding
	accepted bool
}

// Accepted rechecks the exact owner, Work and frozen command generation before
// revealing the comparison. Zero, foreign and returned handles deny; this
// observation can never be supplied to the consuming verification API.
func (a PhoneRecoveryTOTPAttempt) Accepted(ctx context.Context, w kernel.OTPAttemptWork, owner kernel.OTPAttemptContributor) (bool, error) {
	if ctx == nil || a.custody == nil {
		return false, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s := a.custody()
	b, err := w.Binding(owner)
	if err != nil || w != s.work || owner != s.owner || b != s.binding {
		return false, invalidAuthority()
	}
	return s.accepted, nil
}

// VerifyPhoneRecoveryTOTPAttempt locks active user, aggregate factor authority,
// then the original confirmed factor BEFORE the caller locks OTP/challenge
// exclusions. It verifies the exact sealed input or generated command's TOTP with
// the core verifier at current database time, without advancing replay or any
// budget. A wrong/replayed code yields a live classification of false; stale
// authority, expiry and unavailable storage yield errors. Every error must abort
// the parent callback. No caller/provider callback, decryption, transaction or
// retry occurs under locks. Prepared plaintext is destroyed on every return.
func VerifyPhoneRecoveryTOTPAttempt(ctx context.Context, w kernel.OTPAttemptWork, owner kernel.OTPAttemptContributor, prepared PreparedPhoneRecoveryTOTP) (PhoneRecoveryTOTPAttempt, error) {
	s, err := prepared.borrow()
	if err != nil {
		return PhoneRecoveryTOTPAttempt{}, err
	}
	defer s.finish()
	if ctx == nil {
		return PhoneRecoveryTOTPAttempt{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return PhoneRecoveryTOTPAttempt{}, err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return PhoneRecoveryTOTPAttempt{}, err
	}
	c, err := w.NativeCommand(owner)
	if err != nil || b.Generation == 0 || b.Fingerprint == ([32]byte{}) || b.Plan.Mode != kernel.OTPConsume {
		return PhoneRecoveryTOTPAttempt{}, invalidAuthority()
	}
	if err := requirePhoneRecoveryTOTPAttemptCommand(c, b.Command, s); err != nil {
		return PhoneRecoveryTOTPAttempt{}, err
	}
	_, accepted, err := verifyPhoneRecoveryTOTPCode(ctx, s, phoneRecoveryAttemptSQL(w), b.Command, b.Fingerprint, b.Generation)
	if err != nil {
		return PhoneRecoveryTOTPAttempt{}, err
	}
	result := phoneRecoveryTOTPAttempt{work: w, owner: owner, binding: b, accepted: accepted}
	return PhoneRecoveryTOTPAttempt{custody: func() phoneRecoveryTOTPAttempt { return result }}, nil
}

func requirePhoneRecoveryTOTPAttemptCommand(command identity.Command, binding identity.CommandBinding, prepared *phoneRecoveryTOTPUse) error {
	if prepared == nil || command != prepared.command {
		return invalidAuthority()
	}
	m, err := prepared.snapshot.Metadata()
	if err != nil {
		return err
	}
	_, input, err := phoneRecoveryCommand(command, m)
	f, ok := command.PhonePasswordResetFeature()
	if prepared.input {
		f, ok = command.PhonePasswordResetInputFeature()
	}
	if err != nil || input != prepared.input || !ok || f.Binding != binding {
		return invalidAuthority()
	}
	return nil
}

// PhoneRecoveryTOTPCompletion is opaque nonsecret custody for one actual replay
// CAS in the same protected Work as the parent password mutation. It cannot be
// constructed from a scalar counter, accepted flag, attempt handle or metadata.
// It is not a committed result. RequireRecorded is Apply-only; the separate
// RequireOTPApplyRecorded method accepts only the kernel-correlated final OTP
// check in this same still-live transaction. No general Work access is exposed.
type PhoneRecoveryTOTPCompletion struct {
	custody func() phoneRecoveryTOTPCompletion
}
type phoneRecoveryTOTPCompletion struct {
	work        kernel.Work
	owner       kernel.FeatureExecutionContributor
	binding     identity.CommandBinding
	fingerprint [32]byte
	generation  uint64
	snapshot    TOTPFactorSnapshot
	step        uint64
	until       time.Time
}

// VerifyAndRecordPhoneRecoveryTOTP independently verifies the exact generated
// joint phone-reset command at current database time and atomically advances
// only the internally verified step. The OTP reservation owner must first call
// RequirePhoneRecoveryTOTPReservation before acquiring downstream OTP locks;
// this Apply rechecks those account/aggregate/factor locks. The phone owner gates its protected
// mutation on RequireRecorded in this same Apply and abort on every error.
// The sole parent coordinator commits/rolls back/reconciles unknown outcomes;
// this helper never retries or claims rollback. Prepared plaintext is destroyed
// on every return; no decryption or application callback runs under row locks.
func VerifyAndRecordPhoneRecoveryTOTP(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, prepared PreparedPhoneRecoveryTOTP) (PhoneRecoveryTOTPCompletion, error) {
	s, err := prepared.borrow()
	if err != nil {
		return PhoneRecoveryTOTPCompletion{}, err
	}
	defer s.finish()
	if ctx == nil || s.input || command != s.command {
		return PhoneRecoveryTOTPCompletion{}, invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return PhoneRecoveryTOTPCompletion{}, err
	}
	b, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || generation == 0 || fingerprint == ([32]byte{}) {
		return PhoneRecoveryTOTPCompletion{}, invalidAuthority()
	}
	m, err := s.snapshot.Metadata()
	if err != nil {
		return PhoneRecoveryTOTPCompletion{}, err
	}
	_, input, err := phoneRecoveryCommand(command, m)
	f, _ := command.PhonePasswordResetFeature()
	if err != nil || input || f.Binding != b {
		return PhoneRecoveryTOTPCompletion{}, invalidAuthority()
	}
	sql := completionTOTPStore(w)
	step, accepted, err := verifyPhoneRecoveryTOTPCode(ctx, s, sql, b, fingerprint, generation)
	if err != nil {
		return PhoneRecoveryTOTPCompletion{}, err
	}
	if !accepted {
		return PhoneRecoveryTOTPCompletion{}, identity.ForbiddenError{}
	}
	if err := recordPhoneRecoveryTOTPStep(ctx, sql, s.snapshot, s.until, step); err != nil {
		return PhoneRecoveryTOTPCompletion{}, err
	}
	result := phoneRecoveryTOTPCompletion{work: w, owner: owner, binding: b, fingerprint: fingerprint, generation: generation, snapshot: s.snapshot, step: step, until: s.until}
	return PhoneRecoveryTOTPCompletion{custody: func() phoneRecoveryTOTPCompletion { return result }}, nil
}

// RequireRecorded verifies the actual provisional replay write and original
// live owner/command/generation, current user/factor authority and original
// deadline. It grants no independently reusable reset or session permission.
// Call only inside the same Apply, immediately before the protected mutation.
func (a PhoneRecoveryTOTPCompletion) RequireRecorded(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || a.custody == nil {
		return invalidAuthority()
	}
	s := a.custody()
	if w != s.work || owner != s.owner {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || b != s.binding || fingerprint != s.fingerprint || generation != s.generation {
		return invalidAuthority()
	}
	successor, err := s.recordedSnapshot()
	if err != nil {
		return err
	}
	_, err = lockPhoneRecoveryTOTP(ctx, completionTOTPStore(w), successor, s.until)
	return err
}

// RequireOTPApplyRecorded fences only the successor written by this receipt's
// actual TOTP verification/CAS, during the later native OTP check in the SAME
// protected transaction. The kernel correlates the exact registered owners,
// private Work identity and completed phone Apply before and after all locks.
// The originating Work is retained privately solely for that no-IO guard; this
// method borrows SQL only from the current OTPApplyWork. It rechecks active user,
// original enrollment/aggregate/ciphertext/profile, exact verified replay step
// and current database time/deadline. No code is compared, replay advanced,
// authority renewed, scalar verdict accepted or transaction opened. Errors must
// abort; zero/foreign/returned/expired and other-profile receipts deny. This is
// neither independent factor proof nor a committed result.
func (a PhoneRecoveryTOTPCompletion) RequireOTPApplyRecorded(ctx context.Context, w kernel.OTPApplyWork, owner kernel.OTPReservationContributor) error {
	if ctx == nil || a.custody == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := a.custody()
	if err := w.RequireFeatureOrigin(ctx, owner, s.owner, s.work); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil || b.Command != s.binding || b.Fingerprint != s.fingerprint || b.Generation != s.generation || b.PreviousGeneration != 0 || b.Plan.Mode != kernel.OTPConsume {
		return invalidAuthority()
	}
	spec, err := w.CommandSpec(owner)
	if err != nil {
		return err
	}
	m, err := s.snapshot.Metadata()
	if err != nil {
		return err
	}
	if err := phoneRecoveryFactorSpec(spec, m); err != nil {
		return err
	}
	successor, err := s.recordedSnapshot()
	if err != nil {
		return err
	}
	if _, err := lockPhoneRecoveryTOTP(ctx, phoneRecoveryReadSQL(w.Query), successor, s.until); err != nil {
		return err
	}
	return w.RequireFeatureOrigin(ctx, owner, s.owner, s.work)
}

func (s phoneRecoveryTOTPCompletion) recordedSnapshot() (TOTPFactorSnapshot, error) {
	if s.snapshot.custody == nil {
		return TOTPFactorSnapshot{}, invalidAuthority()
	}
	f := s.snapshot.custody()
	if !phoneRecoverySnapshot(f.metadata) || f.metadata.RowVersion == math.MaxUint64 {
		return TOTPFactorSnapshot{}, invalidAuthority()
	}
	// Only VerifyAndRecord constructs this receipt: its private step is actual
	// cryptographic output and its row successor is the exact successful CAS.
	f.metadata.RowVersion++
	f.metadata.Replay = mfa.TOTPReplayState{Used: true, LastStep: s.step}
	return TOTPFactorSnapshot{custody: func() totpFactorCustody { return f }}, nil
}

func phoneRecoveryAttemptSQL(w kernel.OTPAttemptWork) totpAttemptSQL {
	return totpAttemptSQL{exec: w.Exec, query: func(ctx context.Context, q string, args []any, dest ...any) error {
		rows, err := w.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		if rows.Next() {
			return invalidAuthority()
		}
		return rows.Err()
	}}
}

func lockPhoneRecoveryTOTP(ctx context.Context, sql totpAttemptSQL, snapshot TOTPFactorSnapshot, until time.Time) (time.Time, error) {
	if ctx == nil || snapshot.custody == nil {
		return time.Time{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	f := snapshot.custody()
	m := f.metadata
	if !phoneRecoverySnapshot(m) || until.IsZero() {
		return time.Time{}, invalidAuthority()
	}
	var status string
	args := []any{string(m.TenantID), string(m.UserID)}
	if err := sql.query(ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, args, &status); err != nil {
		return time.Time{}, attemptStoreError(ctx, err)
	}
	if status != "active" {
		return time.Time{}, identity.ForbiddenError{}
	}
	var authority string
	var active int32
	if err := sql.query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, args, &authority, &active); err != nil {
		return time.Time{}, attemptStoreError(ctx, err)
	}
	if authority != strconv.FormatUint(m.FactorAuthorityVersion, 10) || active < 1 || active > 64 {
		return time.Time{}, identity.ForbiddenError{}
	}
	var wire []byte
	var enrollment, row, algorithm, issuer string
	var last *string
	var digits, period, skew int16
	err := sql.query(ctx, `SELECT CASE WHEN octet_length(encrypted_secret) BETWEEN 1 AND 4096 THEN encrypted_secret END,enrollment_version::text,row_version::text,last_step::text,algorithm,digits,period_seconds,skew_steps,issuer FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL FOR UPDATE`, []any{string(m.TenantID), string(m.UserID), m.FactorID}, &wire, &enrollment, &row, &last, &algorithm, &digits, &period, &skew, &issuer)
	defer clear(wire)
	if err != nil {
		return time.Time{}, attemptStoreError(ctx, err)
	}
	if enrollment != strconv.FormatUint(m.EnrollmentVersion, 10) || row != strconv.FormatUint(m.RowVersion, 10) || !bytes.Equal(wire, f.wire) || algorithm != m.Profile.Algorithm || issuer != m.Profile.Issuer || int64(digits) != int64(m.Profile.Digits) || time.Duration(period)*time.Second != m.Profile.Period || int64(skew) != int64(m.Profile.AllowedSkewSteps) || (last != nil) != m.Replay.Used || last != nil && *last != strconv.FormatUint(m.Replay.LastStep, 10) {
		return time.Time{}, identity.ForbiddenError{}
	}
	var now time.Time
	if err := sql.query(ctx, `SELECT clock_timestamp()`, nil, &now); err != nil {
		return time.Time{}, attemptStoreError(ctx, err)
	}
	if now.IsZero() || now.Unix() < 0 || !now.Before(until) {
		return time.Time{}, identity.ForbiddenError{}
	}
	return now.UTC(), nil
}

func phoneRecoveryComparisonScope(b identity.CommandBinding, fingerprint [32]byte, generation uint64, keyVersion uint32, m TOTPFactorMetadata) ([]byte, error) {
	return json.Marshal(struct {
		Domain, Tenant, User, Factor, Command string
		Enrollment, Authority, Generation     uint64
		Fingerprint                           [32]byte
		KeyVersion                            uint32
	}{"phone-password-recovery-totp-v1", string(b.TenantID), string(b.UserID), m.FactorID, string(b.CommandID), m.EnrollmentVersion, m.FactorAuthorityVersion, generation, fingerprint, keyVersion})
}

func verifyPhoneRecoveryTOTPCode(ctx context.Context, s *phoneRecoveryTOTPUse, sql totpAttemptSQL, b identity.CommandBinding, fingerprint [32]byte, generation uint64) (uint64, bool, error) {
	m, err := s.snapshot.Metadata()
	if err != nil || fingerprint == ([32]byte{}) || generation == 0 {
		return 0, false, invalidAuthority()
	}
	code, _, err := phoneRecoveryCommand(s.command, m)
	if err != nil {
		return 0, false, err
	}
	f, _ := s.command.PhonePasswordResetInputFeature()
	if !s.input {
		f, _ = s.command.PhonePasswordResetFeature()
	}
	if f.Binding != b {
		return 0, false, invalidAuthority()
	}
	now, err := lockPhoneRecoveryTOTP(ctx, sql, s.snapshot, s.until)
	if err != nil {
		return 0, false, err
	}
	scope, err := phoneRecoveryComparisonScope(b, fingerprint, generation, s.keyVersion, m)
	if err != nil {
		return 0, false, err
	}
	defer clear(scope)
	step, err := s.verifier.Verify(ctx, s.secret, code, m.Profile, scope, now, m.Replay)
	var wrong identity.ForbiddenError
	if errors.As(err, &wrong) {
		return 0, false, nil
	}
	return step, err == nil, err
}

// step is private output of the core verifier, never public caller input. The
// SQL clock/expiry and frozen replay CAS also fence delay after computation.
func recordPhoneRecoveryTOTPStep(ctx context.Context, sql totpAttemptSQL, snapshot TOTPFactorSnapshot, until time.Time, step uint64) error {
	m, err := snapshot.Metadata()
	if err != nil || !phoneRecoverySnapshot(m) || m.RowVersion == math.MaxUint64 {
		return invalidAuthority()
	}
	var previous any
	if m.Replay.Used {
		previous = strconv.FormatUint(m.Replay.LastStep, 10)
	}
	count, err := sql.exec(ctx, `UPDATE identity_mfa.totp_factors SET last_step=$4::numeric,row_version=row_version+1
WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL
AND enrollment_version=$5::numeric AND row_version=$6::numeric AND last_step IS NOT DISTINCT FROM $7::numeric
AND (last_step IS NULL OR last_step<$4::numeric)
AND clock_timestamp()<$8 AND $4::numeric BETWEEN floor(extract(epoch FROM clock_timestamp())/period_seconds)-skew_steps AND floor(extract(epoch FROM clock_timestamp())/period_seconds)+skew_steps`, string(m.TenantID), string(m.UserID), m.FactorID, strconv.FormatUint(step, 10), strconv.FormatUint(m.EnrollmentVersion, 10), strconv.FormatUint(m.RowVersion, 10), previous, until)
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (PhoneRecoveryTOTPAttempt) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.PhoneRecoveryTOTPAttempt(redacted)"))
}
func (PhoneRecoveryTOTPAttempt) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }
func (PhoneRecoveryTOTPAttempt) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
func (PhoneRecoveryTOTPCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.PhoneRecoveryTOTPCompletion(redacted)"))
}
func (PhoneRecoveryTOTPCompletion) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }
func (PhoneRecoveryTOTPCompletion) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
