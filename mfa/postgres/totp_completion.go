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
	"github.com/jackc/pgx/v5"
)

// LockedTOTPCompletion borrows the current factor and continuation fences in
// the exact registered MFA owner's protected Apply. It is not factor proof or
// session authority. Copies share serial-use custody; returned callbacks deny.
type LockedTOTPCompletion struct{ custody func() *lockedTOTPCompletion }
type lockedTOTPCompletion struct {
	work         kernel.Work
	owner        kernel.MFACompletionContributor
	command      identity.Command
	binding      kernel.MFATOTPAttemptBinding
	snapshot     TOTPFactorSnapshot
	continuation mfa.PartialAuthContinuation
	now          time.Time
	recorded     bool
	step         uint64
}

// Format prevents accidental disclosure of borrowed authority and identity.
func (LockedTOTPCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.LockedTOTPCompletion(redacted)"))
}

// MarshalJSON denies export of borrowed transactional custody.
func (LockedTOTPCompletion) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText denies export of borrowed transactional custody.
func (LockedTOTPCompletion) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

func (a LockedTOTPCompletion) live(ctx context.Context) (*lockedTOTPCompletion, error) {
	if ctx == nil || a.custody == nil {
		return nil, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := a.custody()
	if s == nil || s.recorded {
		return nil, invalidAuthority()
	}
	if err := s.work.RequireFeatureCommand(ctx, s.owner, s.command); err != nil {
		return nil, err
	}
	b, p, err := s.work.MFACompletionConsumption(s.owner)
	if err != nil || b.Command != s.binding.Command || b.Fingerprint != s.binding.Fingerprint || b.Generation != s.binding.Generation || p != s.binding.Plan {
		return nil, invalidAuthority()
	}
	return s, nil
}

// VerificationState returns the locked exact factor and primary database time
// only in the live protected Apply. The native MFA owner must verify the
// unchanged command's opaque code here with its already decrypted owned secret.
// No provider IO, decryption or application callback may run under these locks.
func (a LockedTOTPCompletion) VerificationState() (TOTPFactorMetadata, time.Time, error) {
	s, err := a.live(context.Background())
	if err != nil {
		return TOTPFactorMetadata{}, time.Time{}, err
	}
	m, err := s.snapshot.Metadata()
	return m, s.now, err
}

// LockTOTPCompletion fences account, factor authority, original continuation
// and exact encrypted factor in the same lock order as counted denials. Only
// the unchanged TOTP command in the actual protected MFA invocation is accepted,
// after the coordinator provisionally consumes the existing child. No code is
// verified, attempt spent, replay advanced or session issued by this method.
// The owner separately checks current policy and original primary authority.
func LockTOTPCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, snapshot TOTPFactorSnapshot) (LockedTOTPCompletion, error) {
	if ctx == nil {
		return LockedTOTPCompletion{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return LockedTOTPCompletion{}, err
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return LockedTOTPCompletion{}, err
	}
	b, p, err := w.MFACompletionConsumption(owner)
	if err != nil || b.Command.OperationID != "identity.mfa.totp-verify" {
		return LockedTOTPCompletion{}, invalidAuthority()
	}
	if _, ok := command.OneTimeCode(); !ok {
		return LockedTOTPCompletion{}, invalidAuthority()
	}
	binding := kernel.MFATOTPAttemptBinding{Command: b.Command, Plan: p, Fingerprint: b.Fingerprint, Generation: b.Generation}
	c, now, err := lockTOTPAttempt(ctx, completionTOTPStore(w), binding, snapshot)
	if err != nil {
		return LockedTOTPCompletion{}, err
	}
	s := &lockedTOTPCompletion{work: w, owner: owner, command: command, binding: binding, snapshot: snapshot, continuation: c, now: now}
	return LockedTOTPCompletion{custody: func() *lockedTOTPCompletion { return s }}, nil
}

// RecordTOTPCompletion persists the native owner's just-verified counter and
// terminal continuation in the same borrowed transaction. A counter is not
// authentication: the exact owner must first verify the original opaque code
// against VerificationState inside this Apply. The store enforces current
// window, replay, row/continuation versions and shared budget, but does not
// decide factor policy or issue sessions. All errors must abort. Session,
// child finalization, audit and these provisional effects commit or roll back
// together through the sole coordinator; no separate transaction is started.
func RecordTOTPCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, a LockedTOTPCompletion, step uint64) error {
	s, err := a.live(ctx)
	if err != nil {
		return err
	}
	if w != s.work {
		return invalidAuthority()
	}
	b, p, err := w.MFACompletionConsumption(owner)
	if err != nil || b.Command != s.binding.Command || b.Fingerprint != s.binding.Fingerprint || b.Generation != s.binding.Generation || p != s.binding.Plan {
		return invalidAuthority()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := completeTOTP(ctx, completionTOTPStore(w), s.continuation, s.snapshot, now, step); err != nil {
		return err
	}
	s.recorded = true
	s.step = step
	return nil
}

// RequireRecordedTOTPCompletion confirms this same borrowed handle's actual
// provisional replay/continuation write during the exact original native Apply.
// Zero, foreign, unrecorded, returned or finalized custody denies. Original
// scope and pre-completion factor metadata are returned for exhaustive session
// mapping, along with the durable original primary command. These projections
// are not reusable proof. Native policy, primary/browser and session authority
// remain required, and every error must abort the sole transaction. No retry,
// transaction, consumption, lease or authentication is created here.
func RequireRecordedTOTPCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, a LockedTOTPCompletion) (mfa.ContinuationSpec, TOTPFactorMetadata, identity.CommandID, error) {
	deny := func(err error) (mfa.ContinuationSpec, TOTPFactorMetadata, identity.CommandID, error) {
		return mfa.ContinuationSpec{}, TOTPFactorMetadata{}, "", err
	}
	if ctx == nil || a.custody == nil {
		return deny(invalidAuthority())
	}
	if err := ctx.Err(); err != nil {
		return deny(err)
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
		return deny(invalidAuthority())
	}
	m, err := s.snapshot.Metadata()
	if err != nil {
		return deny(invalidAuthority())
	}
	var primary []byte
	var now time.Time
	err = completionTOTPStore(w).query(ctx, `SELECT c.origin_command_id,clock_timestamp()
FROM identity_mfa.continuations c
JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id
JOIN identity_mfa.factor_authorities f ON f.tenant_id=c.tenant_id AND f.user_id=c.user_id
JOIN identity.users u ON u.tenant_id=c.tenant_id AND u.user_id=c.user_id
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.command_id=c.origin_command_id AND j.purpose=c.origin_purpose
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.continuation_id=$3 AND t.factor_id=$4
AND c.state=3 AND c.version=$5::numeric AND c.attempts_remaining=$6 AND c.scope_digest=$7
AND t.state=2 AND t.enrollment_version=$8::numeric AND t.row_version=$9::numeric AND t.last_step=$10::numeric
AND f.version=$11::numeric AND f.active_factors BETWEEN 1 AND 64 AND u.status='active'
AND j.state='committed' AND NOT k.retired AND k.fingerprint=c.origin_fingerprint AND j.generation=c.origin_generation
AND c.expires_at>clock_timestamp()`, []any{string(m.TenantID), string(m.UserID), string(m.ContinuationID), m.FactorID, strconv.FormatUint(original.Version+1, 10), int32(original.AttemptsRemaining - 1), m.ScopeDigest[:], strconv.FormatUint(m.EnrollmentVersion, 10), strconv.FormatUint(m.RowVersion+1, 10), strconv.FormatUint(s.step, 10), strconv.FormatUint(m.FactorAuthorityVersion, 10)}, &primary, &now)
	if err != nil {
		return deny(attemptStoreError(ctx, err))
	}
	if len(primary) != 16 || s.continuation.RequirePending(now) != nil {
		return deny(identity.ForbiddenError{})
	}
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(primary))
	if err != nil {
		return deny(identity.ForbiddenError{})
	}
	return original, m, id, nil
}

func completionTOTPStore(w kernel.Work) totpAttemptSQL {
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

func completeTOTP(ctx context.Context, sql totpAttemptSQL, c mfa.PartialAuthContinuation, snapshot TOTPFactorSnapshot, now time.Time, step uint64) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m, err := snapshot.Metadata()
	if err != nil || m.RowVersion == math.MaxUint64 || now.IsZero() || now.Unix() < 0 {
		return invalidAuthority()
	}
	s, err := c.Bindings()
	if err != nil || c.RequirePending(now) != nil || s.Version == math.MaxUint64 || s.ID != m.ContinuationID || s.TenantID != m.TenantID || s.SubjectID != identity.SubjectID(m.UserID) || s.Version != m.ContinuationVersion || s.FactorVersion != m.FactorAuthorityVersion {
		return identity.ForbiddenError{}
	}
	if err := m.Profile.Validate(); err != nil {
		return err
	}
	current := uint64(now.Unix() / int64(m.Profile.Period/time.Second))
	skew := uint64(m.Profile.AllowedSkewSteps)
	if step > current+skew || current > step && current-step > skew || m.Replay.Used && step <= m.Replay.LastStep {
		return identity.ForbiddenError{}
	}
	// RecordAttempt validates allowed-method membership and the shared version
	// before any write. Successful use on the last attempt completes, not revokes.
	next, err := c.RecordAttempt("totp", now, s.Version)
	if err != nil {
		return err
	}
	n, _ := next.Bindings()
	n.State = mfa.Completed
	if _, err := mfa.NewPartialAuthContinuation(n); err != nil {
		return err
	}
	digest, err := c.ScopeDigest()
	if err != nil || digest != m.ScopeDigest {
		return identity.ForbiddenError{}
	}
	var previous any
	if m.Replay.Used {
		previous = strconv.FormatUint(m.Replay.LastStep, 10)
	}
	count, err := sql.exec(ctx, `UPDATE identity_mfa.totp_factors SET last_step=$4::numeric,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND enrollment_version=$5::numeric AND row_version=$6::numeric AND last_step IS NOT DISTINCT FROM $7::numeric`, string(m.TenantID), string(m.UserID), m.FactorID, strconv.FormatUint(step, 10), strconv.FormatUint(m.EnrollmentVersion, 10), strconv.FormatUint(m.RowVersion, 10), previous)
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
