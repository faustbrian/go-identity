package mfapostgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// LockedOTPCompletion borrows exact native factor/continuation fences only
// after the coordinator has checked consuming OTP and provisionally consumed
// this child in the same Work. It is not transferable proof or session authority.
// Copies share one provisional transition; returned/foreign handles deny.
type LockedOTPCompletion struct{ custody func() *lockedOTPCompletion }
type lockedOTPCompletion struct {
	work         kernel.Work
	owner        kernel.MFACompletionContributor
	command      identity.Command
	binding      kernel.CapabilityReservationBinding
	plan         kernel.MFACompletionPlan
	otp          kernel.OTPReservationBinding
	metadata     OTPFactorMetadata
	continuation mfa.PartialAuthContinuation
	now          time.Time
	recorded     bool
}

// Format redacts borrowed authority and original factor/child correlation.
func (LockedOTPCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.LockedOTPCompletion(redacted)"))
}

// MarshalJSON denies implicit transactional custody export.
func (LockedOTPCompletion) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText denies implicit textual custody export.
func (LockedOTPCompletion) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

func (c LockedOTPCompletion) live(ctx context.Context, recorded bool) (*lockedOTPCompletion, error) {
	if ctx == nil || c.custody == nil {
		return nil, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := c.custody()
	if p == nil || p.recorded != recorded {
		return nil, invalidAuthority()
	}
	if err := p.work.RequireFeatureCommand(ctx, p.owner, p.command); err != nil {
		return nil, err
	}
	b, plan, err := p.work.MFACompletionConsumption(p.owner)
	if err != nil || b != p.binding || plan != p.plan {
		return nil, invalidAuthority()
	}
	otp, err := p.work.OTPConsumption(p.owner)
	if err != nil || otp != p.otp {
		return nil, invalidAuthority()
	}
	return p, nil
}

// LockOTPCompletion requires both actual consuming owners and locks the exact
// current shared continuation/factor/recipient. The MFA owner must separately
// admit original password/browser, directory, credential, policy and risk.
// No code is compared, budget spent, child finalized or session issued here.
func LockOTPCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, snapshot OTPFactorSnapshot) (LockedOTPCompletion, error) {
	if ctx == nil {
		return LockedOTPCompletion{}, invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return LockedOTPCompletion{}, err
	}
	b, plan, err := w.MFACompletionConsumption(owner)
	if err != nil || b.Command.OperationID != "identity.mfa.otp-verify" {
		return LockedOTPCompletion{}, invalidAuthority()
	}
	otp, err := w.OTPConsumption(owner)
	if err != nil || otp.Command != b.Command || otp.Fingerprint != b.Fingerprint || otp.Generation != b.Generation || otp.Plan.Mode != kernel.OTPConsume {
		return LockedOTPCompletion{}, invalidAuthority()
	}
	m, err := snapshot.Metadata()
	if err != nil || m.TenantID != b.Command.TenantID || m.UserID != plan.UserID || identity.CommandID(m.ContinuationID) != plan.ID || m.ScopeDigest != plan.ScopeDigest || m.ContinuationVersion != plan.ContinuationVersion || m.FactorAuthorityVersion != plan.FactorVersion {
		return LockedOTPCompletion{}, identity.ForbiddenError{}
	}
	store := completionTOTPStore(w)
	shared := kernel.MFATOTPAttemptBinding{Command: b.Command, Plan: plan, Fingerprint: b.Fingerprint, Generation: b.Generation}
	c, now, err := lockMFAAttemptContinuation(ctx, store, shared, "otp")
	if err != nil {
		return LockedOTPCompletion{}, err
	}
	var found bool
	err = store.query(ctx, `SELECT true FROM identity_mfa.continuations c
JOIN identity_mfa.otp_factors f ON f.tenant_id=c.tenant_id AND f.user_id=c.user_id AND f.factor_id=c.otp_send_factor_id
JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.continuation_id=$3 AND c.otp_send_command_id=$4 AND f.factor_id=$5
AND f.state=2 AND f.confirmed_at IS NOT NULL AND f.enrollment_version=$6::numeric AND f.row_version=$7::numeric
AND f.identifier_id=$8 AND f.identifier_version=$9::numeric AND f.verification_version=$10::numeric
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL AND i.version=f.identifier_version AND i.verification_version=f.verification_version
AND ((f.channel='email' AND i.kind='email') OR (f.channel='sms' AND i.kind='phone')) FOR SHARE OF f,i`, []any{string(m.TenantID), string(m.UserID), string(m.ContinuationID), decodeOTPCompletionID(otp.Plan.ChallengeID), m.FactorID, strconv.FormatUint(m.EnrollmentVersion, 10), strconv.FormatUint(m.RowVersion, 10), string(m.IdentifierID), strconv.FormatUint(m.IdentifierVersion, 10), strconv.FormatUint(m.VerificationVersion, 10)}, &found)
	if err != nil || !found {
		if err != nil {
			return LockedOTPCompletion{}, attemptStoreError(ctx, err)
		}
		return LockedOTPCompletion{}, identity.ForbiddenError{}
	}
	p := &lockedOTPCompletion{work: w, owner: owner, command: command, binding: b, plan: plan, otp: otp, metadata: m, continuation: c, now: now}
	return LockedOTPCompletion{custody: func() *lockedOTPCompletion { return p }}, nil
}

func decodeOTPCompletionID(id string) []byte {
	parsed, err := identity.ParseCommandID(id)
	if err != nil {
		return nil
	}
	wire, _ := base64.RawURLEncoding.Strict().DecodeString(string(parsed))
	return wire
}

// VerificationState returns original factor metadata and locked primary time
// only before this same live callback records completion. The code has already
// been checked by OTP's actual consuming owner, not a caller boolean.
func (c LockedOTPCompletion) VerificationState() (OTPFactorMetadata, time.Time, error) {
	p, err := c.live(context.Background(), false)
	if err != nil {
		return OTPFactorMetadata{}, time.Time{}, err
	}
	return p.metadata, p.now, nil
}

// RecordOTPCompletion atomically spends one shared attempt and completes this
// original continuation after actual consuming OTP/child checks. OTP replay
// state stays at its native owner. Errors abort all provisional effects; copies
// cannot record again, and no token or session is created by this helper.
func RecordOTPCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, c LockedOTPCompletion) error {
	p, err := c.live(ctx, false)
	if err != nil {
		return err
	}
	if w != p.work || owner != p.owner || command != p.command {
		return invalidAuthority()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	s, err := p.continuation.Bindings()
	if err != nil {
		return err
	}
	next, err := p.continuation.RecordAttempt("otp", now, s.Version)
	if err != nil {
		return err
	}
	n, err := next.Bindings()
	if err != nil {
		return err
	}
	n.State = mfa.Completed
	if _, err := mfa.NewPartialAuthContinuation(n); err != nil {
		return err
	}
	count, err := w.Exec(ctx, `UPDATE identity_mfa.continuations SET state=3,version=$4::numeric,attempts_remaining=$5
WHERE tenant_id=$1 AND user_id=$2 AND continuation_id=$3 AND scope_digest=$6 AND version=$7::numeric AND state=$8 AND attempts_remaining=$9
AND otp_send_command_id=$10 AND otp_send_factor_id=$11 AND expires_at>clock_timestamp()`, string(s.TenantID), string(s.SubjectID), string(s.ID), strconv.FormatUint(n.Version, 10), int32(n.AttemptsRemaining), p.metadata.ScopeDigest[:], strconv.FormatUint(s.Version, 10), int16(s.State), int32(s.AttemptsRemaining), decodeOTPCompletionID(p.otp.Plan.ChallengeID), p.metadata.FactorID)
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	p.recorded = true
	return ctx.Err()
}

// RequireRecordedOTPCompletion proves this same live Work's provisional shared
// transition before session persistence. Returned original scope/factor/primary
// metadata is not reusable proof. The session owner must independently admit
// original password/browser and current directory/credential/policy, and commit
// its effect atomically with OTP and child finalization. Errors abort the Work.
func RequireRecordedOTPCompletion(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, c LockedOTPCompletion) (mfa.ContinuationSpec, OTPFactorMetadata, identity.CommandID, error) {
	bad := func(err error) (mfa.ContinuationSpec, OTPFactorMetadata, identity.CommandID, error) {
		return mfa.ContinuationSpec{}, OTPFactorMetadata{}, "", err
	}
	p, err := c.live(ctx, true)
	if err != nil {
		return bad(err)
	}
	if w != p.work || owner != p.owner || command != p.command {
		return bad(invalidAuthority())
	}
	s, err := p.continuation.Bindings()
	if err != nil {
		return bad(err)
	}
	var primary []byte
	var now time.Time
	err = completionTOTPStore(w).query(ctx, `SELECT c.origin_command_id,clock_timestamp()
FROM identity_mfa.continuations c
JOIN identity_mfa.otp_factors f ON f.tenant_id=c.tenant_id AND f.user_id=c.user_id AND f.factor_id=c.otp_send_factor_id
JOIN identity_mfa.factor_authorities a ON a.tenant_id=c.tenant_id AND a.user_id=c.user_id
JOIN identity.users u ON u.tenant_id=c.tenant_id AND u.user_id=c.user_id
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.command_id=c.origin_command_id AND j.purpose=c.origin_purpose
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.continuation_id=$3 AND c.state=3 AND c.version=$4::numeric AND c.attempts_remaining=$5 AND c.scope_digest=$6
AND c.otp_send_command_id=$7 AND f.factor_id=$8 AND f.state=2 AND f.confirmed_at IS NOT NULL AND f.enrollment_version=$9::numeric AND f.row_version=$10::numeric
AND a.version=$11::numeric AND a.active_factors BETWEEN 1 AND 64 AND u.status='active'
AND j.state='committed' AND NOT k.retired AND k.fingerprint=c.origin_fingerprint AND j.generation=c.origin_generation
AND c.expires_at>clock_timestamp()`, []any{string(s.TenantID), string(s.SubjectID), string(s.ID), strconv.FormatUint(s.Version+1, 10), int32(s.AttemptsRemaining - 1), p.metadata.ScopeDigest[:], decodeOTPCompletionID(p.otp.Plan.ChallengeID), p.metadata.FactorID, strconv.FormatUint(p.metadata.EnrollmentVersion, 10), strconv.FormatUint(p.metadata.RowVersion, 10), strconv.FormatUint(p.metadata.FactorAuthorityVersion, 10)}, &primary, &now)
	if err != nil {
		return bad(attemptStoreError(ctx, err))
	}
	if len(primary) != 16 || p.continuation.RequirePending(now) != nil {
		return bad(identity.ForbiddenError{})
	}
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(primary))
	if err != nil {
		return bad(identity.ForbiddenError{})
	}
	return s, p.metadata, id, ctx.Err()
}
