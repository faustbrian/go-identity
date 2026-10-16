package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

var _ otp.EmailVerificationService = (*EmailVerificationService)(nil)

// RecoverEmailVerify authenticates original Send/session possession and current
// query authority, then reconciles only the exact consuming command through the
// existing primary journal. It never compares a code, meters another attempt,
// changes an address, issues a session or regenerates/redelivers a code. A
// committed identifier successor does not erase its original history. All other
// directory, user, credential and authorization epochs remain current and fenced.
// Successful recovery is metadata-only; Address is always absent.
func (s *EmailVerificationService) RecoverEmailVerify(ctx context.Context, r otp.EmailVerifyRecoveryRequest) (out otp.EmailVerifyResult, err error) {
	if ctx == nil || s == nil || s.sender == nil || s.coordinator == nil {
		return out, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out.Address, err = identity.IdentifierProjection{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	b, _ := r.Recovery.Bindings()
	original, custody, _, err := s.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, b.SendCommandID)
	if err != nil {
		return out, err
	}
	f, _ := original.Feature()
	issued, err := custody.challenge.Bindings()
	if err != nil || custody.recipient == nil {
		return out, ErrInvalidCommand
	}
	scope, err := issued.Continuation.Bindings()
	if err != nil || scope.Scope.Purpose != otp.PurposeEmailVerification || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.ChallengeID != string(b.SendCommandID) {
		return out, identity.ForbiddenError{}
	}
	target, err := otp.ParseEmailVerificationTarget(scope.Scope.TargetID)
	if err != nil {
		return out, err
	}
	selected, _ := target.Bindings()
	if selected.IdentifierID != custody.recipient.Identifier.ID {
		return out, identity.ForbiddenError{}
	}
	current, err := s.authorizeRecovery(ctx, r.Caller, f.Binding, custody.authority)
	if err != nil {
		return out, err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(string(b.Attempt.Fingerprint))
	if err != nil || len(raw) != 32 {
		clear(raw)
		return out, ErrInvalidCommand
	}
	defer clear(raw)
	plan := kernel.OTPAttemptPlan{AttemptID: string(b.Attempt.AttemptID), AttemptFingerprint: [32]byte(raw), FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion, ChallengeID: string(b.SendCommandID), ScopeDigest: b.ScopeDigest, DigestKeyVersion: b.DigestKeyVersion, ExpectedVersion: b.ExpectedVersion, Mode: kernel.OTPConsume}
	q := checkQuery(f.Binding, b.Attempt.CommandID, emailVerificationOperation().OperationID, false)
	q.RecordID = string(selected.IdentifierID)
	caller := s.source.planCaller(r.Caller, q)
	receipt, err := s.coordinator.RecoverOTPFeatureCommand(ctx, q, plan, caller)
	out.CommandID, out.Outcome, out.RetryAfter, out.Recovery, out.Replayed = b.Attempt.CommandID, receipt.Outcome, receipt.RetryAfter, r.Recovery, true
	// Observing an original denied command is not a new authorization denial.
	// Recheck current disclosure authority for both terminal outcomes before
	// returning successful metadata; never suppress a late policy failure.
	if err != nil && receipt.Outcome != identity.CommitOutcomeNotCommitted {
		return out, err
	}
	// The coordinator returns classified original abort errors alongside a
	// validated terminal NotCommitted receipt. Current query/IO failures return
	// zero or Unknown instead. Normalize only exact, validated original history;
	// cancellation and current disclosure failures remain errors below.
	if receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation != emailVerificationOperation() || receipt.Binding.CommandID != b.Attempt.CommandID || receipt.Binding.TenantID != r.TenantID || receipt.Binding.UserID != r.UserID || receipt.Binding.RecordID != string(selected.IdentifierID) {
		return out, ErrUnavailable
	}
	after, err := s.authorizeRecovery(ctx, r.Caller, f.Binding, custody.authority)
	if err != nil {
		return out, err
	}
	if current != after {
		return out, identity.ForbiddenError{}
	}
	return out, nil
}

func (s *EmailVerificationService) authorizeRecovery(ctx context.Context, caller authorization.DecisionContext, binding identity.CommandBinding, original AttemptAuthority) (AttemptAuthority, error) {
	current, err := s.owner.readInitiatingAuthority(ctx, binding)
	if err != nil {
		return AttemptAuthority{}, err
	}
	if current.Directory != original.Directory || current.UserAuthorityVersion != original.UserAuthorityVersion || current.CredentialAuthorityVersion != original.CredentialAuthorityVersion || current.UserAuthorization != original.UserAuthorization {
		return AttemptAuthority{}, identity.ForbiddenError{}
	}
	// Identifier epoch may have advanced due to the original verified transition
	// or a later authorized identifier action. History observation does not turn
	// either epoch into executable original session/OTP authority.
	c := caller.Clone()
	c.PolicyRevision = authorization.Revision(s.queryPolicy.PolicyVersion)
	c.Request.Action = "identity.otp.email-verify.recover"
	c.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}
	decision, err := s.queryPolicy.Authorization.Decide(ctx, c)
	if ctx.Err() != nil {
		return AttemptAuthority{}, ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != c.PolicyRevision {
		return AttemptAuthority{}, identity.ForbiddenError{}
	}
	return current, nil
}

// Format redacts retained domain, keys and deployment configuration.
func (EmailVerificationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.EmailVerificationConfig(redacted)"))
}

// MarshalJSON rejects configuration export.
func (EmailVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects configuration export.
func (EmailVerificationConfig) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// Format redacts retained graph internals.
func (*EmailVerificationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.EmailVerificationService(redacted)"))
}

// LogValue emits only a constant marker.
func (*EmailVerificationService) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.EmailVerificationService(redacted)")
}

// MarshalJSON rejects graph export.
func (*EmailVerificationService) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects graph export.
func (*EmailVerificationService) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
