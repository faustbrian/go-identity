package reference

import (
	"context"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// RecoveryUse uses the original primary/browser owner and the existing native
// preparation/journal/attempt engine. Correct probing grants no factor proof;
// Apply independently compares and burns the original code before issuing.
// Only explicitly selected recovery effects/keys can enter this method.
func (s *magicLinkTOTPService) RecoveryUse(ctx context.Context, r mfa.RecoveryUseRequest) (out mfa.RecoveryUseResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidTOTPCompletion()
	}
	state := s.state()
	if state == nil || state.recoveryEffect == nil {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = mfa.RecoveryUseResult{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			clearRecoveryDelivery(&out)
		}
	}()
	input, err := s.readRecoveryInput(ctx, r, false)
	if err != nil {
		return out, err
	}
	defer input.destroy()
	completed, err := executeNativeMFA(ctx, state, input)
	// This selected profile imposes no additional post-login remediation.
	// Factor-sensitive operations still require their own eligible fresh proof;
	// recovery login cannot substitute for that authority.
	return mfa.RecoveryUseResult{Outcome: completed.Outcome, Session: completed.Session, CSRFToken: completed.CSRFToken}, err
}

// RecoveryVerificationRateSource returns only issuer-authenticated original
// subject/child/lifetime after browser/current-primary admission. It performs
// no code comparison, set lookup, attempt charge or issuance. Retained exact
// outcomes precede mutable continuation state without renewing freshness.
func (s *magicLinkTOTPService) RecoveryVerificationRateSource(ctx context.Context, r mfa.RecoveryUseRequest) (user identity.UserID, child string, lifetime time.Duration, err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, child, lifetime = "", "", 0
		}
	}()
	if s == nil || s.state == nil || s.state() == nil || s.state().recoveryEffect == nil {
		return "", "", 0, identity.ForbiddenError{}
	}
	input, err := s.readRecoveryInput(ctx, r, true)
	if err != nil {
		return "", "", 0, err
	}
	defer input.destroy()
	return input.rateUser, input.rateChallenge, input.rateLifetime, nil
}

// RecoverRecoveryUse is code/proof/browser-free outcome reconciliation. It
// cannot reconstruct a bearer, renew authority or repeat primary verification.
func (s *magicLinkTOTPService) RecoverRecoveryUse(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.RecoveryUseResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != recoveryCompletionOperation().OperationID || q.UserID != "" || q.RecordID != "" || caller.Validate() != nil {
		return out, invalidTOTPCompletion()
	}
	if _, err := identity.ParsePreAuthTransactionID(q.AnonymousFlowID); err != nil {
		return out, invalidTOTPCompletion()
	}
	state := s.state()
	if state == nil || state.recoveryEffect == nil {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = mfa.RecoveryUseResult{}, identity.UnavailableError{}
		}
		clearRecoveryDelivery(&out)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	p := &magicTOTPPhase{state: state, recovery: true}
	if err := p.compose(); err != nil {
		return out, err
	}
	caller = caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	receipt, err := p.coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Feature != nil && receipt.Feature.Operation != recoveryCompletionOperation() {
		return out, identity.UnavailableError{}
	}
	completed := nativeMFAReceipt(q.CommandID, receipt)
	return mfa.RecoveryUseResult{Outcome: completed.Outcome, Session: completed.Session}, err
}

func clearRecoveryDelivery(out *mfa.RecoveryUseResult) {
	out.Session.Token = session.Token{}
	out.Session.Cookie = http.Cookie{}
	out.CSRFToken = session.CSRFToken{}
}

var _ mfa.RecoveryCompletionService = (*magicLinkTOTPService)(nil)
