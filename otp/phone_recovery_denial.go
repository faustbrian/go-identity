package otp

import (
	"time"

	"github.com/faustbrian/go-identity/session"
)

// EvaluatePhoneRecoveryDenial proposes one non-consuming compound denial against
// the existing SMS challenge budget, even when the submitted SMS is correct.
// Only the explicit bound, sessionless phone password-reset profile and Consume
// mode are accepted. It performs the same single bounded SMS comparison and
// scope/version/expiry/key checks as EvaluateAttempt, never inventing a wrong
// code or creating a second attempt allowance. Errors return a zero proposal.
//
// The native owner may call this only after its actual locked verification of
// the independent factor denies the ORIGINAL joint submission. This method
// always denies; it accepts no claimed factor result and certifies none. It is
// not a factor verifier, proof, reservation or durable attempt receipt. Current
// authority, exact command replay, atomic charge/audit/denial and ambiguous
// recovery remain the existing native participant/coordinator's responsibility.
// Successful conjunctions must instead reverify both factors in consuming Work.
func (v Verifier) EvaluatePhoneRecoveryDenial(c Challenge, a AttemptCommand, primaryNow time.Time) (AttemptDecision, error) {
	if c.state == nil {
		return AttemptDecision{}, ErrInvalidChallenge
	}
	b, err := c.state.Continuation.Bindings()
	if err != nil {
		return AttemptDecision{}, ErrInvalidChallenge
	}
	original, bound := b.Authorization.PreAuthTransaction()
	record, err := original.Bindings()
	if !bound || err != nil || record.Binding.Intent.Purpose != session.PreAuthPhonePasswordRecovery || b.Scope.Purpose != PurposePasswordReset || b.Scope.Channel != ChannelSMS || a.state == nil || a.state.bindings.Mode != AttemptModeConsume {
		return AttemptDecision{}, ErrInvalidAttempt
	}
	return v.evaluateAttempt(c, a, primaryNow, true)
}
