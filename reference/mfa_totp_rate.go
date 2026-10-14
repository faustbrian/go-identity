package reference

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// TotpVerificationRateSource authenticates original issuance and exact current
// browser/primary/recipient/policy admission before returning subject-bound
// HTTP quota metadata. Exact authorized retained outcomes precede mutable
// continuation/factor state, so retries do not need an active continuation.
// Conflicting intent, unauthorized history, expired proof or outages return
// zero metadata. Expired-proof reconciliation remains RecoverTotpVerify.
// The lifetime is the original signed interval, never remaining/new validity.
// No factor lookup/decryption, code comparison, reservation, debit or issuance
// is performed. This tuple is not permission to complete or create a session.
func (s *magicLinkTOTPService) TotpVerificationRateSource(ctx context.Context, request mfa.TotpVerifyRequest) (user identity.UserID, challenge string, lifetime time.Duration, err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, challenge, lifetime = "", "", 0
		}
	}()
	input, err := s.readInputMode(ctx, request, true)
	if err != nil {
		return "", "", 0, err
	}
	defer input.destroy()
	return input.rateUser, input.rateChallenge, input.rateLifetime, nil
}
