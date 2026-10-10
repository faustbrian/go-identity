package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
)

// SignupRateSource returns the frozen creation parser's canonical identifier
// for initial signup rate admission. It performs no IO, account lookup,
// password work, flow validation, risk admission or mutation. The result is
// sensitive rate-budget input, not account existence, authentication or
// permission to register; callers must not log or disclose it. Debit trusted
// IP admission first and pass the same address to identifier admission and
// Signup. Signup remains the owner of original flow and keyed retry custody.
// In particular, normalization does not require a live flow and cannot break
// historical keyed retries after flow consumption or deletion. Calls are
// concurrent-safe, bounded by Repository.MaximumDuration, and return no
// identifier on invalid input, cancellation or failure.
func (s *SignupService) SignupRateSource(ctx context.Context, input password.SignupAddressInput) (canonical string, err error) {
	if s == nil || s.config == nil || ctx == nil {
		return "", password.ErrPasswordWork
	}
	callerContext := ctx
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if callerContext.Err() != nil {
			err = callerContext.Err()
		}
		if err != nil {
			canonical = ""
		}
	}()
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = input.Validate(); err != nil {
		return "", err
	}
	c := s.config()
	if c.Repository.MaximumDuration <= 0 || c.Repository.MaximumDuration > 10*time.Second {
		return "", password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	address, parseErr := c.Address.Parse(email.AddressInput(input))
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if parseErr != nil {
		return "", password.ErrInvalidSignupAddress
	}
	return address.Canonical().Record().Value, nil
}
