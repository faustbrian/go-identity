package magiclinkpostgres

import (
	"context"

	"github.com/faustbrian/go-identity/email"
)

// RequestRateSource returns the frozen request parser's canonical destination
// without account, factor, issuer, delivery or database access. It grants no
// eligibility or authentication authority. Call after trusted-IP admission,
// debit the shared destination budget, then pass the same raw input to Request;
// Request independently repeats normalization and current recipient selection.
// The returned address is sensitive: never log it or include it in a response.
// Calls are concurrent-safe, bounded by the parser's input limits and perform
// no IO or callbacks. Cancellation and invalid configuration return no source.
func (s *RequestService) RequestRateSource(ctx context.Context, input email.AddressInput) (canonical string, err error) {
	if ctx == nil || s == nil || s.config == nil {
		return "", invalid()
	}
	defer func() {
		if recover() != nil {
			err = invalid()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			canonical = ""
		}
	}()
	if err = ctx.Err(); err != nil {
		return "", err
	}
	address, err := s.config().Address.Parse(input)
	if err != nil {
		return "", invalid()
	}
	return address.Canonical().Record().Value, nil
}
