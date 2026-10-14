package passwordpostgres

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
)

// SigninRateSource authenticates the original pre-auth transaction and returns
// the identifier normalization used by Signin, including its unchanged invalid
// email fallback. It reads no account or credential and performs no password
// comparison, risk admission, flow consumption or session issuance. The result
// is rate-budget input, not authentication or permission to execute Signin.
// Callers must debit the trusted IP budget first and pass the same immutable
// request to subsequent identifier admission and Signin. The caller owns the
// borrowed password and its destruction. Cancellation, invalid flow custody and
// errors return an empty result; work is bounded by Repository.MaximumDuration.
func (s *SigninService) SigninRateSource(ctx context.Context, r password.SigninRequest) (canonical string, err error) {
	if s == nil || s.repository == nil || ctx == nil || r.Validate() != nil {
		return "", password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
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
	if !slices.Contains(s.c.Origins, r.Origin) || !slices.Contains(s.c.CallbackURLs, r.CallbackURL) {
		return "", identity.ForbiddenError{}
	}
	if _, _, err = s.flow(ctx, r); err != nil {
		return "", err
	}
	address, parseErr := s.address.Parse(email.AddressInput(r.Identifier))
	if parseErr != nil {
		return string(r.Identifier), nil
	}
	return address.Canonical().Record().Value, nil
}
