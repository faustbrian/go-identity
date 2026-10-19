package passwordpostgres

import (
	"context"
	"crypto/hmac"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	phone "github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// Run before account discovery, risk attribution or password comparison. Cookie
// possession alone cannot retarget the original phone/password transaction.
func (s *SigninService) requirePhoneSigninTarget(ctx context.Context, request password.SigninRequest, flow session.PreAuthTransaction) error {
	if s == nil || s.c.Phone == nil || request.Caller.Request.Action != "identity.phone.password-signin" {
		return identity.ForbiddenError{}
	}
	number, err := s.c.Phone.Canonicalize(ctx, string(request.Identifier))
	if err != nil {
		return identity.ForbiddenError{}
	}
	expected, err := phone.PasswordSigninIdentifierBinding(number, request.TenantID, s.c.IdentifierKey)
	if err != nil {
		return identity.ForbiddenError{}
	}
	original, err := flow.Bindings()
	if err != nil || original.Binding.Intent.IdentifierBinding == ([32]byte{}) || !hmac.Equal(expected[:], original.Binding.Intent.IdentifierBinding[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}
