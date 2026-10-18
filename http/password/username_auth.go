package passwordhttp

import (
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewUsernameSignupHandler selects only POST /v1/username/signup. It requires
// email, username, password and the original username-signup browser flow.
// The native username-enabled signup owner validates the name once and owns
// neutral collisions, verification delivery and original keyed recovery.
// Construction enables no password route and performs no native IO.
func NewUsernameSignupHandler(c SignupConfig) (http.Handler, error) {
	return NewUsernameSignupHandlerWithMiddleware(c, nil)
}

// NewUsernameSignupHandlerWithMiddleware preserves the shared bounded password
// custody pipeline while binding its distinct username action, route and input.
// Hooks receive SignupState and must not retain sensitive request-local data.
func NewUsernameSignupHandlerWithMiddleware(c SignupConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSignupHandler(c, m, true)
}

// NewUsernameSigninHandler selects only POST /v1/username/signin with closed
// username/password input and original username-signin browser custody. The
// native owner supplies canonical rate input and enumeration-safe comparison.
// This profile supports known-empty MFA only; MFAContinuation is rejected.
func NewUsernameSigninHandler(c SigninConfig) (http.Handler, error) {
	return NewUsernameSigninHandlerWithMiddleware(c, nil)
}

// NewUsernameSigninHandlerWithMiddleware binds the distinct username operation
// without duplicating credential delivery or weakening shared cookie custody.
// Hooks receive SigninState; borrowed owners must outlive concurrent requests.
func NewUsernameSigninHandlerWithMiddleware(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.MFAContinuation {
		return nil, identityhttp.ErrInvalidInput
	}
	return newSigninHandler(c, m, true)
}
