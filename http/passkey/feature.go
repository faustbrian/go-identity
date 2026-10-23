package passkeyhttp

import (
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewFeature contributes only explicitly selected operation groups and their
// concrete wire contracts. Nil groups expose no route or metadata. Construction
// performs no native IO and returns no partial selection on error. Dependencies
// remain borrowed and must outlive concurrent requests. Base HTTP imports no
// concrete passkey integration; pass this feature to its selected router.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware binds trusted hooks to the same real owner phases.
// Hooks cannot replace original browser input, extend owner validity or acquire
// credential response custody. This non-streaming JSON profile buffers bounded
// responses until all synchronous hooks return; no goroutine owns delivery.
func NewFeatureWithMiddleware(c FeatureConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	var ops []identityhttp.OperationDescriptor
	add := func(name string, h http.Handler, err error) error {
		if err != nil {
			return err
		}
		csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}
		switch name {
		case "register-options", "register-verify", "update":
			csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
		case "list":
			csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "passkey", OperationID: "identity.passkey." + name, Handler: h, CSRF: csrf, MaximumSerializedBytes: 300000})
		if err != nil {
			return err
		}
		op.Wire = passkeyWire(c, name)
		ops = append(ops, op)
		return nil
	}
	if c.Registration != nil {
		h, err := NewRegistrationOptionsHandlerWithMiddleware(*c.Registration, middleware)
		if err := add("register-options", h, err); err != nil {
			return identityhttp.Feature{}, err
		}
		h, err = NewRegistrationVerifyHandlerWithMiddleware(*c.Registration, middleware)
		if err := add("register-verify", h, err); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	if c.Signin != nil {
		h, err := NewSigninOptionsHandlerWithMiddleware(*c.Signin, middleware)
		if err := add("signin-options", h, err); err != nil {
			return identityhttp.Feature{}, err
		}
		h, err = NewSigninVerifyHandlerWithMiddleware(*c.Signin, middleware)
		if err := add("signin-verify", h, err); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	if c.Inventory != nil {
		h, err := NewListHandlerWithMiddleware(*c.Inventory, middleware)
		if err := add("list", h, err); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	if c.Update != nil {
		h, err := NewUpdateHandlerWithMiddleware(*c.Update, middleware)
		if err := add("update", h, err); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "passkey", Operations: ops})
}
