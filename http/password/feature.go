package passwordhttp

import (
	"fmt"
	"io"
	"log/slog"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// FeatureConfig selects only the non-nil operations as one password-owned
// contribution. At least one is required. Change may select cookie or bearer;
// BearerVerification is bearer-only and never inherits Change's cookie policy.
// Configurations are copied during construction; do not mutate them concurrently.
// Their native owners remain borrowed and must outlive requests.
// BrowserDeviceBearerVerification selects explicit signed correlation instead
// of generic BearerVerification. CookieVerification selects the distinct native
// cookie port. Selecting more than one verification variant denies.
// ResetRequest selects only initiation; it does not implicitly expose completion.
type FeatureConfig struct {
	ResetRequest                    *ResetRequestConfig
	ResetComplete                   *ResetCompleteConfig
	ResetInspect                    *ResetInspectConfig
	Signup                          *SignupConfig
	Signin                          *SigninConfig
	Change                          *ChangeConfig
	BearerVerification              *BearerVerificationConfig
	BrowserDeviceBearerVerification *BrowserDeviceBearerVerificationConfig
	CookieVerification              *CookieVerificationConfig
}

// Format redacts borrowed runtime configuration.
func (FeatureConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.FeatureConfig(redacted)")
}

// MarshalJSON denies implicit runtime configuration export.
func (FeatureConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (FeatureConfig) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (FeatureConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.FeatureConfig(redacted)")
}

// NewFeature contributes exactly the selected real handlers and wire schemas.
// Combining change and verification here avoids duplicate owner contributions;
// consumers must not independently select the standalone factories together.
// Invalid selected dependencies return no partial feature. Construction performs
// no native IO, global registration or route/metadata publication.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware binds the trusted synchronous owner hooks to each
// selected operation. Hooks must handle the operation's distinct typed state;
// they cannot replace input or grant transaction authority. Returned selection
// is frozen; changing configuration pointers later cannot change its profile.
func NewFeatureWithMiddleware(c FeatureConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	verificationProfiles := 0
	if c.BearerVerification != nil {
		verificationProfiles++
	}
	if c.BrowserDeviceBearerVerification != nil {
		verificationProfiles++
	}
	if c.CookieVerification != nil {
		verificationProfiles++
	}
	if (c.ResetComplete == nil && c.ResetRequest == nil && c.ResetInspect == nil && c.Signup == nil && c.Signin == nil && c.Change == nil && verificationProfiles == 0) || verificationProfiles > 1 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var ops []identityhttp.OperationDescriptor
	if c.ResetInspect != nil {
		op, err := resetInspectOperation(*c.ResetInspect, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.ResetComplete != nil {
		op, err := resetCompleteOperation(*c.ResetComplete, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		// Combined reset declares its shared browser-cookie wire component on
		// request exactly once. Standalone completion retains that declaration.
		if c.ResetRequest != nil {
			op.Wire.SecuritySchemes = nil
		}
		ops = append(ops, op)
	}
	if c.ResetRequest != nil {
		op, err := resetRequestOperation(*c.ResetRequest, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.Signup != nil {
		op, err := signupOperation(*c.Signup, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.Signin != nil {
		op, err := signinOperation(*c.Signin, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.Change != nil {
		op, err := changeOperation(*c.Change, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.BearerVerification != nil {
		op, err := verificationOperation(*c.BearerVerification, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.BrowserDeviceBearerVerification != nil {
		op, err := deviceVerificationOperation(*c.BrowserDeviceBearerVerification, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if c.CookieVerification != nil {
		op, err := cookieVerificationOperation(*c.CookieVerification, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/password", Operations: ops})
}

// NewBearerVerificationFeature selects only strict bearer verification. Omission
// exposes neither its route nor metadata. Select NewFeature for verification
// alongside change under the same canonical owner.
func NewBearerVerificationFeature(c BearerVerificationConfig) (identityhttp.Feature, error) {
	return NewBearerVerificationFeatureWithMiddleware(c, nil)
}

// NewBearerVerificationFeatureWithMiddleware preserves the verification owner's
// typed bounded phases and original custody. No cookie profile is selected.
func NewBearerVerificationFeatureWithMiddleware(c BearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{BearerVerification: &c}, middleware)
}

func verificationOperation(c BearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewBearerVerificationHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.verify", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = verificationWire(c, false)
	return op, nil
}

// NewChangeFeature selects only the real keyed password-change operation.
// Omit this contribution to expose neither route nor metadata. Construction
// validates and freezes the selected credential profile without native IO.
// It does not select verification, signin, registration, reset or recovery.
func NewChangeFeature(c ChangeConfig) (identityhttp.Feature, error) {
	return NewChangeFeatureWithMiddleware(c, nil)
}

// NewChangeFeatureWithMiddleware contributes the same typed owner phases and
// actual wire contract. Base HTTP does not import this optional integration.
// Borrowed owners and trusted hooks must outlive concurrent routed requests;
// hooks cannot replace frozen input or grant primary transaction authority.
func NewChangeFeatureWithMiddleware(c ChangeConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{Change: &c}, middleware)
}

func changeOperation(c ChangeConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewChangeHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
	if c.Transport == session.CredentialCookie {
		csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.change", Handler: h, CSRF: csrf, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = changeWire(c)
	return op, nil
}
