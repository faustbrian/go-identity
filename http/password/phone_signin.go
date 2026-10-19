package passwordhttp

import (
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewPhoneSigninHandler selects only POST /v1/phone/password-signin. Closed JSON
// requires flowID, phoneNumber, password and callbackURL, with optional remember.
// The native phone-enabled owner must enforce the original target-bound flow,
// verified canonical phone, current credential/account and known-empty factors.
// This adapter never enables enrollment, OTP or MFA continuation. Other cookie,
// rate, timeout, response-custody and recovery semantics match NewSigninHandler.
func NewPhoneSigninHandler(c SigninConfig) (http.Handler, error) {
	return NewPhoneSigninHandlerWithMiddleware(c, nil)
}

// NewPhoneSigninHandlerWithMiddleware freezes typed execution phases. Borrowed
// owners must remain concurrency-safe and outlive requests; construction is IO
// free. Hooks observe opaque SigninState, not credentials or current authority.
func NewPhoneSigninHandlerWithMiddleware(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSigninHandler(c, m, phoneSigninProfile)
}

// NewPhoneSigninFeature explicitly contributes only phone/password signin and
// its canonical wire contract under identity/phone. Compositions also selecting
// phone enrollment must combine operation descriptors under one phone feature;
// constructing this feature enables no other route or provider dependency.
func NewPhoneSigninFeature(c SigninConfig) (identityhttp.Feature, error) {
	return NewPhoneSigninFeatureWithMiddleware(c, nil)
}

// NewPhoneSigninFeatureWithMiddleware binds trusted middleware to the selected
// native phases. MFAContinuation must be false; unsupported factor authority
// must deny natively rather than downgrade to single-factor authentication.
func NewPhoneSigninFeatureWithMiddleware(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	op, err := signinOperationProfile(c, m, phoneSigninProfile)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: []identityhttp.OperationDescriptor{op}})
}
