package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// OTPSignin returns the public consuming service only when explicitly selected.
// It shares Send's original custody and this graph's startup, tenant allowlist
// and bounded lifetime. Retained handles deny after Close. No route, listener,
// migration or implicit startup is enabled by obtaining a handle.
func (f FeatureSet) OTPSignin() (otp.SigninService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_otp_signin"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.signin == nil {
		return nil, identity.UnavailableError{}
	}
	return composedOTPSignin{state: s}, nil
}

type composedOTPSignin struct{ state *storeState }

func (f composedOTPSignin) Signin(ctx context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return otp.SigninResult{}, err
	}
	defer done()
	if f.state.tenants[string(r.TenantID)] == nil {
		return otp.SigninResult{}, identity.UnavailableError{}
	}
	// Preserve native commitment and original recovery even when cancellation
	// races acknowledgment. This wrapper cannot reinterpret durable outcomes.
	return f.state.features.signin.Signin(w, r)
}

func (f composedOTPSignin) RecoverSignin(ctx context.Context, r otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return otp.SigninResult{}, err
	}
	defer done()
	if f.state.tenants[string(r.TenantID)] == nil {
		return otp.SigninResult{}, identity.UnavailableError{}
	}
	return f.state.features.signin.RecoverSignin(w, r)
}

var _ otp.SigninService = composedOTPSignin{}
