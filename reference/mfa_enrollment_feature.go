package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func (f FeatureSet) mfaEnrollmentSelected() error {
	s := f.state
	if s == nil {
		return identity.InvalidInputError{Field: "reference_mfa_enrollment"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.mfaEnrollment == nil || s.features.mfaEnrollment.enable == nil || s.features.mfaEnrollment.uri == nil || s.features.mfaEnrollment.confirm == nil {
		return identity.UnavailableError{}
	}
	return nil
}

// MFAEnrollment returns the selected native pending TOTP enrollment workflow.
// It exposes no route and grants no confirmed factor authority. Calls require
// initialized graph custody and an allowed tenant; retained handles deny after
// Close. Recovery cannot redeliver recovery codes or renew primary evidence.
func (f FeatureSet) MFAEnrollment() (mfa.EnrollmentService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	return composedMFAEnrollment{state: f.state}, nil
}

// MFAProvisioningURI returns separate original-session/CSRF disclosure. It
// returns material only from the first known committed reveal, never retries
// or recovery. Graph startup, tenant, lifetime and shutdown guards are retained.
func (f FeatureSet) MFAProvisioningURI() (mfa.TOTPURIService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	return composedMFAEnrollment{state: f.state}, nil
}

// MFAEnrollmentConfirmation returns the explicit enrollment variant of TOTP
// verification. Login-child requests deny; confirmation never silently upgrades
// the original session. Selecting it does not select HTTP or login completion.
func (f FeatureSet) MFAEnrollmentConfirmation() (mfa.TOTPCompletionService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	return composedMFAEnrollment{state: f.state}, nil
}

type composedMFAEnrollment struct{ state *storeState }

// TotpUriRateSource retains native original lifetime/deadline metadata while
// applying the graph's startup, tenant and shutdown ownership. It is neither
// disclosure permission nor a projection/cache with renewable freshness.
func (f composedMFAEnrollment) TotpUriRateSource(ctx context.Context, r mfa.TotpUriRequest) (time.Duration, time.Time, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.uri.TotpUriRateSource(w, r)
}

// EnrollmentConfirmationRateSource exposes native original-custody quota and
// earliest deadline under the same graph/tenant lifetime as protected activation.
// It performs no factor verification or mutation and grants no current authority.
func (f composedMFAEnrollment) EnrollmentConfirmationRateSource(ctx context.Context, r mfa.TotpVerifyRequest) (time.Duration, time.Time, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.confirm.EnrollmentConfirmationRateSource(w, r)
}

func (f composedMFAEnrollment) Enable(ctx context.Context, r mfa.EnableRequest) (mfa.EnableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.EnableResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.enable.Enable(w, r)
}
func (f composedMFAEnrollment) RecoverEnable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.EnableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.EnableResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.enable.RecoverEnable(w, q, caller)
}
func (f composedMFAEnrollment) TotpUri(ctx context.Context, r mfa.TotpUriRequest) (mfa.TotpUriResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.TotpUriResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.uri.TotpUri(w, r)
}
func (f composedMFAEnrollment) RecoverTotpUri(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.TotpUriResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.TotpUriResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.uri.RecoverTotpUri(w, q, caller)
}
func (f composedMFAEnrollment) TotpVerify(ctx context.Context, r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.confirm.TotpVerify(w, r)
}
func (f composedMFAEnrollment) RecoverTotpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.confirm.RecoverTotpVerify(w, q, caller)
}

var _ mfa.EnrollmentService = composedMFAEnrollment{}
var _ mfa.TOTPURIService = composedMFAEnrollment{}
var _ mfa.TOTPCompletionService = composedMFAEnrollment{}
