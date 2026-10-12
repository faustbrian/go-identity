package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MagicLinkTOTP returns the explicitly selected native TOTP completion owner.
// It neither exposes an HTTP route nor enrolls a factor or grants trusted-device
// policy. All calls retain graph startup, tenant, bounded lifetime and shutdown
// admission. Unselected/zero/closed graphs expose no handle; retained handles
// deny after Close. Recovery is original proof/code-free outcome reconciliation.
func (f FeatureSet) MagicLinkTOTP() (mfa.TOTPCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.magicTOTP == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicTOTP{state: s}, nil
}

type composedMagicTOTP struct{ state *storeState }

func (f composedMagicTOTP) TotpVerify(ctx context.Context, request mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, request.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.state.features.magicTOTP.TotpVerify(w, request)
}

func (f composedMagicTOTP) RecoverTotpVerify(ctx context.Context, query identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, query.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.state.features.magicTOTP.RecoverTotpVerify(w, query, caller)
}

// TotpVerificationRateSource returns only authenticated original subject,
// child identity and immutable signed lifetime for transport quotas. It retains
// graph startup/tenant/shutdown admission and performs no native debit, factor
// decryption, comparison, reservation, issuance or validity renewal.
func (f composedMagicTOTP) TotpVerificationRateSource(ctx context.Context, request mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, request.TenantID)
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return f.state.features.magicTOTP.TotpVerificationRateSource(w, request)
}

var _ mfa.TOTPCompletionService = composedMagicTOTP{}
