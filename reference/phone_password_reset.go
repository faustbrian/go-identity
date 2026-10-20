package reference

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
)

// PhonePasswordResetService is a borrowed selected-native workflow handle.
// Calls retain graph initialization, tenant, deadline and shutdown admission;
// zero or retained-after-Close handles deny. The pool, native services and
// providers remain graph-owned/borrowed under their original contracts.
type PhonePasswordResetService struct{ read func() *storeState }

var _ phone.PasswordResetService = (*PhonePasswordResetService)(nil)

// PhonePasswordReset obtains the explicitly selected native recovery profile
// without IO. No email reset, phone enrollment/signin or HTTP is selected.
func (f FeatureSet) PhonePasswordReset() (*PhonePasswordResetService, error) {
	if _, err := f.selectedPhonePasswordReset(); err != nil {
		return nil, err
	}
	return &PhonePasswordResetService{read: func() *storeState { return f.state }}, nil
}

func (f FeatureSet) selectedPhonePasswordReset() (*phonePasswordResetState, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_phone_password_reset"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.phonePasswordReset == nil {
		return nil, identity.UnavailableError{}
	}
	return s.features.phonePasswordReset, nil
}

// PhonePasswordResetPreAuth obtains the original no-session recovery issuer
// with lookup-free canonical target binding. It preserves the same graph/key
// custody as reset and refuses an unbound Prepare; no Remember choice exists.
func (f FeatureSet) PhonePasswordResetPreAuth() (IdentifierBoundPreAuthService, error) {
	s, err := f.selectedPhonePasswordReset()
	if err != nil {
		return nil, err
	}
	return composedPhonePreAuth{composedPreAuth: composedPreAuth{state: f.state, issuer: s.preauth}, bind: s.bind}, nil
}

func (s *PhonePasswordResetService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *phonePasswordResetState, func(), error) {
	if s == nil || s.read == nil || s.read() == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_phone_password_reset"}
	}
	state := s.read()
	w, done, err := (composedPasswordReset{state: state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if state.features.phonePasswordReset == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, state.features.phonePasswordReset, done, nil
}

// PasswordResetRequest queues original SMS/link intents, never a session.
func (s *PhonePasswordResetService) PasswordResetRequest(ctx context.Context, r phone.PasswordResetRequestRequest) (phone.PasswordResetRequestResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.PasswordResetRequestResult{}, err
	}
	w, n, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.PasswordResetRequestResult{}, err
	}
	defer done()
	return n.owner.PasswordResetRequest(w, r)
}

// PasswordResetComplete delegates the actual joint capability/SMS/TOTP/risk
// transaction, required password screening and all-session invalidation.
func (s *PhonePasswordResetService) PasswordResetComplete(ctx context.Context, r phone.PasswordResetCompleteRequest) (phone.PasswordResetCompleteResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.PasswordResetCompleteResult{}, err
	}
	w, n, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.PasswordResetCompleteResult{}, err
	}
	defer done()
	return n.owner.PasswordResetComplete(w, r)
}

// RecoverPasswordResetRequest reads only actual scoped original history.
func (s *PhonePasswordResetService) RecoverPasswordResetRequest(ctx context.Context, q identity.RecoveryQuery, c authorization.DecisionContext) (phone.PasswordResetRequestResult, error) {
	w, n, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return phone.PasswordResetRequestResult{}, err
	}
	defer done()
	return n.owner.RecoverPasswordResetRequest(w, q, c)
}

// RecoverPasswordResetComplete cannot compare codes, rehash, reissue or renew
// validity; it delegates current-authorized original native outcome resolution.
func (s *PhonePasswordResetService) RecoverPasswordResetComplete(ctx context.Context, q identity.RecoveryQuery, c authorization.DecisionContext) (phone.PasswordResetCompleteResult, error) {
	w, n, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return phone.PasswordResetCompleteResult{}, err
	}
	defer done()
	return n.owner.RecoverPasswordResetComplete(w, q, c)
}

// EvaluatePasswordResetRequestRisk derives current account/phone/factor scope
// from the actual original browser and canonical number, never body identity.
func (s *PhonePasswordResetService) EvaluatePasswordResetRequestRisk(ctx context.Context, r phone.PasswordResetInitiationRiskRequest) (risk.PhoneEvidenceResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return risk.PhoneEvidenceResult{}, err
	}
	w, n, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return risk.PhoneEvidenceResult{}, err
	}
	defer done()
	return n.request.EvaluatePasswordResetRequestRisk(w, r)
}

// EvaluatePasswordResetCompletionRisk resolves distinct original evidence
// before new live admission, preserving terminal retries without provider work.
func (s *PhonePasswordResetService) EvaluatePasswordResetCompletionRisk(ctx context.Context, r phone.PasswordResetCompletionRiskRequest) (risk.PhoneEvidenceResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return risk.PhoneEvidenceResult{}, err
	}
	w, n, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return risk.PhoneEvidenceResult{}, err
	}
	defer done()
	return n.request.EvaluatePasswordResetCompletionRisk(w, r)
}

// PasswordResetCompletionRateSource returns authenticated original rate input,
// not executable admission. It neither renews lifetime nor spends any budget.
func (s *PhonePasswordResetService) PasswordResetCompletionRateSource(ctx context.Context, p capability.Proof, f otp.SendFlow, c authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	w, n, done, err := s.enter(ctx, identity.TenantID(c.Request.Tenant))
	if err != nil {
		return "", "", "", 0, err
	}
	defer done()
	return n.request.PasswordResetCompletionRateSource(w, p, f, c)
}

func (*PhonePasswordResetService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhonePasswordResetService(redacted)"))
}
func (*PhonePasswordResetService) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
func (*PhonePasswordResetService) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
