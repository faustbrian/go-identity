package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/session"
)

// EmailOTPVerificationService borrows the graph's selected native workflow.
// It owns no pool, journal or goroutines. Calls borrow actual original session
// possession, obey graph/caller bounds and deny after graph Close. Zero denies.
type EmailOTPVerificationService struct{ state *storeState }

var _ otp.EmailVerificationService = (*EmailOTPVerificationService)(nil)

// EmailOTPVerification exposes only explicit native selection, not an HTTP route,
// proof or authorization lease. Missing composition fails closed.
func (f FeatureSet) EmailOTPVerification() (*EmailOTPVerificationService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_email_otp"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.email == nil || s.features.email.otpVerification == nil {
		return nil, identity.UnavailableError{}
	}
	return &EmailOTPVerificationService{state: s}, nil
}

// EmailVerificationSession maps original token possession for transport only;
// it neither validates a current session nor renews its lifetime or authority.
func (s *EmailOTPVerificationService) EmailVerificationSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	w, owner, done, err := s.enter(ctx, tenant)
	if err != nil {
		return session.Session{}, err
	}
	defer done()
	return owner.EmailVerificationSession(w, tenant, flow)
}

// EmailVerificationSendDestination preserves original keyed source for budgets;
// it creates no preparation, challenge or delivery and grants no admission.
func (s *EmailOTPVerificationService) EmailVerificationSendDestination(ctx context.Context, r otp.EmailVerificationSendRequest) (otp.DestinationInput, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.DestinationInput{}, err
	}
	defer done()
	return owner.EmailVerificationSendDestination(w, r)
}

// EmailVerificationChallenge preserves authenticated original verification
// correlation for transport budgets, not code proof or renewed validity.
func (s *EmailOTPVerificationService) EmailVerificationChallenge(ctx context.Context, r otp.EmailVerifyRequest) (otp.EmailVerificationChallenge, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.EmailVerificationChallenge{}, err
	}
	defer done()
	return owner.EmailVerificationChallenge(w, r)
}

func (s *EmailOTPVerificationService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *otppg.EmailVerificationService, func(), error) {
	if s == nil || s.state == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_email_otp"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.state.features.email == nil || s.state.features.email.otpVerification == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, s.state.features.email.otpVerification, done, nil
}

// SendEmailVerification preserves native current authority, risk, one-code
// issuance and original request correlation; it verifies no address itself.
func (s *EmailOTPVerificationService) SendEmailVerification(ctx context.Context, r otp.EmailVerificationSendRequest) (otp.SendResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.SendResult{}, err
	}
	defer done()
	return owner.SendEmailVerification(w, r)
}

// EmailVerify preserves native atomic code use and pending-address verification.
func (s *EmailOTPVerificationService) EmailVerify(ctx context.Context, r otp.EmailVerifyRequest) (otp.EmailVerifyResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.EmailVerifyResult{}, err
	}
	defer done()
	return owner.EmailVerify(w, r)
}

// RecoverEmailVerify observes only original native metadata, never a new code
// comparison, address projection, session, resend or mutation.
func (s *EmailOTPVerificationService) RecoverEmailVerify(ctx context.Context, r otp.EmailVerifyRecoveryRequest) (otp.EmailVerifyResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.EmailVerifyResult{}, err
	}
	defer done()
	return owner.RecoverEmailVerify(w, r)
}
