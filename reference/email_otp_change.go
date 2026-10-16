package reference

import (
	"context"
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/session"
)

// EmailOTPChangeService borrows the selected native genuine-primary workflow.
// It owns no pool, journal or goroutines. Calls preserve original custody and
// obey graph, caller and native bounds. Zero and retained closed handles deny.
type EmailOTPChangeService struct{ state *storeState }

var _ otp.EmailChangeService = (*EmailOTPChangeService)(nil)
var _ otp.EmailChangeRateSource = (*EmailOTPChangeService)(nil)

// EmailOTPChange exposes only explicit native selection; HTTP is independent.
func (f FeatureSet) EmailOTPChange() (*EmailOTPChangeService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_email_otp_change"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.email == nil || s.features.email.otpChange == nil {
		return nil, identity.UnavailableError{}
	}
	return &EmailOTPChangeService{state: s}, nil
}

func (s *EmailOTPChangeService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *otppg.EmailChangeService, func(), error) {
	if s == nil || s.state == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_email_otp_change"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.state.features.email == nil || s.state.features.email.otpChange == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, s.state.features.email.otpChange, done, nil
}

// EmailChangeSession authenticates original token possession without renewing
// its validity or granting current mutation/disclosure authority.
func (s *EmailOTPChangeService) EmailChangeSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	w, owner, done, err := s.enter(ctx, tenant)
	if err != nil {
		return session.Session{}, err
	}
	defer done()
	return owner.EmailChangeSession(w, tenant, flow)
}

// EmailChangeSendDestination preserves authentic original transport budget
// correlation without issuance, mutable recipient substitution or renewal.
func (s *EmailOTPChangeService) EmailChangeSendDestination(ctx context.Context, r otp.EmailChangeRequest) (otp.DestinationInput, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.DestinationInput{}, err
	}
	defer done()
	return owner.EmailChangeSendDestination(w, r)
}

// EmailChangeChallenge preserves original purpose/target/session scope for
// transport budgets; it compares no code and grants no replacement permission.
func (s *EmailOTPChangeService) EmailChangeChallenge(ctx context.Context, r otp.EmailChangeConfirmRequest) (otp.EmailChangeChallenge, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.EmailChangeChallenge{}, err
	}
	defer done()
	return owner.EmailChangeChallenge(w, r)
}

// EmailChangeRequest preserves independent native issuance and original intent.
func (s *EmailOTPChangeService) EmailChangeRequest(ctx context.Context, r otp.EmailChangeRequest) (otp.SendResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.SendResult{}, err
	}
	defer done()
	return owner.EmailChangeRequest(w, r)
}

// EmailChangeConfirm preserves the sole atomic primary/notice/OTP transition.
func (s *EmailOTPChangeService) EmailChangeConfirm(ctx context.Context, r otp.EmailChangeConfirmRequest) (otp.EmailChangeResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.EmailChangeResult{}, err
	}
	defer done()
	return owner.EmailChangeConfirm(w, r)
}

// RecoverEmailChange observes original metadata without comparison or mutation.
func (s *EmailOTPChangeService) RecoverEmailChange(ctx context.Context, r otp.EmailChangeRecoveryRequest) (otp.EmailChangeResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return otp.EmailChangeResult{}, err
	}
	defer done()
	return owner.RecoverEmailChange(w, r)
}

// Format redacts graph internals.
func (*EmailOTPChangeService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.EmailOTPChangeService(redacted)"))
}

// LogValue redacts graph internals.
func (*EmailOTPChangeService) LogValue() slog.Value {
	return slog.StringValue("reference.EmailOTPChangeService(redacted)")
}

// MarshalJSON rejects graph export.
func (*EmailOTPChangeService) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects graph export.
func (*EmailOTPChangeService) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
