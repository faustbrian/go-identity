package reference

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// PhoneService borrows the selected native existing-account enrollment owner.
// Every invocation obeys graph startup, tenant, deadline and drain/Close bounds.
// It owns no pool, journal, provider, timer or goroutine. Zero always denies.
// Closure custody prevents nested diagnostics from traversing native secrets.
type PhoneService struct{ read func() *storeState }

var _ phone.VerificationService = (*PhoneService)(nil)

// Phone returns the explicitly selected native owner, not an HTTP route or
// authentication lease. Retained handles deny after their graph is closed.
func (f FeatureSet) Phone() (*PhoneService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_phone"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.phone == nil {
		return nil, identity.UnavailableError{}
	}
	return &PhoneService{read: func() *storeState { return s }}, nil
}

func (s *PhoneService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *passwordpg.PhoneVerificationService, func(), error) {
	if s == nil || s.read == nil || s.read() == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_phone"}
	}
	state := s.read()
	w, done, err := (composedPasswordReset{state: state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if state.features.phone == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, state.features.phone.owner, done, nil
}

// SendVerification delegates atomic pending enrollment and queued encrypted SMS;
// it never verifies a phone or signs the user in.
func (s *PhoneService) SendVerification(ctx context.Context, r phone.EnrollmentRequest) (phone.EnrollmentResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.EnrollmentResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.EnrollmentResult{}, err
	}
	defer done()
	return owner.SendVerification(w, r)
}

// Verify delegates one native counted attempt and atomic pending-phone effect.
func (s *PhoneService) Verify(ctx context.Context, r phone.VerificationRequest) (phone.VerificationResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.VerificationResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.VerificationResult{}, err
	}
	defer done()
	return owner.Verify(w, r)
}

// RecoverVerification observes original code-free durability under current
// native historical disclosure policy. No code is compared or phone disclosed.
func (s *PhoneService) RecoverVerification(ctx context.Context, r phone.VerificationRecoveryRequest) (phone.VerificationResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.VerificationResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.VerificationResult{}, err
	}
	defer done()
	return owner.RecoverVerification(w, r)
}

// PhoneVerificationSession authenticates original session possession for trusted
// transport mapping, not current session authority or renewed freshness.
func (s *PhoneService) PhoneVerificationSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	w, owner, done, err := s.enter(ctx, tenant)
	if err != nil {
		return session.Session{}, err
	}
	defer done()
	return owner.PhoneVerificationSession(w, tenant, flow)
}

// PhoneEnrollmentDestination preserves native read-only original keyed custody
// before shared rate admission; it does not create delivery or mutate identity.
func (s *PhoneService) PhoneEnrollmentDestination(ctx context.Context, r phone.EnrollmentRequest) (phone.Number, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.Number{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.Number{}, err
	}
	defer done()
	return owner.PhoneEnrollmentDestination(w, r)
}

// PhoneVerificationLifetime returns authenticated immutable original issuance
// metadata without code comparison, debit, renewal or verification authority.
func (s *PhoneService) PhoneVerificationLifetime(ctx context.Context, r phone.VerificationRequest) (time.Duration, error) {
	b, err := r.Bindings()
	if err != nil {
		return 0, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return 0, err
	}
	defer done()
	return owner.PhoneVerificationLifetime(w, r)
}

// Format redacts the entire borrowed graph.
func (*PhoneService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneService(redacted)"))
}

// MarshalJSON rejects implicit graph export.
func (*PhoneService) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// MarshalText rejects implicit text/map-key graph export.
func (*PhoneService) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
