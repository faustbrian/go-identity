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

// PhoneChangeService borrows the selected native replacement owner. All calls
// retain graph tenant, initialization, deadline and shutdown guards. It owns no
// resources; zero and handles retained after graph Close deny. Concurrent calls
// share only the native owners' documented synchronization and custody.
type PhoneChangeService struct{ read func() *storeState }

var _ phone.ChangeService = (*PhoneChangeService)(nil)

// PhoneChange obtains an explicitly selected native handle without IO. It
// enables neither HTTP nor enrollment and grants no session or proof authority.
func (f FeatureSet) PhoneChange() (*PhoneChangeService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_phone_change"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.phoneChange == nil {
		return nil, identity.UnavailableError{}
	}
	return &PhoneChangeService{read: func() *storeState { return s }}, nil
}

func (s *PhoneChangeService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *passwordpg.PhoneChangeService, func(), error) {
	if s == nil || s.read == nil || s.read() == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_phone_change"}
	}
	state := s.read()
	w, done, err := (composedPasswordReset{state: state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if state.features.phoneChange == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, state.features.phoneChange.owner, done, nil
}

// SendChange delegates original keyed new-number SMS with no identifier change.
func (s *PhoneChangeService) SendChange(ctx context.Context, r phone.ChangeRequest) (identity.CommandResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return identity.CommandResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.Enrollment.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.SendChange(w, r)
}

// Update delegates the distinct fresh-proof/OTP atomic native replacement.
func (s *PhoneChangeService) Update(ctx context.Context, r phone.UpdateRequest) (phone.UpdateResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.UpdateResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.UpdateResult{}, err
	}
	defer done()
	return owner.Update(w, r)
}

// RecoverUpdate delegates original code-free current-authorized observation.
func (s *PhoneChangeService) RecoverUpdate(ctx context.Context, r phone.UpdateRecoveryRequest) (phone.UpdateResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.UpdateResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return phone.UpdateResult{}, err
	}
	defer done()
	return owner.RecoverUpdate(w, r)
}

// PhoneChangeSession authenticates original possession for transport mapping,
// not current executable session authority or permission for disclosure.
func (s *PhoneChangeService) PhoneChangeSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	w, owner, done, err := s.enter(ctx, tenant)
	if err != nil {
		return session.Session{}, err
	}
	defer done()
	return owner.PhoneChangeSession(w, tenant, flow)
}

// PhoneChangeDestination reads exact authenticated original sending rate input
// without mapping creation, challenge issuance or protected mutation.
func (s *PhoneChangeService) PhoneChangeDestination(ctx context.Context, r phone.ChangeRequest) (phone.Number, error) {
	b, err := r.Bindings()
	if err != nil {
		return phone.Number{}, err
	}
	w, owner, done, err := s.enter(ctx, b.Enrollment.TenantID)
	if err != nil {
		return phone.Number{}, err
	}
	defer done()
	return owner.PhoneChangeDestination(w, r)
}

// PhoneUpdateLifetime reads only the authenticated immutable issued interval;
// it neither compares code nor grants current admission or renewed validity.
func (s *PhoneChangeService) PhoneUpdateLifetime(ctx context.Context, r phone.UpdateRequest) (time.Duration, error) {
	b, err := r.Bindings()
	if err != nil {
		return 0, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return 0, err
	}
	defer done()
	return owner.PhoneUpdateLifetime(w, r)
}

// Format redacts the complete borrowed graph and native custody.
func (*PhoneChangeService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneChangeService(redacted)"))
}

// MarshalJSON rejects implicit graph export.
func (*PhoneChangeService) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// MarshalText rejects implicit graph and map-key export.
func (*PhoneChangeService) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
