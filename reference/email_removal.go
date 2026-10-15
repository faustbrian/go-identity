package reference

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

// EmailRemovalService binds native self-removal to the composed graph lifetime.
// It owns no pool, proof authority, journal or goroutine. Calls borrow request
// custody until return; retained handles deny after graph Close. Zero denies.
type EmailRemovalService struct{ state *storeState }

var _ email.AddressRemovalService = (*EmailRemovalService)(nil)

// EmailRemoval exposes only explicitly selected safe self-removal. No route is
// created and no unsupported factor or recovery owner is silently substituted.
func (f FeatureSet) EmailRemoval() (*EmailRemovalService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_email_removal"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.email == nil || s.features.email.removal == nil {
		return nil, identity.UnavailableError{}
	}
	return &EmailRemovalService{state: s}, nil
}

func (s *EmailRemovalService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *passwordpg.EmailRemovalService, func(), error) {
	if s == nil || s.state == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_email_removal"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	return w, s.state.features.email.removal, done, nil
}

// AddressRemove preserves native original-input correlation, fresh proof,
// actual remaining signin/reset eligibility and atomic revocation/cascade.
func (s *EmailRemovalService) AddressRemove(ctx context.Context, r email.AddressRemoveRequest) (identity.CommandResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.AddressRemove(w, r)
}

// AddressRemoveRateSource authenticates original correlation before transport
// admission without removal or proof consumption. The user must not be logged.
func (s *EmailRemovalService) AddressRemoveRateSource(ctx context.Context, r email.AddressRemoveRequest) (identity.UserID, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return "", err
	}
	defer done()
	return owner.AddressRemoveRateSource(w, r)
}

// AddressRemoveRecover observes the original scoped outcome under current
// query authorization. It cannot repeat removal or refresh original evidence.
func (s *EmailRemovalService) AddressRemoveRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	w, owner, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.AddressRemoveRecover(w, q, caller)
}

// Format redacts native graph and proof custody.
func (EmailRemovalService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EmailRemovalService(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (EmailRemovalService) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit runtime export.
func (EmailRemovalService) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// LogValue exposes no graph, credential or policy metadata.
func (EmailRemovalService) LogValue() slog.Value {
	return slog.StringValue("reference.EmailRemovalService(redacted)")
}
