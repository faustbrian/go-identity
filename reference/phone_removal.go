package reference

import (
	"context"
	"fmt"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PhoneRemovalConfiguration independently selects native self-removal. The graph
// injects actual password verification, email/password signin/reset, risk and
// delivery owners. Native.Risk.Evaluation/Keys and Notice.Delivery/Templates must
// be zero; Primary selects the exact removal action and audience. Cookie CSRF
// keys must match this graph's verification owner. Enrollment is not required.
type PhoneRemovalConfiguration struct {
	Policy  *phone.NumberPolicy
	Primary passwordpg.ActionPrimaryConfig
	Native  passwordpg.PhoneRemovalConfig
}

type phoneRemovalState struct {
	owner    *passwordpg.PhoneRemovalService
	policy   *phone.NumberPolicy
	provider uint64
}

func composePhoneRemoval(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proofs *passwordVerificationState, signin *passwordpg.SigninService, reset *passwordpg.ResetService) (*phoneRemovalState, error) {
	if c.PhoneRemoval == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone_removal"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || proofs == nil || proofs.native == nil || signin == nil || reset == nil || c.OTP == nil || c.Delivery == nil || c.PasswordVerification == nil {
		return nil, invalid
	}
	n := *c.PhoneRemoval
	delivery := n.Native.Notice.Delivery
	if n.Policy == nil || n.Primary.Action != "identity.phone.remove" || n.Native.Risk.Evaluation != (risk.Evaluator{}) || len(n.Native.Risk.Keys) != 0 || delivery.Deployment != "" || delivery.CurrentDigestKeyVersion != 0 || len(delivery.RetainedDigestKeys) != 0 || delivery.ActiveEnvelopeKeyID != "" || delivery.PreparationTimeout != 0 || len(delivery.ProviderProfiles) != 0 || len(n.Native.Notice.Templates) != 0 || n.Native.MaximumDuration > c.OTP.Timeout || n.Native.RequestKeys.Namespace == c.OTP.RequestKeys.Namespace || n.Native.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.Native.RequestKeys.Policy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || n.Native.Counters.Schema != c.Velocity.Schema || n.Native.Counters.CommandCounters == nil || n.Native.Counters.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion {
		return nil, invalid
	}
	if n.Primary.Transport == session.CredentialCookie {
		if len(n.Primary.CSRFKeys) != 0 {
			return nil, invalid
		}
		n.Primary.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
	}
	primary, err := passwordpg.NewActionPrimarySource(proofs.native, n.Primary)
	if err != nil {
		return nil, fmt.Errorf("reference phone removal primary: %w", err)
	}
	n.Native.Risk.Evaluation, n.Native.Risk.Keys = evaluation, slices.Clone(c.OTP.RiskKeys)
	n.Native.Notice.Delivery, n.Native.Notice.Templates = c.Delivery.Enqueue.Custody, c.Delivery.Templates
	owner, err := passwordpg.NewPhoneRemovalService(primary, signin, reset, n.Policy, n.Native, keys)
	if err != nil {
		return nil, fmt.Errorf("reference phone removal native: %w", err)
	}
	policy := *n.Policy
	return &phoneRemovalState{owner: owner, policy: &policy, provider: n.Native.Notice.ProviderVersion}, nil
}

// PhoneRemovalService borrows a selected graph's native removal owner. All calls
// retain tenant, startup, deadline and shutdown guards; it owns no resources.
// Zero denies and nested diagnostics cannot traverse retained graph secrets.
type PhoneRemovalService struct{ read func() *storeState }

var _ phone.RemovalService = (*PhoneRemovalService)(nil)
var _ phone.RemovalRateSource = (*PhoneRemovalService)(nil)

// PhoneRemoval obtains an explicitly selected native handle without IO. It does
// not select HTTP, enrollment or authentication; retained handles deny on Close.
func (f FeatureSet) PhoneRemoval() (*PhoneRemovalService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_phone_removal"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.phoneRemoval == nil {
		return nil, identity.UnavailableError{}
	}
	return &PhoneRemovalService{read: func() *storeState { return s }}, nil
}

func (s *PhoneRemovalService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *passwordpg.PhoneRemovalService, func(), error) {
	if s == nil || s.read == nil || s.read() == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_phone_removal"}
	}
	state := s.read()
	w, done, err := (composedPasswordReset{state: state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if state.features.phoneRemoval == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, state.features.phoneRemoval.owner, done, nil
}

// Remove delegates the sole native atomic removal, proof and required effects.
func (s *PhoneRemovalService) Remove(ctx context.Context, r phone.RemoveRequest) (identity.CommandResult, error) {
	b, err := r.Bindings()
	if err != nil {
		return identity.CommandResult{}, err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.Remove(w, r)
}

// RemovalRateSource authenticates original keyed input without granting removal.
func (s *PhoneRemovalService) RemovalRateSource(ctx context.Context, r phone.RemoveRequest) (identity.UserID, error) {
	b, err := r.Bindings()
	if err != nil {
		return "", err
	}
	w, owner, done, err := s.enter(ctx, b.TenantID)
	if err != nil {
		return "", err
	}
	defer done()
	return owner.RemovalRateSource(w, r)
}

// RecoverRemoval observes the original code-free outcome, never new mutation.
func (s *PhoneRemovalService) RecoverRemoval(ctx context.Context, q identity.RecoveryQuery, c authorization.DecisionContext) (identity.CommandResult, error) {
	w, owner, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.RecoverRemoval(w, q, c)
}

// Format redacts the complete borrowed graph.
func (*PhoneRemovalService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneRemovalService(redacted)"))
}

// MarshalJSON denies implicit graph export.
func (*PhoneRemovalService) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// MarshalText denies implicit graph/map-key export.
func (*PhoneRemovalService) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// Format redacts native configuration and key custody.
func (PhoneRemovalConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneRemovalConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (PhoneRemovalConfiguration) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// MarshalText denies implicit configuration export.
func (PhoneRemovalConfiguration) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
