package reference

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

// ManagedEmailService is a graph-lifetime-bound native email handle, not a
// repository, credential validator or independently committable workflow.
// The selected getter fixes verification-send versus change-request. Methods
// for the other profile deny; calls preserve native proof, recovery and outcome
// semantics and are bounded by graph/caller/native deadlines. Zero denies.
type ManagedEmailService struct {
	state  *storeState
	change bool
}

// EmailVerification exposes the selected add/resend/verify native workflow.
// It creates no HTTP route, resource or goroutine. Retained handles deny after
// graph Close; the caller does not acquire the borrowed pool or signing owners.
func (f FeatureSet) EmailVerification() (*ManagedEmailService, error) { return f.managedEmail(false) }

// EmailChange exposes the separately selected request/confirmation/notice
// workflow. Original password verification must select its exact action target.
func (f FeatureSet) EmailChange() (*ManagedEmailService, error) { return f.managedEmail(true) }

func (f FeatureSet) managedEmail(change bool) (*ManagedEmailService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_email"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.email == nil || change && s.features.email.change == nil || !change && s.features.email.verification == nil {
		return nil, identity.UnavailableError{}
	}
	return &ManagedEmailService{state: s, change: change}, nil
}

func (s *ManagedEmailService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, *passwordpg.EmailManagementService, func(), error) {
	if s == nil || s.state == nil {
		return nil, nil, nil, identity.InvalidInputError{Field: "reference_email"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	owner := s.state.features.email.verification
	if s.change {
		owner = s.state.features.email.change
	}
	return w, owner, done, nil
}

// VerificationSend preserves native original-password admission, issuance and
// delivery under the graph's lifetime. A change-selected handle cannot use it.
func (s *ManagedEmailService) VerificationSend(ctx context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	w, owner, done, err := s.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return passwordpg.EmailManagementResult{}, err
	}
	defer done()
	return owner.VerificationSend(w, r)
}

// VerificationResend preserves native cooldown and predecessor supersession.
func (s *ManagedEmailService) VerificationResend(ctx context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	w, owner, done, err := s.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return passwordpg.EmailManagementResult{}, err
	}
	defer done()
	return owner.VerificationResend(w, r)
}

// ChangeRequest attaches the selected native candidate, not a completed swap.
func (s *ManagedEmailService) ChangeRequest(ctx context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	w, owner, done, err := s.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return passwordpg.EmailManagementResult{}, err
	}
	defer done()
	return owner.ChangeRequest(w, r)
}

// VerificationSendKeyed selects original-input correlation when explicitly
// configured. Command/address IDs must be empty. It preserves native atomic
// proof, issuance, delivery and retry semantics; missing keyed selection denies.
func (s *ManagedEmailService) VerificationSendKeyed(ctx context.Context, r passwordpg.EmailManagementRequest, key identity.IdempotencyKey) (passwordpg.EmailManagementResult, error) {
	if s == nil || s.change {
		return passwordpg.EmailManagementResult{}, identity.InvalidInputError{Field: "reference_email_keyed"}
	}
	return s.keyedRequest(ctx, r, key, false)
}

// VerificationResendKeyed retains the existing pending target and cooldown.
// It requires selected keyed verification, an empty command ID and exact target.
func (s *ManagedEmailService) VerificationResendKeyed(ctx context.Context, r passwordpg.EmailManagementRequest, key identity.IdempotencyKey) (passwordpg.EmailManagementResult, error) {
	if s == nil || s.change {
		return passwordpg.EmailManagementResult{}, identity.InvalidInputError{Field: "reference_email_keyed"}
	}
	return s.keyedRequest(ctx, r, key, true)
}

// ChangeRequestKeyed creates one original pending change candidate, not a swap.
// It is available only on the selected change handle with keyed composition.
func (s *ManagedEmailService) ChangeRequestKeyed(ctx context.Context, r passwordpg.EmailManagementRequest, key identity.IdempotencyKey) (passwordpg.EmailManagementResult, error) {
	if s == nil || !s.change {
		return passwordpg.EmailManagementResult{}, identity.InvalidInputError{Field: "reference_email_keyed"}
	}
	return s.keyedRequest(ctx, r, key, false)
}

// RequestRateSourceKeyed authenticates native subject/destination rate metadata
// before mutable session lookup. Both values are sensitive and must not be logged
// or disclosed. It does not allocate durable request state, assess providers,
// issue links, charge counters or grant current mutation/session authority.
// Exact retries preserve original possession and retain the native input/clock
// provenance. It requires selected keyed composition and the graph lifetime.
func (s *ManagedEmailService) RequestRateSourceKeyed(ctx context.Context, r passwordpg.EmailManagementRequest, key identity.IdempotencyKey, resend bool) (identity.UserID, string, error) {
	w, _, done, err := s.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return "", "", err
	}
	defer done()
	owner := s.state.features.email.keyedVerification
	if s.change {
		owner = s.state.features.email.keyedChange
	}
	if owner == nil || s.change && resend {
		return "", "", identity.InvalidInputError{Field: "reference_email_keyed"}
	}
	return owner.RequestRateSource(w, r, key, resend)
}

func (s *ManagedEmailService) keyedRequest(ctx context.Context, r passwordpg.EmailManagementRequest, key identity.IdempotencyKey, resend bool) (passwordpg.EmailManagementResult, error) {
	w, _, done, err := s.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return passwordpg.EmailManagementResult{}, err
	}
	defer done()
	owner := s.state.features.email.keyedVerification
	if s.change {
		owner = s.state.features.email.keyedChange
	}
	if owner == nil || s.change && resend {
		return passwordpg.EmailManagementResult{}, identity.InvalidInputError{Field: "reference_email_keyed"}
	}
	if s.change {
		return owner.ChangeRequest(w, r, key)
	}
	if resend {
		return owner.VerificationResend(w, r, key)
	}
	return owner.VerificationSend(w, r, key)
}

// VerificationConfirm delegates explicit protected one-use verification.
func (s *ManagedEmailService) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return email.VerificationConfirmResult{}, err
	}
	defer done()
	return owner.VerificationConfirm(w, r)
}

// ChangeConfirm delegates original new-address-confirmed primary change.
func (s *ManagedEmailService) ChangeConfirm(ctx context.Context, r email.ChangeConfirmRequest) (email.ChangeConfirmResult, error) {
	w, owner, done, err := s.enter(ctx, r.TenantID)
	if err != nil {
		return email.ChangeConfirmResult{}, err
	}
	defer done()
	return owner.ChangeConfirm(w, r)
}

// VerificationSendRecover observes original metadata without historical proof.
func (s *ManagedEmailService) VerificationSendRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (passwordpg.EmailManagementResult, error) {
	w, owner, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return passwordpg.EmailManagementResult{}, err
	}
	defer done()
	return owner.VerificationSendRecover(w, q, caller)
}

// ChangeRequestRecover observes the exact original candidate request metadata.
func (s *ManagedEmailService) ChangeRequestRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (passwordpg.EmailManagementResult, error) {
	w, owner, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return passwordpg.EmailManagementResult{}, err
	}
	defer done()
	return owner.ChangeRequestRecover(w, q, caller)
}

// VerificationRecover preserves native original verification reconciliation.
func (s *ManagedEmailService) VerificationRecover(ctx context.Context, r email.VerificationRecoveryRequest) (email.VerificationRecoveryResult, error) {
	q, err := r.Recovery.Bindings()
	if err != nil {
		return email.VerificationRecoveryResult{}, err
	}
	w, owner, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return email.VerificationRecoveryResult{}, err
	}
	defer done()
	return owner.VerificationRecover(w, r)
}

// ChangeRecover preserves original change metadata; it never repeats effects.
func (s *ManagedEmailService) ChangeRecover(ctx context.Context, r email.ChangeRecoveryRequest) (email.ChangeRecoveryResult, error) {
	q, err := r.Recovery.Bindings()
	if err != nil {
		return email.ChangeRecoveryResult{}, err
	}
	w, owner, done, err := s.enter(ctx, q.TenantID)
	if err != nil {
		return email.ChangeRecoveryResult{}, err
	}
	defer done()
	return owner.ChangeRecover(w, r)
}

// ReadManagedVerification authenticates original intent without consuming it.
func (s *ManagedEmailService) ReadManagedVerification(ctx context.Context, p capability.Proof, caller authorization.DecisionContext) (email.ManagedVerificationSpec, uint32, error) {
	w, owner, done, err := s.enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return email.ManagedVerificationSpec{}, 0, err
	}
	defer done()
	return owner.ReadManagedVerification(w, p, caller)
}

// ValidateManagedVerification is a non-consuming bounded current-state read.
func (s *ManagedEmailService) ValidateManagedVerification(ctx context.Context, p capability.Proof, callback string, caller authorization.DecisionContext) (bool, error) {
	w, owner, done, err := s.enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return false, err
	}
	defer done()
	return owner.ValidateManagedVerification(w, p, callback, caller)
}

// ManagedVerificationRateSource preserves exact verification-only provenance.
func (s *ManagedEmailService) ManagedVerificationRateSource(ctx context.Context, p capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	w, owner, done, err := s.enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return owner.ManagedVerificationRateSource(w, p, callback, caller)
}

// ChangeConfirmationRateSource preserves the distinct original change action.
func (s *ManagedEmailService) ChangeConfirmationRateSource(ctx context.Context, p capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	w, owner, done, err := s.enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return owner.ChangeConfirmationRateSource(w, p, callback, caller)
}

// EmailAddressService retains graph lifetime for authorized email primary reads.
// It grants no authentication or administrative rights. Zero denies.
type EmailAddressService struct{ state *storeState }

// Format redacts retained graph and native credential/key custody.
func (ManagedEmailService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.ManagedEmailService(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (ManagedEmailService) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit runtime text export.
func (ManagedEmailService) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// LogValue emits no graph or credential metadata.
func (ManagedEmailService) LogValue() slog.Value {
	return slog.StringValue("reference.ManagedEmailService(redacted)")
}

// Format redacts retained graph and authorization custody.
func (EmailAddressService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EmailAddressService(redacted)")
}

// MarshalJSON denies implicit query-owner export.
func (EmailAddressService) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit query-owner text export.
func (EmailAddressService) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// LogValue emits no graph or policy metadata.
func (EmailAddressService) LogValue() slog.Value {
	return slog.StringValue("reference.EmailAddressService(redacted)")
}

// EmailAddresses returns only explicitly selected list/get capabilities.
func (f FeatureSet) EmailAddresses() (*EmailAddressService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_email"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.email == nil || s.features.email.addresses == nil {
		return nil, identity.UnavailableError{}
	}
	return &EmailAddressService{state: s}, nil
}

// AdministrativeQueriesConfigured reports live required-audit composition only,
// never a permission or identity-validity guarantee. A closed graph denies.
func (s *EmailAddressService) AdministrativeQueriesConfigured() bool {
	if s == nil || s.state == nil {
		return false
	}
	state := s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return !state.closed && state.features != nil && state.features.composed && state.features.email != nil && state.features.email.addresses.AdministrativeQueriesConfigured()
}

// AddressGet delegates current owner/admin policy and safe projection.
func (s *EmailAddressService) AddressGet(ctx context.Context, r email.AddressGetRequest) (email.AddressGetResult, error) {
	if s == nil || s.state == nil {
		return email.AddressGetResult{}, identity.InvalidInputError{Field: "reference_email"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, r.TenantID)
	if err != nil {
		return email.AddressGetResult{}, err
	}
	defer done()
	return s.state.features.email.addresses.AddressGet(w, r)
}

// AddressList delegates bounded, scope-bound pagination without mutation.
func (s *EmailAddressService) AddressList(ctx context.Context, r email.AddressListRequest) (email.AddressListResult, error) {
	if s == nil || s.state == nil {
		return email.AddressListResult{}, identity.InvalidInputError{Field: "reference_email"}
	}
	w, done, err := (composedPasswordReset{state: s.state}).enter(ctx, r.TenantID)
	if err != nil {
		return email.AddressListResult{}, err
	}
	defer done()
	return s.state.features.email.addresses.AddressList(w, r)
}
