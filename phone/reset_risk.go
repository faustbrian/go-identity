package phone

import (
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// PasswordResetInitiationRiskRequestSpec supplies original browser/number scope
// before any risk reference exists. CommandID is the original recovery attempt;
// IssuanceCommandID is distinct and identifies its one durable risk evaluation.
// There is deliberately no UserID, carrier fact, decision or evidence field.
// Native composition resolves current verified phone/password/independent TOTP
// authority and supplies that exact subject to the existing risk owner.
type PasswordResetInitiationRiskRequestSpec struct {
	TenantID                     identity.TenantID
	CommandID, IssuanceCommandID identity.CommandID
	Number                       Number
	Flow                         otp.SendFlow
	Caller                       authorization.DecisionContext
	Origin, Network, Device      string
}

// PasswordResetInitiationRiskRequest owns immutable structural input only.
// Copies are safe concurrently, retain no resources and prove no authority.
type PasswordResetInitiationRiskRequest struct {
	read func() PasswordResetInitiationRiskRequestSpec
}

// NewPasswordResetInitiationRiskRequest freezes bounded input without lookup,
// provider observation, issuance, clocks or permission to send a message.
func NewPasswordResetInitiationRiskRequest(s PasswordResetInitiationRiskRequestSpec) (PasswordResetInitiationRiskRequest, error) {
	if err := s.Validate(); err != nil {
		return PasswordResetInitiationRiskRequest{}, err
	}
	s.Caller = s.Caller.Clone()
	return PasswordResetInitiationRiskRequest{read: func() PasswordResetInitiationRiskRequestSpec { return s }}, nil
}

// Validate shares the request's exact no-session provenance policy without
// requiring an invented evidence reference. It does not authenticate the cookie.
func (s PasswordResetInitiationRiskRequestSpec) Validate() error {
	if resetProvenance(s.TenantID, s.CommandID, s.Flow, s.Caller, s.Origin, s.Network, s.Device, "identity.phone.password-reset-request") != nil || !resetRiskIssuance(s.IssuanceCommandID, s.CommandID) {
		return ErrInvalidPasswordReset
	}
	if _, err := s.Number.Record(); err != nil {
		return ErrInvalidPasswordReset
	}
	return nil
}

// Bindings returns an owned scalar projection and clone of the trusted caller.
func (s PasswordResetInitiationRiskRequest) Bindings() (PasswordResetInitiationRiskRequestSpec, error) {
	if s.read == nil {
		return PasswordResetInitiationRiskRequestSpec{}, ErrInvalidPasswordReset
	}
	r := s.read()
	r.Caller = r.Caller.Clone()
	return r, nil
}

func (PasswordResetInitiationRiskRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetInitiationRiskRequest(redacted)"))
}
func (PasswordResetInitiationRiskRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetInitiationRiskRequest) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetInitiationRiskRequest) LogValue() slog.Value {
	return slog.StringValue("phone.PasswordResetInitiationRiskRequest(redacted)")
}
func (PasswordResetInitiationRiskRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetInitiationRiskRequestSpec(redacted)"))
}
func (PasswordResetInitiationRiskRequestSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetInitiationRiskRequestSpec) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetInitiationRiskRequestSpec) LogValue() slog.Value {
	return slog.StringValue("phone.PasswordResetInitiationRiskRequestSpec(redacted)")
}
