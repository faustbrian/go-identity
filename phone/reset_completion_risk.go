package phone

import (
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// PasswordResetCompletionRiskRequestSpec identifies one completion's distinct
// risk evaluation without requiring an invented reference or caller-selected
// account/number. The native owner authenticates ResetCapability's actual
// issuance and original browser, and derives original phone/password/TOTP scope.
// CommandID is the consuming attempt; IssuanceCommandID is distinct. Caller and
// transport provenance are trusted input, not body-selected authority. Keep the
// borrowed capability live until the bounded native call returns.
type PasswordResetCompletionRiskRequestSpec struct {
	TenantID                     identity.TenantID
	CommandID, IssuanceCommandID identity.CommandID
	Flow                         otp.SendFlow
	ResetCapability              capability.Proof
	Caller                       authorization.DecisionContext
	Origin, Network, Device      string
}

// PasswordResetCompletionRiskRequest retains immutable structural custody, not
// an accepted factor, valid grant or risk decision. Copies share the borrowed
// proof's terminal lifetime; this value owns no IO or background resources.
type PasswordResetCompletionRiskRequest struct {
	read func() PasswordResetCompletionRiskRequestSpec
}

// NewPasswordResetCompletionRiskRequest checks bounds and freezes a caller
// clone without lookup, verification, provider work, clock or issuance.
func NewPasswordResetCompletionRiskRequest(s PasswordResetCompletionRiskRequestSpec) (PasswordResetCompletionRiskRequest, error) {
	if err := s.Validate(); err != nil {
		return PasswordResetCompletionRiskRequest{}, err
	}
	s.Caller = s.Caller.Clone()
	return PasswordResetCompletionRiskRequest{read: func() PasswordResetCompletionRiskRequestSpec { return s }}, nil
}

// Validate checks no-session provenance and live bounded proof custody only.
// It does not authenticate the browser, signature, original account or expiry.
func (s PasswordResetCompletionRiskRequestSpec) Validate() error {
	if resetProvenance(s.TenantID, s.CommandID, s.Flow, s.Caller, s.Origin, s.Network, s.Device, "identity.phone.password-reset-complete") != nil || !resetRiskIssuance(s.IssuanceCommandID, s.CommandID) || s.ResetCapability.ValidateBounds(32, 4096) != nil {
		return ErrInvalidPasswordReset
	}
	return nil
}

// Bindings explicitly borrows original sensitive custody and clones the caller.
// Destroyed capability aliases deny rather than projecting apparently live input.
func (r PasswordResetCompletionRiskRequest) Bindings() (PasswordResetCompletionRiskRequestSpec, error) {
	if r.read == nil {
		return PasswordResetCompletionRiskRequestSpec{}, ErrInvalidPasswordReset
	}
	s := r.read()
	if err := s.Validate(); err != nil {
		return PasswordResetCompletionRiskRequestSpec{}, err
	}
	s.Caller = s.Caller.Clone()
	return s, nil
}

func (PasswordResetCompletionRiskRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetCompletionRiskRequest(redacted)"))
}
func (PasswordResetCompletionRiskRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetCompletionRiskRequest) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetCompletionRiskRequest) LogValue() slog.Value {
	return slog.StringValue("phone.PasswordResetCompletionRiskRequest(redacted)")
}
func (PasswordResetCompletionRiskRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetCompletionRiskRequestSpec(redacted)"))
}
func (PasswordResetCompletionRiskRequestSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetCompletionRiskRequestSpec) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
func (PasswordResetCompletionRiskRequestSpec) LogValue() slog.Value {
	return slog.StringValue("phone.PasswordResetCompletionRiskRequestSpec(redacted)")
}
