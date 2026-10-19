package phone

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// SigninService is the independently selected existing-account phone OTP
// workflow. SendSignin accepts original public pre-auth possession and a number
// canonicalized by this owner. It neither verifies a phone nor creates an
// account. Signin consumes the issued SMS challenge and that original flow with
// the session/effects in one native coordinator transaction. Native adapters
// enforce current verified phone/account/factors and original remember policy.
// Calls must honor bounded contexts and be safe for concurrent use. Unknown
// outcomes require original code-free recovery, never another code submission.
// This interface enables neither password login nor MFA/signup/reset variants.
type SigninService interface {
	SendSignin(context.Context, SigninSendRequest) (otp.SendResult, error)
	Signin(context.Context, otp.SigninRequest) (otp.SigninResult, error)
	RecoverSignin(context.Context, otp.SigninRecoveryRequest) (otp.SigninResult, error)
}

// SigninSendRequestSpec is an explicitly sensitive construction/projection DTO,
// not a safe logging handle. Number must be canonical under the selected owner
// policy; structural validity is not phone possession or account eligibility.
// Caller is trusted composition, not request-selected authorization. Flow is
// the original public pre-auth cookie custody; the native adapter authenticates
// and compares its tenant/action/number/remember binding before discovery.
// Network/Device come from trusted transport composition. No field can select
// a user, challenge, code, session or replacement remember policy. Do not mutate
// Caller maps during construction; exported projection fields reveal custody.
type SigninSendRequestSpec struct {
	TenantID       identity.TenantID
	Number         Number
	Caller         authorization.DecisionContext
	Flow           otp.SendFlow
	Network        string
	Device         string
	IdempotencyKey identity.IdempotencyKey
}

// SigninSendRequest freezes bounded original phone-initiation custody. Zero
// denies; copies are immutable/concurrent-safe and own no IO or goroutines.
// Closure custody prevents nested diagnostics traversing the raw projection.
type SigninSendRequest struct{ read func() SigninSendRequestSpec }

// NewSigninSendRequest validates structure and clones caller collections. It
// performs no lookup, authentication, OTP generation or risk evaluation.
func NewSigninSendRequest(spec SigninSendRequestSpec) (SigninSendRequest, error) {
	if err := spec.Validate(); err != nil {
		return SigninSendRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return SigninSendRequest{read: func() SigninSendRequestSpec { return spec }}, nil
}

// Validate rejects missing number/custody, non-public flow and action confusion.
// It grants no current authorization, recipient, challenge or delivery evidence.
func (r SigninSendRequestSpec) Validate() error {
	invalid := identity.InvalidInputError{Field: "phone.signin"}
	if r.Caller.Request.Action != "identity.phone.signin" {
		return invalid
	}
	kind, _, _, err := r.Flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationPreAuthTransaction {
		return invalid
	}
	number, err := r.Number.Record()
	if err != nil {
		return invalid
	}
	destination, err := otp.NewDestinationInput(number.E164)
	if err != nil {
		return invalid
	}
	// Reuse the OTP owner's bounds without attributing its structural request
	// validation any authentication authority or changing the phone action.
	base := otp.SendRequest{TenantID: r.TenantID, Caller: r.Caller, Flow: r.Flow,
		Channel: otp.ChannelSMS, Destination: destination, Purpose: otp.PurposeSignin,
		TargetID: "identity.phone.signin", Network: r.Network, Device: r.Device,
		IdempotencyKey: r.IdempotencyKey}
	if base.Validate() != nil {
		return invalid
	}
	return nil
}

// Bindings explicitly projects sensitive original custody, cloning caller
// collections. Do not log, serialize or retain the projection after use.
func (r SigninSendRequest) Bindings() (SigninSendRequestSpec, error) {
	if r.read == nil {
		return SigninSendRequestSpec{}, identity.InvalidInputError{Field: "phone.signin"}
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return SigninSendRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate checks the retained structural binding only, without IO.
func (r SigninSendRequest) Validate() error { _, err := r.Bindings(); return err }

// Format redacts the complete original phone and pre-auth custody.
func (SigninSendRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.SigninSendRequest(redacted)"))
}

// MarshalJSON denies implicit export of the original request.
func (SigninSendRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit export or use as a serialized map key.
func (SigninSendRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts custody independently of structured logger selection.
func (SigninSendRequest) LogValue() slog.Value {
	return slog.StringValue("phone.SigninSendRequest(redacted)")
}
