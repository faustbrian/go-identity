package phone

import (
	"fmt"
	"log/slog"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// UpdateRequest is immutable submission custody for replacement, not enrollment
// confirmation. Its proof is specifically for identity.phone.update; the proof
// used to request SMS cannot authorize this distinct consuming operation. Copies
// are concurrent-safe and own no IO, callbacks or background resources. Zero
// denies. Retain the original retry key/input after an ambiguous submission,
// or use code-free recovery correlation. A new key is not original recovery.
type UpdateRequest struct{ read func() UpdateRequestSpec }

// UpdateRequestSpec is sensitive explicit construction/projection input. The
// original SendCommandID owns both numbers, their normalization and predecessor
// versions; completion cannot select a different target or substitute a number.
// Flow retains actual original session possession, not a caller-asserted session.
// Proof must belong to that same session and exact update action. Native owners
// authenticate its signature, one-use record, current authority and freshness
// before code metering and repeat them at protected use. Reason is a bounded
// registered policy code, not arbitrary notice/audit text. CSRFToken is current
// request custody for cookie admission; zero remains valid structural input for
// bearer admission. Do not log/serialize this projection, including in nested
// diagnostics that bypass its formatting methods.
type UpdateRequestSpec struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          otp.SendFlow
	SendCommandID identity.CommandID
	Code          auth.OneTimeCode
	Proof         auth.ReauthenticationProof
	CSRFToken     session.CSRFToken
	Reason        identity.PolicyReason
	// IdempotencyKey identifies one logical submission, including a wrong-code
	// denial. Retries retain it; a genuinely different submission uses a new key.
	// Native correlation owns the unpredictable command and OTP attempt IDs.
	IdempotencyKey identity.IdempotencyKey
}

// NewUpdateRequest checks bounded structure before copying input and cloning
// caller collections. It performs no IO or code comparison and authenticates
// neither the proof nor present phone, factor or recovery authority.
func NewUpdateRequest(spec UpdateRequestSpec) (UpdateRequest, error) {
	if err := spec.Validate(); err != nil {
		return UpdateRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return UpdateRequest{read: func() UpdateRequestSpec { return spec }}, nil
}

// Bindings explicitly reveals sensitive original submission with independent
// caller collections. It cannot renew proof freshness or grant OTP possession.
func (r UpdateRequest) Bindings() (UpdateRequestSpec, error) {
	if r.read == nil {
		return UpdateRequestSpec{}, ErrInvalidChange
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return UpdateRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate denies zero or malformed custody without observing current state.
func (r UpdateRequest) Validate() error { _, err := r.Bindings(); return err }

// Validate checks the exact self/session/action shape, not signatures, current
// validity, configured reason admission or code correctness. Deliberately use
// the original proof issue time: a historical retry must not require a renewed
// proof merely to identify its original command. Native live use owns the clock.
func (r UpdateRequestSpec) Validate() error {
	const action = "identity.phone.update"
	if validateVerificationFlow(r.TenantID, r.UserID, r.Caller, r.Flow, action) != nil ||
		r.Caller.Request.Resource.Type != "identity.user" || r.Caller.Request.Resource.ID != authorization.ResourceID(r.UserID) ||
		!removalReason(r.Reason) || r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return ErrInvalidChange
	}
	if _, err := identity.ParseCommandID(string(r.SendCommandID)); err != nil {
		return ErrInvalidChange
	}
	_, originalSessionID, _, err := r.Flow.Bindings()
	p := r.Proof
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.TenantID), Subject: string(r.UserID),
		Purpose: "identity.password.verify", Audience: p.Proof.Audience, Now: p.Proof.IssuedAt},
		SessionID: originalSessionID, SessionVersion: p.SessionVersion, Action: action, MaximumAge: 15 * time.Minute}
	if err != nil || p.Validate(use) != nil || p.Proof.Method != "password" || p.Proof.Assurance != auth.AssuranceSingleFactor {
		return ErrInvalidChange
	}
	return nil
}

// Format redacts all original submission custody, including nested use.
func (UpdateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.UpdateRequest(redacted)"))
}

// MarshalJSON denies implicit original-submission export.
func (UpdateRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit original-submission export and map-key use.
func (UpdateRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts submission custody independently of the logger.
func (UpdateRequest) LogValue() slog.Value { return slog.StringValue("phone.UpdateRequest(redacted)") }

// Format redacts ordinary projection formatting. Exported fields remain
// sensitive inside enclosing diagnostics that bypass this method.
func (UpdateRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.UpdateRequestSpec(redacted)"))
}

// MarshalJSON denies implicit sensitive-projection export.
func (UpdateRequestSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit sensitive-projection export.
func (UpdateRequestSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }
