package phone

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

// ErrInvalidPasswordReset rejects malformed original recovery custody without
// disclosing a phone, account, password, factor or provider decision.
const ErrInvalidPasswordReset WorkflowError = "identity.phone.invalid_password_reset"

// PasswordResetRequestResult is the existing enumeration-safe send receipt.
// Commitment means acceptance, not recipient existence or actual SMS delivery.
type PasswordResetRequestResult = otp.SendResult

// PasswordResetCompleteResult is the password owner's credential/revocation
// receipt. It never contains a session; unknown outcomes expose no successor.
type PasswordResetCompleteResult = password.ResetCompleteResult

// PasswordResetService is an explicitly selected phone-recovery workflow, not
// an implementation or an enabled feature. Startup must explicitly accept the
// carrier, SIM-swap and number-recycling risks. This profile requires an actual
// independent confirmed TOTP; neither SMS nor its accompanying reset capability
// can supply that independence. No remember or session-suppression choice exists.
//
// Native composition authenticates the original no-session pre-auth, verified
// phone/password/factor authority, distinct initiation/completion RiskEvidence,
// canonical capability and both codes. HIBP precedes hashing. OTP, TOTP replay,
// capability/risk use, password replacement and session revocation commit in the
// sole coordinator transaction. No weaker email or missing-factor fallback is
// allowed. Recovery authorizes original scoped history without codes, password,
// capability re-presentation, reissuance or renewed freshness. Implementations
// honor bounded contexts and support concurrent independent calls. These ports
// alone enable no native workflow or HTTP route.
type PasswordResetService interface {
	PasswordResetRequest(context.Context, PasswordResetRequestRequest) (PasswordResetRequestResult, error)
	PasswordResetComplete(context.Context, PasswordResetCompleteRequest) (PasswordResetCompleteResult, error)
	RecoverPasswordResetRequest(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (PasswordResetRequestResult, error)
	RecoverPasswordResetComplete(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (PasswordResetCompleteResult, error)
}

// PasswordResetRequestRequestSpec is sensitive construction/projection input.
// Number is already canonical under its explicit owner. Flow carries the actual
// original browser cookie, not caller-selected user authority. RiskEvidence is
// an opaque initiation-only reference, never raw carrier facts. Native admission
// checks its genuine provenance, phase, scope, current allowance and one-use row.
// RiskIssuanceCommandID retains that evidence's original issuance command so the
// risk owner can resolve its private record. It must differ from CommandID and
// supplies no authority without the exact authenticated reference and scope.
// CommandID/IdempotencyKey retain original attempt identity on retries. Caller,
// Origin, Network and Device come from trusted transport, not body fields.
// Keep Caller collections immutable during construction; never log projections.
type PasswordResetRequestRequestSpec struct {
	TenantID                identity.TenantID
	CommandID               identity.CommandID
	Number                  Number
	Flow                    otp.SendFlow
	RiskEvidence            risk.RiskEvidenceRef
	RiskIssuanceCommandID   identity.CommandID
	IdempotencyKey          identity.IdempotencyKey
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
}

// PasswordResetRequestRequest freezes original recovery-request custody. Zero
// denies. Copies are concurrent-safe and own no IO, goroutines or resource.
// Closure custody prevents enclosing diagnostics from traversing input fields.
type PasswordResetRequestRequest struct {
	read func() PasswordResetRequestRequestSpec
}

// NewPasswordResetRequestRequest checks structure and clones Caller without
// lookup, clocks, providers, issuance, password work or recovery authorization.
func NewPasswordResetRequestRequest(spec PasswordResetRequestRequestSpec) (PasswordResetRequestRequest, error) {
	if err := spec.Validate(); err != nil {
		return PasswordResetRequestRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return PasswordResetRequestRequest{read: func() PasswordResetRequestRequestSpec { return spec }}, nil
}

// Validate checks bounded original input only. It cannot authenticate the
// cookie or risk reference, choose a recipient, verify TOTP or authorize SMS.
func (r PasswordResetRequestRequestSpec) Validate() error {
	if resetProvenance(r.TenantID, r.CommandID, r.Flow, r.Caller, r.Origin, r.Network, r.Device, "identity.phone.password-reset-request") != nil ||
		r.IdempotencyKey == (identity.IdempotencyKey{}) || r.RiskEvidence.Reveal() == "" || !resetRiskIssuance(r.RiskIssuanceCommandID, r.CommandID) {
		return ErrInvalidPasswordReset
	}
	if _, err := r.Number.Record(); err != nil {
		return ErrInvalidPasswordReset
	}
	return nil
}

// Bindings explicitly reveals sensitive original input with an independent
// Caller clone. Structural validity supplies no authentication or fresh evidence.
func (r PasswordResetRequestRequest) Bindings() (PasswordResetRequestRequestSpec, error) {
	if r.read == nil {
		return PasswordResetRequestRequestSpec{}, ErrInvalidPasswordReset
	}
	s := r.read()
	if err := s.Validate(); err != nil {
		return PasswordResetRequestRequestSpec{}, err
	}
	s.Caller = s.Caller.Clone()
	return s, nil
}

// PasswordResetCompleteRequestSpec borrows the canonical capability, original
// SMS and independent TOTP codes plus caller-owned replacement password. They
// are submissions, not successful-factor proofs. Native custody derives the
// original user, phone, challenge and factor from authenticated issuance, never
// a caller-selected user or today's versions. Completion requires its own
// distinct risk reference. Keep all borrowed owners live during the bounded
// call; destroy NewPassword afterward. No constructor transfers any proof.
// RiskIssuanceCommandID identifies that completion evidence's original issuance,
// not the request's initiation evidence or the consuming CommandID. The native
// risk owner must authenticate the distinct completion purpose and full scope.
type PasswordResetCompleteRequestSpec struct {
	TenantID                identity.TenantID
	CommandID               identity.CommandID
	Flow                    otp.SendFlow
	ResetCapability         capability.Proof
	PhoneCode               auth.OneTimeCode
	IndependentTOTP         auth.OneTimeCode
	RiskEvidence            risk.RiskEvidenceRef
	RiskIssuanceCommandID   identity.CommandID
	NewPassword             primitive.Secret
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
}

// PasswordResetCompleteRequest retains the entire immutable conjunction, not
// separate interchangeable single-factor commands. Copies share terminal
// password/proof lifetimes; no IO, callbacks or background work is owned.
type PasswordResetCompleteRequest struct {
	read func() PasswordResetCompleteRequestSpec
}

// NewPasswordResetCompleteRequest freezes bounded joint input and clones
// Caller. It never compares codes, verifies capability or hashes a password.
func NewPasswordResetCompleteRequest(spec PasswordResetCompleteRequestSpec) (PasswordResetCompleteRequest, error) {
	if err := spec.Validate(); err != nil {
		return PasswordResetCompleteRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return PasswordResetCompleteRequest{read: func() PasswordResetCompleteRequestSpec { return spec }}, nil
}

// Validate checks structure without borrowing password bytes or renewing any
// validity. Numerical code equality does not establish factor independence;
// only the native factor and phone owners may establish that property.
func (r PasswordResetCompleteRequestSpec) Validate() error {
	if resetProvenance(r.TenantID, r.CommandID, r.Flow, r.Caller, r.Origin, r.Network, r.Device, "identity.phone.password-reset-complete") != nil ||
		r.ResetCapability.ValidateBounds(32, 4096) != nil || r.RiskEvidence.Reveal() == "" || !resetRiskIssuance(r.RiskIssuanceCommandID, r.CommandID) || r.NewPassword.Len() == 0 || r.NewPassword.Len() > 1<<20 {
		return ErrInvalidPasswordReset
	}
	for _, code := range []auth.OneTimeCode{r.PhoneCode, r.IndependentTOTP} {
		// This uses the existing owner's bounded structural check only. The
		// discarded digest is not proof or the native attempt fingerprint.
		if _, err := code.CommandDigest([32]byte{1}, "identity.phone.recovery.bounds"); err != nil {
			return ErrInvalidPasswordReset
		}
	}
	return nil
}

func resetRiskIssuance(original, consuming identity.CommandID) bool {
	_, err := identity.ParseCommandID(string(original))
	return err == nil && original != consuming
}

// Bindings reveals sensitive original input; discard it after bounded use.
// Destroyed borrowed password/proof custody returns zero and a redacted error.
func (r PasswordResetCompleteRequest) Bindings() (PasswordResetCompleteRequestSpec, error) {
	if r.read == nil {
		return PasswordResetCompleteRequestSpec{}, ErrInvalidPasswordReset
	}
	s := r.read()
	if err := s.Validate(); err != nil {
		return PasswordResetCompleteRequestSpec{}, err
	}
	s.Caller = s.Caller.Clone()
	return s, nil
}

func resetProvenance(tenant identity.TenantID, command identity.CommandID, flow otp.SendFlow, caller authorization.DecisionContext, origin, network, device string, action authorization.Action) error {
	if !boundedVerificationCaller(caller) || caller.Validate() != nil || string(caller.Request.Tenant) != string(tenant) ||
		caller.Request.Action != action || caller.Request.Subject.Kind != authorization.SubjectServiceAccount ||
		caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != "" ||
		!verificationText(origin, 2048) || !verificationText(device, 128) || len(network) > 45 {
		return ErrInvalidPasswordReset
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return ErrInvalidPasswordReset
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		return ErrInvalidPasswordReset
	}
	kind, _, _, err := flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationPreAuthTransaction {
		return ErrInvalidPasswordReset
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return ErrInvalidPasswordReset
	}
	ip, err := netip.ParseAddr(network)
	if err != nil || ip.Zone() != "" || ip.String() != network || ip.IsUnspecified() || ip.IsMulticast() {
		return ErrInvalidPasswordReset
	}
	return nil
}

// Format redacts original request custody for all formatting verbs.
func (PasswordResetRequestRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetRequestRequest(redacted)"))
}

// MarshalJSON rejects implicit export of the original request.
func (PasswordResetRequestRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// MarshalText rejects implicit export and map-key use.
func (PasswordResetRequestRequest) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// LogValue redacts original request custody independently of logger selection.
func (PasswordResetRequestRequest) LogValue() slog.Value {
	return slog.StringValue("phone.PasswordResetRequestRequest(redacted)")
}

// Format redacts explicit projection diagnostics; do not enclose its public
// fields in private diagnostics that bypass Formatter.
func (PasswordResetRequestRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetRequestRequestSpec(redacted)"))
}

// MarshalJSON rejects implicit sensitive projection export.
func (PasswordResetRequestRequestSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// MarshalText rejects implicit sensitive projection export.
func (PasswordResetRequestRequestSpec) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// Format redacts all original completion factors and password custody.
func (PasswordResetCompleteRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetCompleteRequest(redacted)"))
}

// MarshalJSON rejects implicit factor/password export.
func (PasswordResetCompleteRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// MarshalText rejects implicit factor/password export and map-key use.
func (PasswordResetCompleteRequest) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// LogValue redacts completion custody independently of logger selection.
func (PasswordResetCompleteRequest) LogValue() slog.Value {
	return slog.StringValue("phone.PasswordResetCompleteRequest(redacted)")
}

// Format redacts ordinary completion-projection diagnostics, not arbitrary
// reflection through an enclosing value. Treat projected fields as sensitive.
func (PasswordResetCompleteRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.PasswordResetCompleteRequestSpec(redacted)"))
}

// MarshalJSON rejects implicit sensitive completion-projection export.
func (PasswordResetCompleteRequestSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// MarshalText rejects implicit sensitive completion-projection export.
func (PasswordResetCompleteRequestSpec) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}
