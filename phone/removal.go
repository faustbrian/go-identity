package phone

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ErrInvalidRemoval denies malformed or cross-scope removal custody without
// disclosing a number, proof, account or configured recovery method.
const ErrInvalidRemoval WorkflowError = "identity.phone.invalid_removal"

// RemoveResult is the original native command outcome. A committed Cascade
// records pending identifier-removal consumers, not completed cleanup. Unknown
// or denied results grant no authentication or replacement credentials.
type RemoveResult = identity.CommandResult

// RemovalService is separately selected authenticated self-removal, not phone
// replacement or account recovery. Implementations authenticate recent original
// action-bound proof, current account/factor/risk authority and the configured
// independent recovery method. Removal, proof use, required session/notification
// effects and the pending identifier-removal cascade commit in one native unit
// of work. No OTP is issued, reserved, compared or consumed and no session is
// issued. Calls must honor bounded contexts and support concurrent callers.
// Unknown outcomes require original code-free recovery, never a new mutation.
type RemovalService interface {
	Remove(context.Context, RemoveRequest) (RemoveResult, error)
	RecoverRemoval(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error)
}

// RemovalRateSource authenticates original request possession before transport
// admission. It may persist encrypted intent in the existing request journal,
// but cannot remove a phone, consume proof or grant current authority. The
// returned subject is sensitive; native execution repeats its protected checks.
type RemovalRateSource interface {
	RemovalRateSource(context.Context, RemoveRequest) (identity.UserID, error)
}

// RemoveRequest is immutable opaque original removal custody. Zero denies;
// copies are concurrent-safe and own no IO or goroutines. Closure custody keeps
// nested diagnostics from traversing raw number, bearer, proof or request key.
type RemoveRequest struct{ read func() RemoveRequestSpec }

// RemoveRequestSpec is sensitive explicit construction/projection input, not a
// safe logging handle. Number is already canonical under the selected immutable
// policy. IdentifierID and both versions name that exact stored verified phone;
// neither the number nor these selectors prove ownership. Caller and Network
// come from trusted composition. Session/Proof retain original signed custody;
// native configuration owns freshness, one-use, current authority and CSRF.
// Reason is a registered code, not arbitrary audit text. Preserve every field
// and IdempotencyKey on retry. Do not mutate caller collections during copying
// or log/serialize this projection, including inside private diagnostics.
type RemoveRequestSpec struct {
	TenantID                                               identity.TenantID
	UserID                                                 identity.UserID
	Number                                                 Number
	IdentifierID                                           identity.IdentifierID
	ExpectedIdentifierVersion, ExpectedVerificationVersion uint64
	Reason                                                 identity.PolicyReason
	Session                                                auth.BearerCredential
	Proof                                                  auth.ReauthenticationProof
	CSRFToken                                              session.CSRFToken
	IdempotencyKey                                         identity.IdempotencyKey
	Caller                                                 authorization.DecisionContext
	Network                                                string
}

// NewRemoveRequest validates bounded original structure before cloning caller
// collections. It does no IO and authenticates neither proof nor phone ownership.
func NewRemoveRequest(spec RemoveRequestSpec) (RemoveRequest, error) {
	if err := spec.Validate(); err != nil {
		return RemoveRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return RemoveRequest{read: func() RemoveRequestSpec { return spec }}, nil
}

// Bindings reveals sensitive original input with independent caller collections.
// Structural validity is not current permission or renewed proof freshness.
func (r RemoveRequest) Bindings() (RemoveRequestSpec, error) {
	if r.read == nil {
		return RemoveRequestSpec{}, ErrInvalidRemoval
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return RemoveRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate rejects zero and malformed retained custody without IO.
func (r RemoveRequest) Validate() error { _, err := r.Bindings(); return err }

// Validate checks bounded self/action/proof structure, not its signature, present
// freshness, CSRF or actual recovery eligibility. Original issue time is used
// deliberately: a committed retry must not invent a fresh proof to read history.
func (r RemoveRequestSpec) Validate() error {
	const action = "identity.phone.remove"
	if validateVerificationCaller(r.TenantID, r.UserID, r.Caller, action) != nil ||
		r.Caller.Request.Resource.Type != "identity.user" || r.Caller.Request.Resource.ID != authorization.ResourceID(r.UserID) ||
		r.ExpectedIdentifierVersion == 0 || r.ExpectedIdentifierVersion == ^uint64(0) ||
		r.ExpectedVerificationVersion == 0 || r.ExpectedVerificationVersion == ^uint64(0) ||
		r.IdempotencyKey == (identity.IdempotencyKey{}) || !removalReason(r.Reason) || len(r.Network) > 45 {
		return ErrInvalidRemoval
	}
	if _, err := identity.ParseIdentifierID(string(r.IdentifierID)); err != nil {
		return ErrInvalidRemoval
	}
	if _, err := r.Number.Record(); err != nil {
		return ErrInvalidRemoval
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return ErrInvalidRemoval
	}
	ip, err := netip.ParseAddr(r.Network)
	if err != nil || ip.Zone() != "" || ip.String() != r.Network || ip.IsUnspecified() || ip.IsMulticast() {
		return ErrInvalidRemoval
	}
	p := r.Proof
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.TenantID), Subject: string(r.UserID), Purpose: "identity.password.verify", Audience: p.Proof.Audience, Now: p.Proof.IssuedAt}, SessionID: p.SessionID, SessionVersion: p.SessionVersion, Action: action, MaximumAge: 15 * time.Minute}
	if p.Validate(use) != nil || p.Proof.Method != "password" || p.Proof.Assurance != auth.AssuranceSingleFactor {
		return ErrInvalidRemoval
	}
	return nil
}

func removalReason(reason identity.PolicyReason) bool {
	if len(reason) == 0 || len(reason) > 64 || reason[0] < 'a' || reason[0] > 'z' {
		return false
	}
	for _, c := range reason {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// Format redacts the complete original removal custody.
func (RemoveRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.RemoveRequest(redacted)"))
}

// MarshalJSON denies implicit original-custody export.
func (RemoveRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit original-custody export and map-key use.
func (RemoveRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts original custody independently of logger selection.
func (RemoveRequest) LogValue() slog.Value { return slog.StringValue("phone.RemoveRequest(redacted)") }

// Format redacts ordinary formatting of the sensitive projection; callers must
// not enclose its exported fields in diagnostics that bypass this method.
func (RemoveRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phone.RemoveRequestSpec(redacted)"))
}

// MarshalJSON denies implicit projection export.
func (RemoveRequestSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit projection export.
func (RemoveRequestSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }
