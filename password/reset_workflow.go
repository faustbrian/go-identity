package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

// ResetRequestRequest preserves unnormalized identifier input and the exact
// selected HTTPS callback. TenantID, Caller, Origin, Network and Device require
// trusted transport provenance. CommandID and IdempotencyKey are the original
// stable attempt identities and must not change on retries or unknown outcomes.
// Neither creates user authority. No target user, recovery method, factor state,
// expiry or reset token is selected by the caller. Native composition must
// enforce its callback allowlist, owner normalization, current factor/account
// eligibility, risk and enumeration-safe selection before durable issuance.
// Keep the request and Caller collections immutable during calls; do not log
// explicit field projections or persist raw identifiers in command metadata.
type ResetRequestRequest struct {
	TenantID                identity.TenantID
	CommandID               identity.CommandID
	Identifier              identifier.Input
	CallbackURL             string
	IdempotencyKey          identity.IdempotencyKey
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
}

// Validate checks structure only, without normalization, discovery, issuance,
// clocks or callbacks. HTTPS syntax does not prove callback allowlist admission.
// The original raw string is preserved, including path/query spelling; fragments
// and userinfo deny. Zero inputs deny rather than acquiring defaults.
func (r ResetRequestRequest) Validate() error {
	if r.Caller.Request.Action != "identity.password.reset-request" || r.IdempotencyKey == (identity.IdempotencyKey{}) || !resetHTTPS(r.CallbackURL, 2048) || validateSigninProvenance(r.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil {
		return ErrPasswordWork
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrPasswordWork
	}
	if _, err := identifier.NewInput(string(r.Identifier)); err != nil {
		return ErrPasswordWork
	}
	return nil
}

// ResetCompleteRequest borrows the original upstream capability and replacement
// Secret without copying password bytes. Destroy NewPassword after the call,
// not during it. Token aliases retain upstream shared terminal-transfer state.
// Submit the same CommandID for explicit retries; reconcile unknown outcomes
// through proof-free original-command recovery rather than minting a new attempt.
// No request field selects a target user, verifier, method, authority version,
// clock or session policy. Native composition obtains these from verified issuer
// custody and authoritative owners, screens HIBP before hashing, then atomically
// consumes with credential/session/audit effects. Caller metadata is not proof.
type ResetCompleteRequest struct {
	TenantID                identity.TenantID
	CommandID               identity.CommandID
	Token                   capability.Proof
	NewPassword             primitive.Secret
	Caller                  authorization.DecisionContext
	Origin, Network, Device string
}

// Validate is bounded structural admission, not signature or reset permission.
// It does not borrow password bytes, transfer or consume the proof, hash, query
// state or sample time. A successful length observation is not a custody lease;
// the native workflow must borrow again and reject concurrent destruction.
func (r ResetCompleteRequest) Validate() error {
	if r.Caller.Request.Action != "identity.password.reset-complete" || validateSigninProvenance(r.TenantID, r.Caller, r.Origin, r.Network, r.Device) != nil || r.NewPassword.Len() == 0 || r.NewPassword.Len() > 1<<20 || r.Token.ValidateBounds(32, 4096) != nil {
		return ErrPasswordWork
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrPasswordWork
	}
	return nil
}

// ResetRequestResult acknowledges only accepted original work. Accepted is
// identical for eligible and suppressed identifiers after known commitment;
// it does not reveal account existence, actual queueing or provider delivery.
// Busy/unknown outcomes must retain the same attempt and never trigger issuance
// under a new identity. No recipient, capability or mailbox is returned.
type ResetRequestResult struct {
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
	Accepted  bool
}

// Validate rejects invented acceptance before a known original commitment.
func (r ResetRequestResult) Validate() error {
	if !validResetOutcome(r.CommandID, r.Outcome) || r.Accepted != (r.Outcome == identity.CommitOutcomeCommitted) {
		return ErrPasswordWork
	}
	return nil
}

// ResetCompleteResult exposes successors only after error-free known commitment
// of the sole protected transaction. SessionsRevoked means the required complete
// session set was invalidated atomically, including the valid empty-set case;
// it is not an asynchronous cleanup promise. No authentication/session issuance
// follows reset automatically. Unknown and busy results carry no successor or
// revocation success and cannot authorize another attempt.
type ResetCompleteResult struct {
	CommandID         identity.CommandID
	Outcome           identity.CommitOutcome
	CredentialVersion uint64
	SessionsRevoked   bool
}

// Validate checks coupled receipt shape only, never durable commitment evidence.
func (r ResetCompleteResult) Validate() error {
	if !validResetOutcome(r.CommandID, r.Outcome) {
		return ErrPasswordWork
	}
	if r.Outcome == identity.CommitOutcomeCommitted {
		if r.CredentialVersion < 2 || !r.SessionsRevoked {
			return ErrPasswordWork
		}
	} else if r.CredentialVersion != 0 || r.SessionsRevoked {
		return ErrPasswordWork
	}
	return nil
}

func validResetOutcome(command identity.CommandID, outcome identity.CommitOutcome) bool {
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		return false
	}
	switch outcome {
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress:
		return true
	default:
		return false
	}
}

// ResetService is the platform-owned request/completion workflow port, not an
// application-written callback/store. Implementations must compose the real
// issuer, encrypted delivery, current factor/credential owners, risk/HIBP and
// atomic one-use/session effects. Request acknowledges suppressed selections
// identically, with no bearer disclosure. Completion requires explicit user
// confirmation; scanner validation never calls it. Recovery uses no password
// or proof, checks current scoped result-access policy and retained original
// custody, and never issues a replacement token, password or session.
// Methods honor bounded contexts, preserve cancellation and commit ambiguity,
// and support concurrent independent requests under borrowed dependency contracts.
// This interface's existence is not a claim that native orchestration is ready.
type ResetService interface {
	ResetRequest(context.Context, ResetRequestRequest) (ResetRequestResult, error)
	ResetComplete(context.Context, ResetCompleteRequest) (ResetCompleteResult, error)
	RecoverResetRequest(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (ResetRequestResult, error)
	RecoverResetComplete(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (ResetCompleteResult, error)
}

// Format redacts reset input including malformed values.
func (ResetRequestRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ResetRequestRequest(redacted)")
}

// MarshalJSON rejects implicit input export; the opt-in HTTP owner owns wire schemas.
func (ResetRequestRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text/map-key disclosure.
func (ResetRequestRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a constant redacted marker.
func (ResetRequestRequest) LogValue() slog.Value {
	return slog.StringValue("password.ResetRequestRequest(redacted)")
}

// Format redacts reset proof and password input for every diagnostic verb.
func (ResetCompleteRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ResetCompleteRequest(redacted)")
}

// MarshalJSON rejects implicit export of borrowed secrets and proof custody.
func (ResetCompleteRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text/map-key disclosure.
func (ResetCompleteRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a constant redacted marker.
func (ResetCompleteRequest) LogValue() slog.Value {
	return slog.StringValue("password.ResetCompleteRequest(redacted)")
}
