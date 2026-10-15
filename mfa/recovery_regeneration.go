package mfa

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RecoveryRegenerateRequest borrows a current session and a separately verified
// active-factor proof for one exact action. FactorProof is only the public
// projection: the native owner must authenticate its original issuance, source
// session/version, factor, authority generation and exclusive freshness, then
// consume it atomically with the replacement. Neither an MFA session nor a
// recovery-code login grants this proof. Set identity, count, key and epoch are
// selected by the native owner, never supplied as replacement authority here.
// Inputs must remain immutable while concurrent calls are in flight.
type RecoveryRegenerateRequest struct {
	TenantID    identity.TenantID
	CommandID   identity.CommandID
	FactorProof auth.Proof
	Session     auth.BearerCredential
	// Cookie transports require the exact session synchronizer and Origin;
	// zero CSRFToken is permitted only for an explicitly selected bearer profile.
	CSRFToken session.CSRFToken
	Caller    authorization.DecisionContext
	Origin    string
	Network   string
}

// Validate checks bounded structure and exact caller/subject/action scope only.
// It performs no IO, clock read, signature validation, proof consumption or code
// generation. Historical input may remain structurally valid after expiry;
// native fresh admission and metadata-only recovery are separate operations.
// Eligible methods are enrolled TOTP, OTP or security keys. A configured native
// profile must independently reject methods it does not implement or allow.
func (r RecoveryRegenerateRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_recovery_regenerate"} }
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return bad()
	}
	p := r.FactorProof
	if _, err := auth.NewProof(auth.ProofSpec(p)); err != nil || p.Purpose != "identity.mfa.recovery-regenerate" || !eligibleFreshFactorProof(p) {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(p.ID)); err != nil || string(p.ID) == string(r.CommandID) {
		return bad()
	}
	request := r.Caller.Request
	if r.Caller.Validate() != nil || r.Caller.PolicyRevision == 0 || request.Tenant != authorization.TenantID(r.TenantID) || request.Subject.Kind != authorization.SubjectUser || request.Action != "identity.mfa.recovery-regenerate" || request.Resource.Type != "identity.user" || request.Resource.ID != authorization.ResourceID(request.Subject.ID) || p.Tenant != string(r.TenantID) || p.Subject != string(request.Subject.ID) {
		return bad()
	}
	if _, err := identity.ParseIdentifierID(string(request.Subject.ID)); err != nil {
		return bad()
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return bad()
	}
	origin, err := url.Parse(r.Origin)
	if err != nil || len(r.Origin) > 2048 || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Opaque != "" || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.RawFragment != "" || origin.String() != r.Origin {
		return bad()
	}
	if len(r.Network) > 255 || net.ParseIP(r.Network) == nil {
		return bad()
	}
	return nil
}

// RecoveryRegenerateResult separates historical outcome from reveal-once
// replacement material. Only the original error-free known commit may carry
// RecoveryCodes. Replay, recovery, cancellation and ambiguity carry none, even
// when the replacement committed. Destroy each returned Secret immediately
// after explicit delivery; copies share destruction. No result issues a session.
type RecoveryRegenerateResult struct {
	CommandID     identity.CommandID
	Outcome       identity.CommitOutcome
	RecoveryCodes RevealOnceCodes
}

// RecoveryRegenerationService is the narrow replacement workflow port. The
// native implementation owns proof provenance/use, current session/factor/risk
// checks, original encrypted preparation, whole-set retirement/replacement,
// required session/lifecycle/audit effects and protected transaction recovery.
// Consumers provide configuration, not missing domain stores or handlers.
// Recovery requires only original non-secret query scope and current access
// policy; it cannot generate, reveal or repeat factor verification.
type RecoveryRegenerationService interface {
	RecoveryRegenerate(context.Context, RecoveryRegenerateRequest) (RecoveryRegenerateResult, error)
	RecoverRecoveryRegenerate(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (RecoveryRegenerateResult, error)
}

// Format prevents diagnostic traversal of session and proof custody.
func (RecoveryRegenerateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.RecoveryRegenerateRequest(redacted)"))
}

// MarshalJSON rejects implicit credential export.
func (RecoveryRegenerateRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text and map-key export.
func (RecoveryRegenerateRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (RecoveryRegenerateRequest) LogValue() slog.Value {
	return slog.StringValue("mfa.RecoveryRegenerateRequest(redacted)")
}

// Format prevents diagnostic traversal of reveal-once material.
func (RecoveryRegenerateResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.RecoveryRegenerateResult(redacted)"))
}

// MarshalJSON rejects implicit reveal-once material export.
func (RecoveryRegenerateResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text and map-key export.
func (RecoveryRegenerateResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (RecoveryRegenerateResult) LogValue() slog.Value {
	return slog.StringValue("mfa.RecoveryRegenerateResult(redacted)")
}
