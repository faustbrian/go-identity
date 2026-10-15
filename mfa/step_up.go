package mfa

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// TOTPAuthenticatedStepUp borrows the current authenticated browser session and
// synchronizer for active-factor verification. It creates no login continuation
// or trusted-device bypass. The purpose selects exactly recovery-code
// regeneration, factor update or MFA disable. These actions are not
// interchangeable: the native owner must verify current session/primary/factor
// authority, current policy/risk, the submitted TOTP and replay advancement in
// the transaction that persists original signed proof evidence. Zero denies.
type TOTPAuthenticatedStepUp struct {
	Session   auth.BearerCredential
	CSRFToken session.CSRFToken
	Purpose   auth.Purpose
}

func (r TotpVerifyRequest) validateAuthenticatedStepUp() error {
	if r.Enrollment != nil || r.TrustDevice || !factorManagementPurpose(r.StepUp.Purpose) {
		return identity.InvalidInputError{Field: "mfa_totp_verify"}
	}
	return r.validateAuthenticatedTOTPCustody(r.StepUp.Session, r.StepUp.CSRFToken)
}

func factorManagementPurpose(p auth.Purpose) bool {
	switch p {
	case "identity.mfa.recovery-regenerate", "identity.mfa.factor-update", "identity.mfa.disable":
		return true
	default:
		return false
	}
}

// ContinuationProof is an immutable, non-secret projection of fresh factor
// verification for one exact source session/version and protected action. It
// is not a login continuation, signed bearer, current authority or possession
// proof. Construction never authenticates the projection. Native consumers
// must authenticate original signed issuance, fence current session/factor
// generations and consume its one-use record atomically with their mutation.
// Zero denies; copies and Bindings values cannot change retained original data.
type ContinuationProof struct {
	original func() auth.ReauthenticationProof
}

// NewContinuationProof copies structurally valid eligible-factor metadata.
// It uses the original issuance time only for intrinsic validation, not a new
// clock or renewed deadline. It performs no IO, signature check or consumption.
// The action must equal the proof's exact purpose; recovery codes, primary
// passwords and single-factor projections cannot supply an active factor proof.
func NewContinuationProof(p auth.ReauthenticationProof) (ContinuationProof, error) {
	bad := func() (ContinuationProof, error) {
		return ContinuationProof{}, identity.InvalidInputError{Field: "mfa_step_up_proof"}
	}
	proof, err := auth.NewProof(auth.ProofSpec(p.Proof))
	if err != nil || !eligibleFreshFactorProof(proof) || p.Action != string(proof.Purpose) {
		return bad()
	}
	p.Proof = proof
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: proof.Tenant, Subject: proof.Subject, Purpose: proof.Purpose, Audience: proof.Audience, Now: proof.IssuedAt}, SessionID: p.SessionID, SessionVersion: p.SessionVersion, Action: p.Action, MaximumAge: 24 * time.Hour}
	if p.Validate(use) != nil {
		return bad()
	}
	p.SessionID, p.Action = strings.Clone(p.SessionID), strings.Clone(p.Action)
	return ContinuationProof{original: func() auth.ReauthenticationProof { return p }}, nil
}

// Bindings returns an independently owned scalar projection, never evidence
// that verification or consumption committed. Zero returns an empty projection.
func (p ContinuationProof) Bindings() auth.ReauthenticationProof {
	if p.original == nil {
		return auth.ReauthenticationProof{}
	}
	return p.original()
}

func eligibleFreshFactorProof(p auth.Proof) bool {
	return p.Assurance.AtLeast(auth.AssuranceMultiFactor) && (p.Method == "totp" || p.Method == "otp" || p.Method == "security-key")
}

// Format prevents diagnostic traversal of original session/proof metadata.
func (ContinuationProof) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.ContinuationProof(redacted)"))
}

// MarshalJSON rejects implicit proof export; native transport owns delivery.
func (ContinuationProof) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text and map-key export.
func (ContinuationProof) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (ContinuationProof) LogValue() slog.Value {
	return slog.StringValue("mfa.ContinuationProof(redacted)")
}

// Format prevents diagnostic traversal of borrowed browser custody.
func (TOTPAuthenticatedStepUp) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.TOTPAuthenticatedStepUp(redacted)"))
}

// MarshalJSON rejects implicit credential export.
func (TOTPAuthenticatedStepUp) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text and map-key export.
func (TOTPAuthenticatedStepUp) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (TOTPAuthenticatedStepUp) LogValue() slog.Value {
	return slog.StringValue("mfa.TOTPAuthenticatedStepUp(redacted)")
}
