// Package magiclink owns purpose-bound passwordless email workflows. Scanner
// inspection authenticates signed scope only; explicit protected transactions
// remain responsible for current authority and atomic login effects.
package magiclink

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

// Intent is the original closed issuance intent. Consumption cannot reinterpret it.
type Intent uint8

const (
	// IntentUnspecified never authorizes issuance or inspection.
	IntentUnspecified Intent = iota
	// SignInOnly forbids creating an account through this link.
	SignInOnly
	// SignupIfAllowed requires authoritative signup policy at the protected mutation.
	SignupIfAllowed
)

// InspectionCode classifies redacted inspection failures, not account existence.
type InspectionCode uint8

const (
	// InspectionInvalid denotes malformed input or configuration.
	InspectionInvalid InspectionCode = iota + 1
	// InspectionDenied denotes a signature, scope or revocation denial.
	InspectionDenied
	// InspectionExpired denotes expiry of an authenticated upstream token.
	InspectionExpired
	// InspectionUnavailable denotes unavailable verification authority.
	InspectionUnavailable
)

// InspectionError contains no token, recipient, callback or upstream diagnostic.
// Cancellation is returned separately as the original context error.
type InspectionError struct{ Code InspectionCode }

// Error returns only the stable closed classification.
func (e InspectionError) Error() string {
	switch e.Code {
	case InspectionInvalid:
		return "magiclink: invalid inspection"
	case InspectionDenied:
		return "magiclink: inspection denied"
	case InspectionExpired:
		return "magiclink: link expired"
	default:
		return "magiclink: inspection unavailable"
	}
}

// ProofVerifier is the read-only upstream signature/time/revocation boundary.
// Use capability.Service; this port deliberately exposes no issuing, reservation,
// transfer or consumption operation. Collaborators must honor deadlines and be
// concurrent-safe. The inspector never closes caller-owned dependencies.
type ProofVerifier interface {
	Verify(context.Context, capability.Proof, capability.Purpose, string) (capability.Grant, error)
}

// InspectionConfig is a trusted immutable issuer/tenant/profile selection.
// Callbacks are exact original HTTPS strings, not normalized URL equivalents.
// MaximumLifetime must be positive and at most 24h; Timeout at most one minute.
// Configure the upstream verifier's key and revocation policy explicitly.
type InspectionConfig struct {
	Verifier                 ProofVerifier
	Tenant, Issuer, Audience string
	Callbacks                []string
	MaximumLifetime, Timeout time.Duration
}

// Format prevents caller-owned composition internals from entering diagnostics.
func (InspectionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclink.InspectionConfig(redacted)"))
}

// MarshalJSON denies implicit export of the verification composition.
func (InspectionConfig) MarshalJSON() ([]byte, error) { return nil, InspectionError{InspectionInvalid} }

// MarshalText denies implicit textual export of the verification composition.
func (InspectionConfig) MarshalText() ([]byte, error) { return nil, InspectionError{InspectionInvalid} }

// Inspector authenticates signed scope without making a current usability claim.
// It owns a cloned policy snapshot and no mutable state or goroutines.
type Inspector struct{ config InspectionConfig }

// NewInspector validates locally without callbacks, IO or clock sampling.
// It snapshots allowlists; zero configuration is invalid.
func NewInspector(c InspectionConfig) (*Inspector, error) {
	if c.Verifier == nil || !boundedText(c.Tenant, 128) || !httpsURL(c.Issuer) || !boundedText(c.Audience, 256) || len(c.Callbacks) == 0 || len(c.Callbacks) > 64 || c.MaximumLifetime <= 0 || c.MaximumLifetime > 24*time.Hour || c.Timeout <= 0 || c.Timeout > time.Minute {
		return nil, InspectionError{InspectionInvalid}
	}
	for _, callback := range c.Callbacks {
		if !httpsURL(callback) {
			return nil, InspectionError{InspectionInvalid}
		}
	}
	c.Callbacks = slices.Clone(c.Callbacks)
	return &Inspector{config: c}, nil
}

// InspectionRequest borrows the opaque proof without transferring or destroying
// it. Callback is the exact requested callback, never a URL carrying the token.
// The trusted tenant comes from construction, not untrusted request data.
type InspectionRequest struct {
	Token    capability.Proof
	Callback string
}

// Format prevents implicit proof/callback projection into diagnostics.
func (InspectionRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclink.InspectionRequest(redacted)"))
}

// MarshalJSON prevents accidental export of sensitive request data.
func (InspectionRequest) MarshalJSON() ([]byte, error) {
	return nil, InspectionError{InspectionInvalid}
}

// MarshalText prevents implicit text serialization of sensitive request data.
func (InspectionRequest) MarshalText() ([]byte, error) {
	return nil, InspectionError{InspectionInvalid}
}

// InspectionResult exposes signed-profile information only. SignatureValid
// never means unconsumed, nonsuperseded, account eligible, risk admitted or logged
// in. A consumed link may still have a valid signature. No recipient, user,
// envelope, capability ID or session is returned. Explicit Consume must repeat
// verification and all authoritative checks in its protected transaction.
type InspectionResult struct {
	SignatureValid bool
	Intent         Intent
}

// Inspect is scanner-safe: no reservation, consumption, issuance, proof transfer,
// session or identity mutation occurs. Earlier caller deadlines win. Only the
// upstream verifier may read its configured revocation authority. Its panic or
// unavailable authority fails closed with a zero result and redacted error.
func (i *Inspector) Inspect(ctx context.Context, r InspectionRequest) (out InspectionResult, err error) {
	if i == nil || ctx == nil || r.Token.ValidateBounds(32, 4096) != nil || !httpsURL(r.Callback) {
		return out, InspectionError{InspectionInvalid}
	}
	ctx, cancel := context.WithTimeout(ctx, i.config.Timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out = InspectionResult{}
			err = InspectionError{InspectionUnavailable}
		}
		if ctx.Err() != nil {
			out = InspectionResult{}
			err = ctx.Err()
		}
	}()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if !slices.Contains(i.config.Callbacks, r.Callback) {
		return out, InspectionError{InspectionDenied}
	}
	grant, err := i.config.Verifier.Verify(ctx, r.Token, "identity.magic-link.consume", i.config.Audience)
	if err != nil {
		code := InspectionUnavailable
		switch {
		case errors.Is(err, capability.ErrExpired):
			code = InspectionExpired
		case errors.Is(err, capability.ErrInvalidToken), errors.Is(err, capability.ErrInvalidPayload), errors.Is(err, capability.ErrNonCanonical), errors.Is(err, capability.ErrInvalidSignature), errors.Is(err, capability.ErrUnauthorized), errors.Is(err, capability.ErrRevoked), errors.Is(err, capability.ErrKeyRevoked), errors.Is(err, capability.ErrKeyDisabled), errors.Is(err, capability.ErrKeyNotActive), errors.Is(err, capability.ErrUnknownKey), errors.Is(err, capability.ErrAlgorithmMismatch), errors.Is(err, capability.ErrNotYetValid):
			code = InspectionDenied
		}
		return out, InspectionError{code}
	}
	p := grant.Payload()
	if grant.EnvelopeDigest() == ([32]byte{}) || p.Version != 1 || p.Tenant != i.config.Tenant || p.Issuer != i.config.Issuer || p.Operation != "identity.magic-link.consume" || p.Bearer || !boundedText(p.Subject, 128) || !boundedText(p.CorrelationID, 128) || p.MaxUses != 1 || len(p.Audiences) != 1 || p.Audiences[0] != i.config.Audience || !boundedText(p.Caveats["magiclink.identifier"], 128) || p.Resource != "identity.magiclink/"+p.Caveats["magiclink.identifier"] || p.Caveats["magiclink.callback"] != r.Callback || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > i.config.MaximumLifetime {
		return out, InspectionError{InspectionDenied}
	}
	switch p.Caveats["magiclink.intent"] {
	case "signin-only":
		out.Intent = SignInOnly
	case "signup-if-allowed":
		out.Intent = SignupIfAllowed
	default:
		return InspectionResult{}, InspectionError{InspectionDenied}
	}
	out.SignatureValid = true
	return out, nil
}

func boundedText(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func httpsURL(s string) bool {
	if !boundedText(s, 2048) || strings.Contains(s, "#") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}
