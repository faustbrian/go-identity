package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// ResetInspectRequest borrows an emailed-reset proof for read-only inspection.
// Tenant, caller and origin require trusted transport provenance. An omitted
// caller resource ID is resolved only from authenticated original issuance;
// an explicit ID must match. Inspection never transfers or consumes the proof.
// Keep caller collections immutable during the call and destroy the proof only
// afterward. No password, callback override or current-authority claim is input.
type ResetInspectRequest struct {
	TenantID identity.TenantID
	Token    capability.Proof
	Caller   authorization.DecisionContext
	Origin   string
}

// Validate checks bounded structure, not signatures or current eligibility.
func (r ResetInspectRequest) Validate() error {
	if r.Token.ValidateBounds(32, 4096) != nil || r.Caller.Validate() != nil || r.TenantID == "" || r.Caller.Request.Tenant != authorization.TenantID(r.TenantID) || r.Caller.Request.Action != "identity.password.reset-inspect" || r.Caller.Request.Resource.Type != "identity.user" || !resetHTTPS(r.Origin, 2048) {
		return ErrPasswordWork
	}
	return nil
}

// ResetInspectResult exposes only advisory valid/invalid UI state, not subject,
// credential, expiry, a reservation or a clearance for later completion. Valid
// means an unused issued proof and eligible current owners were observed within
// this call; concurrent changes may invalidate it immediately. Completion must
// repeat authoritative admission and consume atomically with its effects.
type ResetInspectResult struct{ Valid bool }

// ResetInspectionService is the additive read-only port, separate from the
// existing ResetService so its consumers and implementations remain compatible.
// Calls are bounded and concurrent-safe, perform no password work or mutation,
// return invalid state without subject disclosure, and return no positive result
// on unavailable authority, cancellation or unknown outcomes.
type ResetInspectionService interface {
	ResetInspect(context.Context, ResetInspectRequest) (ResetInspectResult, error)
}

// Format redacts every input projection, including malformed requests.
func (ResetInspectRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ResetInspectRequest(redacted)")
}

// MarshalJSON denies incidental proof/caller export; HTTP owns the wire schema.
func (ResetInspectRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies incidental textual proof/caller export.
func (ResetInspectRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a constant marker without secret or subject metadata.
func (ResetInspectRequest) LogValue() slog.Value {
	return slog.StringValue("password.ResetInspectRequest(redacted)")
}
