package mfa

import (
	"context"
	"fmt"
	"log/slog"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// FactorTarget is the closed disable scope. OneFactor requires FactorID;
// AllFactors forbids it. Neither zero nor an absent factor defaults to all.
type FactorTarget uint8

const (
	// FactorTargetUnspecified grants no mutation scope.
	FactorTargetUnspecified FactorTarget = iota
	// OneFactor disables only the identified factor under current policy.
	OneFactor
	// AllFactors disables the complete supported set under current policy.
	AllFactors
)

// DisableRequest borrows actual source-session custody and original fresh
// disable-purpose factor proof. The native owner derives optimistic generation
// from authenticated original proof custody, never today's inferred generation.
// Fresh keyed calls leave CommandID empty; retry may carry only the retained
// owner-derived identity. Caller/origin/network require trusted provenance.
// Inputs remain immutable for the call. Validate grants no authority or IO.
type DisableRequest struct {
	TenantID       identity.TenantID
	CommandID      identity.CommandID
	Target         FactorTarget
	FactorID       FactorID
	FactorProof    auth.Proof
	Session        auth.BearerCredential
	CSRFToken      session.CSRFToken
	Caller         authorization.DecisionContext
	Origin         string
	Network        string
	IdempotencyKey identity.IdempotencyKey
}

// Validate requires explicit target and exact self/action/proof bindings.
// Protected owners must still verify signed original issuance, recent primary
// authentication, current generation and viable recovery in the transaction.
func (r DisableRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_disable"} }
	factor := r.FactorID
	switch r.Target {
	case OneFactor:
		if _, err := identity.ParseCommandID(string(factor)); err != nil {
			return bad()
		}
	case AllFactors:
		if factor != "" {
			return bad()
		}
		// Structural placeholder only: the native owner discovers the exact
		// supported set under current authority; this is not a selected factor.
		factor = FactorID(r.FactorProof.ID)
	default:
		return bad()
	}
	common := FactorUpdateRequest{TenantID: r.TenantID, CommandID: r.CommandID,
		FactorID: factor, Action: Remove, ExpectedVersion: 1,
		FactorProof: r.FactorProof, Session: r.Session, CSRFToken: r.CSRFToken,
		Caller: r.Caller, Origin: r.Origin, Network: r.Network, IdempotencyKey: r.IdempotencyKey}
	if common.validateFor("identity.mfa.disable") != nil {
		return bad()
	}
	return nil
}

// DisableResult returns safe remaining factors only after a fresh known commit.
// Historical replay/recovery, unknown outcomes and errors return no projections.
// A known empty set is an allocated empty slice, not an unavailable nil result.
type DisableResult struct {
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
	Factors   []FactorProjection
}

// DisableService owns explicit protected disable and credential-free outcome
// recovery. Proof use, required factor/code/device/session invalidation and
// audit must commit atomically; no replacement secret or session may be issued.
type DisableService interface {
	Disable(context.Context, DisableRequest) (DisableResult, error)
	RecoverDisable(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (DisableResult, error)
}

// Format prevents traversal of borrowed credentials and private identifiers.
func (DisableRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.DisableRequest(redacted)"))
}

// MarshalJSON refuses implicit credential or request-key export.
func (DisableRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText refuses implicit text/map-key credential export.
func (DisableRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue exposes only the fixed redaction marker.
func (DisableRequest) LogValue() slog.Value { return slog.StringValue("mfa.DisableRequest(redacted)") }
