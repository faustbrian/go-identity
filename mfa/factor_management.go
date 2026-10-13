package mfa

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// FactorUpdateResult separates authoritative historical outcome from safe
// metadata disclosed after a fresh known commit. CommandID is the owner-derived
// original identity. Replay, recovery and errors may retain a known Outcome
// while carrying no Factor; they do not authorize another mutation or session.
type FactorUpdateResult struct {
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
	Factor    FactorProjection
}

// FactorManagementService owns protected self-management and metadata-only
// outcome recovery. Implementations must consume original factor proof and
// apply policy-compliant mutation, revocation and audit atomically. Consumers
// provide configuration, not transactions, factor stores or missing handlers.
type FactorManagementService interface {
	FactorUpdate(context.Context, FactorUpdateRequest) (FactorUpdateResult, error)
	RecoverFactorUpdate(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (FactorUpdateResult, error)
}

// FactorUpdateAction selects one exact management transition. Zero and unknown
// values deny; a native profile must separately reject unsupported actions.
type FactorUpdateAction uint8

const (
	// FactorUpdateActionUnspecified cannot select a mutation.
	FactorUpdateActionUnspecified FactorUpdateAction = iota
	// Rename changes only the safe presentation label, not factor credentials.
	Rename
	// Remove revokes the selected factor under the current recovery-path policy.
	Remove
	// Replace starts a replacement ceremony without treating an unconfirmed
	// replacement as an active factor or silently removing the predecessor.
	Replace
)

// FactorUpdateRequest borrows actual session and original purpose-bound fresh
// factor proof custody for an optimistic, keyed self-management operation.
// Caller/TenantID/Origin/Network require trusted transport provenance. The
// native owner must authenticate original issuance and exact source session,
// enforce recent primary authentication and current factor/recovery policy,
// and consume proof with the mutation and required revocation/audit effects.
// Validate grants no authority and performs no IO or proof use. Calls require
// immutable inputs; cookie transports must enforce original CSRF and Origin.
type FactorUpdateRequest struct {
	TenantID identity.TenantID
	// CommandID is absent on a fresh keyed call. If supplied on retry, the
	// native owner must compare it with the key's retained authoritative ID;
	// it must never let the caller choose or replace that command.
	CommandID       identity.CommandID
	FactorID        FactorID
	Action          FactorUpdateAction
	Name            string
	ExpectedVersion uint64
	FactorProof     auth.Proof
	Session         auth.BearerCredential
	CSRFToken       session.CSRFToken
	Caller          authorization.DecisionContext
	Origin          string
	Network         string
	IdempotencyKey  identity.IdempotencyKey
}

// Validate checks intrinsic bounds, a closed action and exact self/action
// bindings without renewing original freshness. Rename accepts an empty label
// to clear optional presentation metadata; Remove/Replace forbid Name. A
// positive non-exhausted expected version is required even for historical
// requests. Historical recovery never requires reusable credential custody.
func (r FactorUpdateRequest) Validate() error {
	return r.validateFor("identity.mfa.factor-update")
}

// validateFor shares intrinsic custody bounds, never authentication, between
// the two closed public operations. Actual signed purpose is not rewritten.
func (r FactorUpdateRequest) validateFor(operation string) error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_factor_update"} }
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return bad()
	}
	if r.CommandID != "" {
		if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
			return bad()
		}
	}
	if _, err := identity.ParseCommandID(string(r.FactorID)); err != nil {
		return bad()
	}
	if r.ExpectedVersion == 0 || r.ExpectedVersion == math.MaxUint64 || r.IdempotencyKey == (identity.IdempotencyKey{}) || !listLabel(r.Name) {
		return bad()
	}
	switch r.Action {
	case Rename:
	case Remove, Replace:
		if r.Name != "" {
			return bad()
		}
	default:
		return bad()
	}
	p := r.FactorProof
	if _, err := auth.NewProof(auth.ProofSpec(p)); err != nil || string(p.Purpose) != operation || !eligibleFreshFactorProof(p) {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(p.ID)); err != nil || string(p.ID) == string(r.CommandID) {
		return bad()
	}
	request := r.Caller.Request
	if r.Caller.Validate() != nil || r.Caller.PolicyRevision == 0 || request.Tenant != authorization.TenantID(r.TenantID) || request.Subject.Kind != authorization.SubjectUser || string(request.Action) != operation || request.Resource.Type != "identity.user" || request.Resource.ID != authorization.ResourceID(request.Subject.ID) || p.Tenant != string(r.TenantID) || p.Subject != string(request.Subject.ID) {
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

// Format prevents diagnostic traversal of borrowed credentials and labels.
func (FactorUpdateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.FactorUpdateRequest(redacted)"))
}

// MarshalJSON rejects implicit credential and request-key export.
func (FactorUpdateRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text/map-key credential export.
func (FactorUpdateRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redaction marker.
func (FactorUpdateRequest) LogValue() slog.Value {
	return slog.StringValue("mfa.FactorUpdateRequest(redacted)")
}
