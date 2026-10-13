package mfapostgres

import (
	"context"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// DisablePrimarySource authenticates real current source-session/CSRF custody
// and restores only MFA-authenticated original input. It cannot renew primary
// authentication or supply factor proof/recovery authority. Borrowed owners
// must be concurrency-safe and retain neither credentials nor protected Work.
type DisablePrimarySource interface {
	PrepareDisable(context.Context, mfa.DisableRequest, identity.CommandID) (TOTPActivePrimary, session.GetResult, error)
	RestoreDisable(context.Context, mfa.DisableRequest, identity.CommandID, []byte) (TOTPActivePrimary, error)
}

// DisableConfig selects the current native sole-TOTP/email-reset profile.
// One/all scopes are distinct immutable intents. Additional active factor
// methods/counts deny rather than silently being skipped. RecoveryPath must be
// Email and Recovery must borrow the actual selected reset request/completion
// owner. Both maximum ages are positive and at most five minutes.
type DisableConfig struct {
	Primary                       DisablePrimarySource
	Sessions                      RecoveryRegenerationSessionEffects
	RecoveryPath                  auth.RecoveryPath
	Recovery                      FactorRemovalRecoverySource
	MaximumAge, PrimaryMaximumAge time.Duration
}

// DisableService owns disable-purpose proof consumption and protected native
// factor/code/session invalidation through the existing coordinator. It creates
// no private transaction, proof journal, replacement credential or goroutine.
type DisableService struct{ mutation *FactorUpdateService }

// NewDisableService freezes explicit native disable without IO. Install the
// forward disable MFA/session migrations after the existing histories. The
// enrollment and proof issuer must share exact authority and original custody.
func NewDisableService(enrollment *TOTPEnrollmentService, stepup *TOTPActiveStepUpService, c DisableConfig) (*DisableService, error) {
	if nilEnrollmentPrimary(c.Primary) || c.RecoveryPath != auth.RecoveryPathEmail || nilEnrollmentPrimary(c.Recovery) {
		return nil, invalidAuthority()
	}
	s, err := newFactorMutationService(enrollment, stepup, FactorUpdateConfig{
		Sessions: c.Sessions, MaximumAge: c.MaximumAge, PrimaryMaximumAge: c.PrimaryMaximumAge,
		RemovalRecoveryPath: c.RecoveryPath, RemovalRecovery: c.Recovery}, disableOperation(), c.Primary)
	if err != nil {
		return nil, err
	}
	return &DisableService{mutation: s}, nil
}

func disableOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.disable", SchemaID: "mfa-disable", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Disable requires original signed disable proof and recent primary custody.
// A fresh committed result exposes safe remaining unexpired pending factors;
// all-target returns an empty set after erasing pending siblings. The profile
// supports only one active TOTP. Errors/unknown/replay expose no projections or
// new credentials.
func (s *DisableService) Disable(ctx context.Context, r mfa.DisableRequest) (out mfa.DisableResult, err error) {
	if ctx == nil || s == nil || s.mutation == nil || s.mutation.state == nil || r.Validate() != nil {
		return out, invalidAuthority()
	}
	state := s.mutation.state()
	if state == nil || state.operation != disableOperation() {
		return out, invalidAuthority()
	}
	request := mfa.FactorUpdateRequest{TenantID: r.TenantID, CommandID: r.CommandID,
		FactorID: r.FactorID, Action: mfa.Remove, FactorProof: r.FactorProof,
		Session: r.Session, CSRFToken: r.CSRFToken, Caller: r.Caller, Origin: r.Origin,
		Network: r.Network, IdempotencyKey: r.IdempotencyKey}
	p := &factorUpdatePhase{state: state, request: request, disable: &r}
	result, err := s.mutation.executeFactorMutation(ctx, p)
	out.CommandID, out.Outcome = result.CommandID, result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted && result.Factor.ID != "" {
		out.Factors = p.remaining
	}
	return out, err
}

// RecoverDisable reads the retained original outcome under current access
// policy without replaying proof use or rechecking today's recovery eligibility.
func (s *DisableService) RecoverDisable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.DisableResult, err error) {
	if ctx == nil || s == nil || s.mutation == nil || q.OperationID != disableOperation().OperationID {
		return out, invalidAuthority()
	}
	r, err := s.mutation.RecoverFactorUpdate(ctx, q, caller)
	out.CommandID, out.Outcome = r.CommandID, r.Outcome
	return out, err
}

// Format prevents implicit borrowed configuration traversal.
func (DisableConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.DisableConfig(redacted)"))
}

// MarshalJSON rejects implicit native policy/owner export.
func (DisableConfig) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit text/map-key policy export.
func (DisableConfig) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

var _ mfa.DisableService = (*DisableService)(nil)
