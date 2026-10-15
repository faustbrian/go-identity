package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// RecoveryRegenerationPrimarySource supplies actual current session/cookie
// custody for replacement, not a fabricated TOTP or login request. Restoration
// accepts only MFA-envelope-authenticated original snapshot bytes. Current
// owner checks and proof consumption remain protected transaction work.
type RecoveryRegenerationPrimarySource interface {
	PrepareRegeneration(context.Context, mfa.RecoveryRegenerateRequest) (TOTPActivePrimary, session.GetResult, error)
	RestoreRegeneration(context.Context, mfa.RecoveryRegenerateRequest, []byte) (TOTPActivePrimary, error)
}

// RecoveryRegenerationSessionEffects is the session owner's enlisted bounded
// disposition contract. Apply revokes affected subject sessions and retains
// exact command-bound evidence in the same Work. Check validates the original
// source's intentional revocation and primary authority, not continuing access.
// Recover reads only that owner's durable effect evidence. No callback may open
// a transaction, retain Work, reveal credentials or perform external IO.
type RecoveryRegenerationSessionEffects interface {
	Apply(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Recover(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error)
}

// RecoveryRegenerationConfig selects replacement count and fresh-proof policy
// at startup, not through the request. Count is 1..64; MaximumAge is positive
// and at most five minutes. The real session adapter owns all session writes.
// Digest/envelope/risk/coordinator custody comes from the borrowed enrollment
// graph; original factor signing trust comes from the selected step-up service.
type RecoveryRegenerationConfig struct {
	Primary    RecoveryRegenerationPrimarySource
	Sessions   RecoveryRegenerationSessionEffects
	CodeCount  uint32
	MaximumAge time.Duration
}

// RecoveryRegenerationService replaces all predecessor recovery sets atomically
// with one fresh factor proof use, factor-authority advancement, session effects,
// audit and lifecycle. It owns no goroutines, private transaction or journal.
// Only a fresh known commit can return replacement material, exactly once.
type RecoveryRegenerationService struct {
	state func() *recoveryRegenerationState
}
type recoveryRegenerationState struct {
	shared    *totpEnrollmentState
	stepup    *activeStepUpState
	config    RecoveryRegenerationConfig
	source    *FactorVerificationSource
	validator *auth.AuthorityAuthenticator
	identity  [32]byte
}

// This private source selects only original reauthentication validation. It
// never grants access-token or permanent-authentication authority; unrelated
// interface methods fail closed. Authentication keeps signature/projection/time
// validation ownership, while native Work owns current state and atomic use.
type factorReauthenticationOnlySource struct{ *FactorVerificationSource }

func (factorReauthenticationOnlySource) CurrentValidity(context.Context, auth.ValidityRequest) (auth.SignedValidityEvidence, error) {
	return auth.SignedValidityEvidence{}, auth.ErrInvalidProof
}
func (factorReauthenticationOnlySource) PermanentAuthentication(context.Context, auth.ProofID) (auth.SignedAuthenticationRecord, error) {
	return auth.SignedAuthenticationRecord{}, auth.ErrInvalidProof
}

// NewRecoveryRegenerationService freezes complete native composition without
// IO or entropy. The selected signing-trust ring must fit authentication's
// 32-key bound. Install the factor evidence and selected session-effect histories.
func NewRecoveryRegenerationService(enrollment *TOTPEnrollmentService, stepup *TOTPActiveStepUpService, c RecoveryRegenerationConfig) (*RecoveryRegenerationService, error) {
	if enrollment == nil || enrollment.state == nil || stepup == nil || stepup.state == nil || nilEnrollmentPrimary(c.Primary) || nilEnrollmentPrimary(c.Sessions) || c.CodeCount < 1 || c.CodeCount > 64 || c.MaximumAge <= 0 || c.MaximumAge > 5*time.Minute {
		return nil, invalidAuthority()
	}
	s := &recoveryRegenerationState{shared: enrollment.state(), stepup: stepup.state(), config: c}
	if s.stepup.shared != s.shared || len(s.stepup.config.VerificationKeys) > 32 {
		return nil, invalidAuthority()
	}
	var err error
	s.source, err = NewFactorVerificationSource(s.shared.pool, s.shared.config.MaximumDuration)
	if err != nil {
		return nil, err
	}
	keys := make([]auth.AuthorityKey, 0, len(s.stepup.config.VerificationKeys))
	for id, key := range s.stepup.config.VerificationKeys {
		keys = append(keys, auth.AuthorityKey{ID: id, PublicKey: key})
	}
	s.validator, err = auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: s.stepup.config.Issuer, Environment: s.stepup.config.Environment, Audience: s.stepup.config.Audience, Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: keys, EvidenceKeys: keys, Source: factorReauthenticationOnlySource{s.source}, Clock: s.shared.config.Coordinator.QueryPolicy.Clock, ReadTimeout: s.shared.config.MaximumDuration, ClockUncertainty: time.Millisecond, MaximumDelegationDepth: 1})
	if err != nil {
		return nil, invalidAuthority()
	}
	admitted, err := s.shared.config.Counters.CommandCounters.Policy.Admit("identity.mfa.recovery-regenerate")
	if err != nil || admitted.Profile.Class != risk.CredentialMutation {
		return nil, invalidAuthority()
	}
	frame, err := json.Marshal(struct {
		Shared, StepUp [32]byte
		Count          uint32
		Age            time.Duration
	}{s.shared.identity, s.stepup.identity, c.CodeCount, c.MaximumAge})
	if err != nil {
		return nil, invalidAuthority()
	}
	s.identity = sha256.Sum256(frame)
	clear(frame)
	return &RecoveryRegenerationService{state: func() *recoveryRegenerationState { return s }}, nil
}

func recoveryRegenerationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.recovery-regenerate", SchemaID: "mfa-recovery-regenerate", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (s *recoveryRegenerationState) intent(r mfa.RecoveryRegenerateRequest) ([32]byte, error) {
	wire, err := json.Marshal(struct {
		Tenant, User, Command, Origin, Network string
		Proof                                  auth.Proof
	}{string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.CommandID), r.Origin, r.Network, r.FactorProof})
	if err != nil {
		return [32]byte{}, invalidAuthority()
	}
	defer clear(wire)
	key := s.shared.config.intentKey()
	defer clear(key[:])
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("mfa-recovery-regenerate-input-v1\x00"))
	_, _ = mac.Write(wire)
	_, _ = mac.Write([]byte(r.Session.Token()))
	_, _ = mac.Write(s.identity[:])
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest, nil
}

// RecoveryRegenerate validates genuine original factor evidence and current
// session/CSRF, generates retained encrypted replacement material outside SQL,
// then atomically consumes the proof and replaces all sets in native Work.
// Retries reuse original preparation; ambiguity and historical outcomes carry
// no plaintext. All returned Secret owners must be destroyed after delivery.
func (s *RecoveryRegenerationService) RecoveryRegenerate(ctx context.Context, r mfa.RecoveryRegenerateRequest) (out mfa.RecoveryRegenerateResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidAuthority()
	}
	out.CommandID = r.CommandID
	state := s.state()
	if !slices.Contains(state.stepup.config.AllowedOrigins, r.Origin) || r.FactorProof.Method != "totp" {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	p := &recoveryRegenerationPhase{state: state, request: r}
	defer p.destroy()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			for _, code := range out.RecoveryCodes.Codes {
				code.Destroy()
			}
			out.RecoveryCodes = mfa.RevealOnceCodes{}
		}
	}()
	p.coordinator, p.registry, err = state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	if err = authorizeNativeMFAAction(ctx, state.shared, r.Caller, "identity.mfa.recovery-regenerate"); err != nil {
		return out, err
	}
	if err = p.load(ctx); err != nil {
		return out, err
	}
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	run, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	out.Outcome = run.Outcome
	if err == nil && run.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.RecoveryCodes, err = p.delivery(ctx)
	}
	return out, err
}

// RecoverRecoveryRegenerate resolves code/proof-free historical outcome under
// current access policy. It cannot recreate or redeliver replacement material.
func (s *RecoveryRegenerationService) RecoverRecoveryRegenerate(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.RecoveryRegenerateResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != recoveryRegenerationOperation().OperationID {
		return out, invalidAuthority()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	if q.RecordID == "" {
		q.RecordID = string(q.UserID)
	}
	p := &recoveryRegenerationPhase{state: state}
	c, _, err := state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	result, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.CommandID = q.CommandID
	out.Outcome = result.Outcome
	return out, err
}

// Format redacts borrowed current-authority ownership.
func (RecoveryRegenerationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.RecoveryRegenerationConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (RecoveryRegenerationConfig) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit configuration export.
func (RecoveryRegenerationConfig) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format redacts native runtime ownership.
func (RecoveryRegenerationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.RecoveryRegenerationService(redacted)"))
}

// MarshalJSON rejects implicit service export.
func (RecoveryRegenerationService) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit service export.
func (RecoveryRegenerationService) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

var _ mfa.RecoveryRegenerationService = (*RecoveryRegenerationService)(nil)
