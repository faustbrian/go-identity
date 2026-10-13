package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// FactorUpdatePrimarySource authenticates actual current session/CSRF custody
// for the owner-derived keyed command. Restore accepts only input bytes already
// authenticated by MFA's original envelope. Neither operation verifies or uses
// a factor proof; protected current-state checks remain mandatory.
type FactorUpdatePrimarySource interface {
	PrepareFactorUpdate(context.Context, mfa.FactorUpdateRequest, identity.CommandID) (TOTPActivePrimary, session.GetResult, error)
	RestoreFactorUpdate(context.Context, mfa.FactorUpdateRequest, identity.CommandID, []byte) (TOTPActivePrimary, error)
}

// FactorUpdateConfig selects bounded primary/factor freshness and real enlisted
// session effects. Both ages are positive and at most five minutes. Primary and
// Sessions borrow native owners; they cannot open transactions or retain Work.
// The selected initial profile supports TOTP rename. Other actions fail closed
// until their recovery and replacement owners are composed.
type FactorUpdateConfig struct {
	Primary           FactorUpdatePrimarySource
	Sessions          RecoveryRegenerationSessionEffects
	MaximumAge        time.Duration
	PrimaryMaximumAge time.Duration
}

// FactorUpdateService owns keyed, optimistic native TOTP metadata management
// with original proof consumption, session revocation and lifecycle/audit.
// It borrows existing enrollment, step-up and coordinator owners and creates
// no private transaction, journal, authority, goroutine or generated credential.
type FactorUpdateService struct{ state func() *factorUpdateState }

type factorUpdateState struct {
	shared    *totpEnrollmentState
	stepup    *activeStepUpState
	config    FactorUpdateConfig
	source    *FactorVerificationSource
	validator *auth.AuthorityAuthenticator
	identity  [32]byte
}

// NewFactorUpdateService freezes native composition without IO. Enrollment and
// step-up must share their exact original owner. Install management metadata,
// proof-use and selected session-effect migrations before calls begin.
func NewFactorUpdateService(enrollment *TOTPEnrollmentService, stepup *TOTPActiveStepUpService, c FactorUpdateConfig) (*FactorUpdateService, error) {
	if enrollment == nil || enrollment.state == nil || stepup == nil || stepup.state == nil || nilEnrollmentPrimary(c.Primary) || nilEnrollmentPrimary(c.Sessions) || c.MaximumAge <= 0 || c.MaximumAge > 5*time.Minute || c.PrimaryMaximumAge <= 0 || c.PrimaryMaximumAge > 5*time.Minute {
		return nil, invalidAuthority()
	}
	s := &factorUpdateState{shared: enrollment.state(), stepup: stepup.state(), config: c}
	if s.shared == nil || s.stepup == nil || s.stepup.shared != s.shared || len(s.stepup.config.VerificationKeys) > 32 {
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
	admitted, err := s.shared.config.Counters.CommandCounters.Policy.Admit("identity.mfa.factor-update")
	if err != nil || admitted.Profile.Class != risk.CredentialMutation {
		return nil, invalidAuthority()
	}
	frame, err := json.Marshal(struct {
		Shared, StepUp        [32]byte
		FactorAge, PrimaryAge time.Duration
	}{s.shared.identity, s.stepup.identity, c.MaximumAge, c.PrimaryMaximumAge})
	if err != nil {
		return nil, invalidAuthority()
	}
	s.identity = sha256.Sum256(frame)
	clear(frame)
	return &FactorUpdateService{state: func() *factorUpdateState { return s }}, nil
}

func factorUpdateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.factor-update", SchemaID: "mfa-factor-update", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *factorUpdateState) requestIntent(r mfa.FactorUpdateRequest) (identity.RequestIntent, error) {
	wire, err := json.Marshal(struct {
		Tenant, User, Factor, Name, Origin, Network string
		Action                                      mfa.FactorUpdateAction
		Expected                                    uint64
		Proof                                       auth.Proof
		Cookie                                      bool
	}{string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.FactorID), r.Name, r.Origin, r.Network, r.Action, r.ExpectedVersion, r.FactorProof, r.CSRFToken != (session.CSRFToken{})})
	if err != nil || len(wire) > 32768 {
		clear(wire)
		return identity.RequestIntent{}, invalidAuthority()
	}
	defer clear(wire)
	key := s.shared.config.intentKey()
	defer clear(key[:])
	digest := func(domain string, raw []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("mfa-factor-update-input-v1\x00" + domain + "\x00"))
		_, _ = mac.Write(raw)
		return mac.Sum(nil)
	}
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "factor.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("body", wire)}}, {Name: "factor.session", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("session", []byte(r.Session.Token()))}}, {Name: "factor.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.identity[:])}}})
}

// FactorUpdate reuses the existing immutable keyed input and protected command
// owner. Fresh rename consumes the exact signed factor proof, updates metadata
// optimistically and revokes subject sessions atomically. Retry/unknown/recovery
// never repeat mutation or fabricate fresh metadata. Unsupported actions deny.
func (s *FactorUpdateService) FactorUpdate(ctx context.Context, r mfa.FactorUpdateRequest) (out mfa.FactorUpdateResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidAuthority()
	}
	state := s.state()
	if state == nil || r.Action != mfa.Rename || r.FactorProof.Method != "totp" || !slices.Contains(state.stepup.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	p := &factorUpdatePhase{state: state, request: r}
	defer p.destroy()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Factor = mfa.FactorProjection{}
		}
	}()
	p.coordinator, p.registry, err = state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	if err = authorizeNativeMFAAction(ctx, state.shared, r.Caller, "identity.mfa.factor-update"); err != nil {
		return out, err
	}
	intent, err := state.requestIntent(r)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: factorUpdateOperation().OperationID}
	caller := r.Caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	caller.PolicyRevision = authorization.Revision(state.shared.config.RequestKeys.Policy.PolicyVersion)
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: factorUpdateOperation()}, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	out.CommandID, out.Outcome = k.Admission.CommandID, identity.CommitOutcomeUnknown
	if r.CommandID != "" && r.CommandID != out.CommandID {
		return out, identity.ConflictError{}
	}
	if err = p.restoreInput(ctx, k, wire); err != nil {
		return out, err
	}
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	run, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	if run.Outcome != 0 {
		out.Outcome = run.Outcome
	}
	if err == nil && run.Outcome == identity.CommitOutcomeCommitted && p.applied {
		if !time.Now().Before(p.input.Until) {
			return out, identity.ForbiddenError{}
		}
		out.Factor = p.result
	}
	return out, err
}

// RecoverFactorUpdate resolves historical outcome under current access policy
// without credentials, proof reuse, fresh metadata or new session issuance.
func (s *FactorUpdateService) RecoverFactorUpdate(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.FactorUpdateResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != factorUpdateOperation().OperationID {
		return out, invalidAuthority()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	if q.RecordID == "" {
		q.RecordID = string(q.UserID)
	}
	p := &factorUpdatePhase{state: state}
	c, _, err := state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	result, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.CommandID, out.Outcome = q.CommandID, result.Outcome
	return out, err
}

// Format redacts borrowed native owners and deployment policy.
func (FactorUpdateConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.FactorUpdateConfig(redacted)"))
}

// MarshalJSON rejects implicit native configuration export.
func (FactorUpdateConfig) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit native configuration export.
func (FactorUpdateConfig) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

var _ mfa.FactorManagementService = (*FactorUpdateService)(nil)
