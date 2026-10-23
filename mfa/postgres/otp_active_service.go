package mfapostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// OTPActiveStepUpConfig selects authenticated email-OTP factor-update proof
// issuance. It enables neither enrollment/login nor HTTP routes. Primary and
// Issuance must be real native owners. Signing uses the existing authentication
// frame; retain public keys for original recovery. TTL caps challenge and proof
// lifetime at 1s..5min; the OTP policy and original session may impose earlier
// limits. Origins are exact HTTPS origins. Owners are borrowed and immutable.
type OTPActiveStepUpConfig struct {
	// AllowedPurposes is a closed explicit selection of factor-update and/or
	// disable. Empty preserves the original factor-update-only profile and its
	// configuration identity. Selection grants no proof or recovery authority.
	AllowedPurposes               []auth.Purpose
	Primary                       OTPActivePrimarySource
	Issuance                      OTPActiveIssuanceOwner
	AllowedOrigins                []string
	AttemptKeyVersion             uint32
	SigningKey                    FactorVerificationSigningKey
	VerificationKeys              map[string]ed25519.PublicKey
	Issuer, Environment, Audience string
	TTL                           time.Duration
}

// OTPActiveStepUpService sends a purpose-bound challenge and atomically consumes
// it with original signed action evidence using the existing native coordinator,
// risk, OTP and delivery owners. It issues no session or renewed primary proof.
// Concurrent calls own separate phases; borrowed dependencies must outlive them.
type OTPActiveStepUpService struct{ state *otpActiveState }

type otpActiveState struct {
	shared   *totpEnrollmentState
	config   OTPActiveStepUpConfig
	reader   *OTPFactorReader
	identity [32]byte
}

func otpActiveOperation(verify bool) identity.FeatureOperation {
	operation, schema := "identity.mfa.otp-send", "mfa-otp-step-up-send"
	if verify {
		operation, schema = "identity.mfa.otp-verify", "mfa-otp-step-up"
	}
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: operation, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewOTPActiveStepUpService freezes the selected native composition without IO
// or generation. Install OTPFactorVerificationMigrationSource and selected
// OTP/send/delivery histories first, and initialize the real issuance keys.
func NewOTPActiveStepUpService(enrollment *OTPEnrollmentService, c OTPActiveStepUpConfig) (*OTPActiveStepUpService, error) {
	if enrollment == nil || enrollment.engine == nil || enrollment.engine.state == nil || nilEnrollmentPrimary(c.Primary) || nilEnrollmentPrimary(c.Issuance) || c.AttemptKeyVersion == 0 || c.SigningKey.sign == nil || c.SigningKey.public == nil || c.TTL < time.Second || c.TTL > 5*time.Minute || c.TTL%time.Microsecond != 0 || len(c.AllowedOrigins) < 1 || len(c.AllowedOrigins) > 16 || len(c.VerificationKeys) < 1 || len(c.VerificationKeys) > 64 {
		return nil, invalidAuthority()
	}
	if len(c.AllowedPurposes) > 2 {
		return nil, invalidAuthority()
	}
	c.AllowedPurposes = slices.Clone(c.AllowedPurposes)
	slices.Sort(c.AllowedPurposes)
	for i, purpose := range c.AllowedPurposes {
		if purpose != "identity.mfa.factor-update" && purpose != "identity.mfa.disable" || i > 0 && purpose == c.AllowedPurposes[i-1] {
			return nil, invalidAuthority()
		}
	}
	for _, text := range []string{c.Issuer, c.Environment, c.Audience} {
		if !enrollmentText(text, 128) {
			return nil, invalidAuthority()
		}
	}
	c.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	slices.Sort(c.AllowedOrigins)
	for i, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin || i > 0 && origin == c.AllowedOrigins[i-1] {
			return nil, invalidAuthority()
		}
	}
	c.VerificationKeys = maps.Clone(c.VerificationKeys)
	for id, key := range c.VerificationKeys {
		if !factorEvidenceKeyID(id) || len(key) != ed25519.PublicKeySize {
			return nil, invalidAuthority()
		}
		c.VerificationKeys[id] = slices.Clone(key)
	}
	id, public := c.SigningKey.public()
	if !bytes.Equal(c.VerificationKeys[id], public) || c.Issuance.ValidateConfirmationKey(c.AttemptKeyVersion) != nil || nilEnrollmentPrimary(c.Issuance.DeliveryContributor()) || nilEnrollmentPrimary(c.Issuance.ConfirmationContributor()) {
		return nil, invalidAuthority()
	}
	configuration, err := c.Issuance.Configuration()
	if err != nil || configuration == ([32]byte{}) {
		return nil, invalidAuthority()
	}
	s := &otpActiveState{shared: enrollment.engine.state(), config: c}
	if s.shared.method != "otp" {
		return nil, invalidAuthority()
	}
	for _, verify := range []bool{false, true} {
		profile, err := s.shared.config.Counters.CommandCounters.Policy.Admit(risk.Action(otpActiveOperation(verify).OperationID))
		if err != nil || profile.Profile.Class != risk.CredentialMutation {
			return nil, invalidAuthority()
		}
	}
	s.reader, err = NewOTPFactorReader(s.shared.pool, s.shared.config.MaximumDuration)
	if err != nil {
		return nil, err
	}
	frame, err := json.Marshal(struct {
		Profile                            string
		Shared, Issuance                   [32]byte
		Origins                            []string
		Key, Issuer, Environment, Audience string
		Public                             ed25519.PublicKey
		Version                            uint32
		TTL                                time.Duration
		Purposes                           []auth.Purpose `json:",omitempty"`
	}{"mfa-otp-active-v1", s.shared.identity, configuration, c.AllowedOrigins, id, c.Issuer, c.Environment, c.Audience, public, c.AttemptKeyVersion, c.TTL, c.AllowedPurposes})
	if err != nil {
		return nil, invalidAuthority()
	}
	s.identity = sha256.Sum256(frame)
	clear(frame)
	return &OTPActiveStepUpService{state: s}, nil
}

func (s *otpActiveState) allows(p auth.Purpose) bool {
	if len(s.config.AllowedPurposes) == 0 {
		return p == "identity.mfa.factor-update"
	}
	return slices.Contains(s.config.AllowedPurposes, p)
}

func (s *otpActiveState) sendIntent(r mfa.OtpSendRequest) (identity.RequestIntent, error) {
	wire, err := json.Marshal(struct {
		Factor          mfa.FactorID
		Action          string
		Channel         delivery.Channel
		Origin, Network string
	}{r.FactorID, string(r.StepUp.Purpose), r.Channel, r.Origin, r.Network})
	if err != nil {
		return identity.RequestIntent{}, invalidAuthority()
	}
	defer clear(wire)
	key := s.shared.config.intentKey()
	defer clear(key[:])
	digest := func(domain string, input []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("mfa-otp-active-input-v1\x00" + domain + "\x00"))
		_, _ = mac.Write(input)
		return mac.Sum(nil)
	}
	return identity.NewRequestIntent([]identity.FeatureField{
		{Name: "mfa.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("body", wire)}},
		{Name: "mfa.bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("session", []byte(r.StepUp.Session.Token()))}},
		{Name: "mfa.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.identity[:])}},
	})
}

// OtpSend accepts only the explicit authenticated StepUp arm. A keyed retry
// retains the original session/factor/recipient/input and never regenerates a
// code. Queued is not provider delivery. Denial/unknown returns no challenge.
func (s *OTPActiveStepUpService) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (out mfa.OtpSendResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.StepUp == nil || r.Validate() != nil {
		return out, invalidAuthority()
	}
	if r.Channel != delivery.ChannelEmail || !s.state.allows(r.StepUp.Purpose) || !slices.Contains(s.state.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	state := s.state
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.ChallengeID, out.DeliveryState = "", 0
		}
	}()
	p := &otpActivePhase{state: state, sendRequest: r}
	defer p.destroy()
	p.coordinator, p.registry, err = state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	intent, err := state.sendIntent(r)
	if err != nil {
		return out, err
	}
	op := otpActiveOperation(false)
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(state.shared.config.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	out.CommandID, out.Outcome = k.Admission.CommandID, identity.CommitOutcomeUnknown
	if err := p.restoreSend(ctx, k, wire); err != nil {
		return out, err
	}
	if err := p.buildCommand(); err != nil {
		return out, err
	}
	result, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	if result.Outcome != 0 {
		out.Outcome = result.Outcome
	}
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.ChallengeID, out.DeliveryState = string(out.CommandID), delivery.StateQueued
	}
	return out, err
}

// OtpVerify consumes only the exact original active send. Actual OTP attempt
// accounting and signed proof persistence are atomic. Replayed or ambiguous
// commands never redeliver proof, and no branch creates a login session.
func (s *OTPActiveStepUpService) OtpVerify(ctx context.Context, r mfa.OtpVerifyRequest) (out mfa.OtpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.StepUp == nil || r.Validate() != nil {
		return out, invalidAuthority()
	}
	if !s.state.allows(r.StepUp.Purpose) || !slices.Contains(s.state.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, s.state.shared.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.StepUpProof = mfa.ContinuationProof{}
		}
	}()
	p := &otpActivePhase{state: s.state, verify: true, verifyRequest: r}
	defer p.destroy()
	p.coordinator, p.registry, err = s.state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	if err := p.loadVerification(ctx); err != nil {
		return out, err
	}
	if err := p.buildCommand(); err != nil {
		return out, err
	}
	result, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	out.Outcome = result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		if !time.Now().Before(p.until) {
			return out, identity.ForbiddenError{}
		}
		out.StepUpProof, err = mfa.NewContinuationProof(p.record.Original.Proof)
	}
	return out, err
}

// RecoverOtpSend reconciles original metadata under current result-access
// permission. It never generates a successor code or delivery.
func (s *OTPActiveStepUpService) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.OtpSendResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != otpActiveOperation(false).OperationID {
		return out, invalidAuthority()
	}
	result, err := s.recover(ctx, q, caller, false)
	out.CommandID, out.Outcome = q.CommandID, result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.ChallengeID, out.DeliveryState = string(q.CommandID), delivery.StateQueued
	}
	return out, err
}

// RecoverOtpVerify returns historical outcome only, never original factor proof.
func (s *OTPActiveStepUpService) RecoverOtpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.OtpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != otpActiveOperation(true).OperationID {
		return out, invalidAuthority()
	}
	result, err := s.recover(ctx, q, caller, true)
	out.Outcome = result.Outcome
	return out, err
}

func (s *OTPActiveStepUpService) recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, verify bool) (identity.CommandResult, error) {
	ctx, stop := context.WithTimeout(ctx, s.state.shared.config.MaximumDuration)
	defer stop()
	p := &otpActivePhase{state: s.state, verify: verify}
	c, _, err := s.state.shared.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return c.RecoverFeatureCommand(ctx, q, caller)
}

// Format redacts cryptographic policy and borrowed native owners.
func (OTPActiveStepUpConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPActiveStepUpConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (OTPActiveStepUpConfig) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit configuration export.
func (OTPActiveStepUpConfig) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format redacts immutable native composition.
func (OTPActiveStepUpService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPActiveStepUpService(redacted)"))
}

// MarshalJSON rejects implicit service export.
func (OTPActiveStepUpService) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit service export.
func (OTPActiveStepUpService) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

var _ mfa.OTPCompletionService = (*OTPActiveStepUpService)(nil)
