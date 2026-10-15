package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// OTPEnrollmentSendConfig selects the real primary, OTP and delivery owners
// for authenticated pending-factor sending. It does not enable partial-login
// sending or register HTTP routes. Owners are borrowed and must outlive calls.
// AllowedOrigins are exact HTTPS origins, copied at construction.
type OTPEnrollmentSendConfig struct {
	Primary        OTPEnrollmentSendPrimarySource
	Issuance       OTPEnrollmentIssuanceOwner
	AllowedOrigins []string
}

// OTPEnrollmentSendService sends a purpose-bound challenge for an existing
// pending OTP enrollment through the sole native coordinator. It creates no
// session, confirmation, proof use, transaction owner or private journal.
// Concurrent calls require immutable configuration and borrowed request inputs.
type OTPEnrollmentSendService struct{ state *otpEnrollmentSendState }
type otpEnrollmentSendState struct {
	common   *totpURIState
	primary  OTPEnrollmentSendPrimarySource
	issuance OTPEnrollmentIssuanceOwner
}

func otpSendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewOTPEnrollmentSendService freezes composition without IO or generation.
// Install OTP send attribution and the selected OTP/delivery histories first;
// initialize the OTP issuer's stable keys before serving requests. Missing
// protected risk, primary/CSRF, issuance, delivery or exact-origin owners deny.
func NewOTPEnrollmentSendService(enrollment *OTPEnrollmentService, c OTPEnrollmentSendConfig) (*OTPEnrollmentSendService, error) {
	if enrollment == nil || enrollment.engine == nil || enrollment.engine.state == nil || nilEnrollmentPrimary(c.Primary) || nilEnrollmentPrimary(c.Issuance) || len(c.AllowedOrigins) < 1 || len(c.AllowedOrigins) > 16 {
		return nil, invalidEnrollment()
	}
	s := &otpEnrollmentSendState{common: &totpURIState{enrollment: enrollment.engine.state()}, primary: c.Primary, issuance: c.Issuance}
	if s.common.enrollment.method != "otp" || c.Issuance.DeliveryContributor() == nil {
		return nil, invalidEnrollment()
	}
	configuration, err := c.Issuance.Configuration()
	if err != nil || configuration == ([32]byte{}) {
		return nil, invalidEnrollment()
	}
	origins := slices.Clone(c.AllowedOrigins)
	slices.Sort(origins)
	for i, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin || i > 0 && origin == origins[i-1] {
			return nil, invalidEnrollment()
		}
	}
	s.common.config.AllowedOrigins = origins
	profile, err := s.common.enrollment.config.Counters.CommandCounters.Policy.Admit(risk.Action(otpSendOperation().OperationID))
	if err != nil || profile.Profile.Class != risk.CredentialMutation {
		return nil, invalidEnrollment()
	}
	frame := append(slices.Clone(s.common.enrollment.identity[:]), []byte("mfa-otp-send-v1\x00")...)
	frame = append(frame, configuration[:]...)
	for _, origin := range origins {
		frame = append(frame, []byte(origin+"\x00")...)
	}
	s.common.identity = sha256.Sum256(frame)
	clear(frame)
	return &OTPEnrollmentSendService{state: s}, nil
}

// OtpSend retains server-assigned original command/recipient/input custody
// before risk or generation, then atomically stores the challenge and encrypted
// queue intent. Matching retries never select another recipient or code. Queued
// is not provider delivery or factor confirmation. Partial-login variants deny.
func (s *OTPEnrollmentSendService) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (out mfa.OtpSendResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidEnrollment()
	}
	if r.Enrollment == nil || !slices.Contains(s.state.common.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	state := s.state
	ctx, stop := context.WithTimeout(ctx, state.common.enrollment.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.ChallengeID = ""
			out.DeliveryState = 0
		}
	}()
	p := &totpURIPhase{state: state.common, send: state, sendRequest: r}
	defer p.destroy()
	c, registry, err := state.common.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = c, registry
	intent, err := state.intent(r)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: otpSendOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(state.common.enrollment.config.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	k, wire, err := c.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: otpSendOperation()}, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	out.CommandID, out.Outcome = k.Admission.CommandID, identity.CommitOutcomeUnknown
	if err = p.restoreOTPSendInput(ctx, k, wire); err != nil {
		return out, err
	}
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	result, err := c.ExecutePreparedFeature(ctx, p.command, p.plan)
	if result.Outcome != 0 {
		out.Outcome = result.Outcome
	}
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.ChallengeID = string(out.CommandID)
		out.DeliveryState = delivery.StateQueued
	}
	return out, err
}

// RecoverOtpSend reconciles the exact original code/proof-free outcome. It
// neither compares a code, regenerates output, sends again nor confirms a factor.
// Current result-access authorization remains required; the outcome is historical.
func (s *OTPEnrollmentSendService) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.OtpSendResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != otpSendOperation().OperationID {
		return out, invalidEnrollment()
	}
	ctx, stop := context.WithTimeout(ctx, s.state.common.enrollment.config.MaximumDuration)
	defer stop()
	p := &totpURIPhase{state: s.state.common, send: s.state}
	c, _, err := s.state.common.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	receipt, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.CommandID, out.Outcome = q.CommandID, receipt.Outcome
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		out.ChallengeID = string(q.CommandID)
		out.DeliveryState = delivery.StateQueued
	}
	return out, err
}

func (s *otpEnrollmentSendState) intent(r mfa.OtpSendRequest) (identity.RequestIntent, error) {
	wire, err := json.Marshal(struct {
		Factor          mfa.FactorID
		Channel         delivery.Channel
		Origin, Network string
	}{r.FactorID, r.Channel, r.Origin, r.Network})
	if err != nil {
		return identity.RequestIntent{}, invalidEnrollment()
	}
	defer clear(wire)
	// Do not reveal/consume a borrowed synchronizer merely to fingerprint a
	// request. Its exact original state is authenticated by the retained parent
	// custody on every restoration and fenced again in the protected Work.
	key := s.common.enrollment.config.intentKey()
	defer clear(key[:])
	digest := func(domain string, raw []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("mfa-otp-send-input-v1\x00" + domain + "\x00"))
		_, _ = mac.Write(raw)
		return mac.Sum(nil)
	}
	return identity.NewRequestIntent([]identity.FeatureField{
		{Name: "mfa.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("body", wire)}},
		{Name: "mfa.bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("session", []byte(r.Enrollment.Session.Token()))}},
		{Name: "mfa.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.common.identity[:])}},
	})
}

// Format redacts borrowed native owners and deployment policy.
func (OTPEnrollmentSendService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPEnrollmentSendService(redacted)"))
}

// MarshalJSON denies implicit service export.
func (OTPEnrollmentSendService) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit service export.
func (OTPEnrollmentSendService) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }

// Format redacts borrowed primary/OTP and origin configuration.
func (OTPEnrollmentSendConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPEnrollmentSendConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (OTPEnrollmentSendConfig) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit configuration export.
func (OTPEnrollmentSendConfig) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }
