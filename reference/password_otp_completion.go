package reference

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// PasswordOTPLoginCompletionConfig selects the actual sender's native password,
// original OTP, browser, risk and transaction owners plus session issuance.
// ConfigurationID pins immutable session/CSRF/callback semantics; change it when
// those semantics change. AttemptKeyVersion selects retained native OTP custody.
// Borrowed owners and clock remain immutable and outlive concurrent calls.
type PasswordOTPLoginCompletionConfig struct {
	Sender            *PasswordOTPLoginSendService
	ConfigurationID   string
	SessionIssuer     session.IssuerConfig
	CSRF              session.CSRFKey
	AttemptKeyVersion uint32
}

// PasswordOTPLoginCompletionService supplies complete native secondary OTP
// send/verification/recovery, not ordinary OTP signin or enrollment. It owns no
// pool, transaction, cache or goroutine. Only a fresh known commit may reveal
// session/CSRF credentials; retries and recovery return historical metadata.
type PasswordOTPLoginCompletionService struct {
	state func() *passwordOTPCompletionState
}
type passwordOTPCompletionState struct {
	config PasswordOTPLoginCompletionConfig
	sender *passwordOTPSendState
	effect *sessionpg.MFAOTPCompletionEffect
}

func invalidPasswordOTPCompletion() error {
	return identity.InvalidInputError{Field: "reference_password_otp_completion"}
}
func passwordOTPCompletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// NewPasswordOTPLoginCompletionService freezes concrete native composition
// without IO, callbacks, migrations or issuance. Install selected OTP completion
// counter/session histories before serving. Missing owners or invalid issuance
// configuration deny; applications provide no missing domain orchestration.
func NewPasswordOTPLoginCompletionService(c PasswordOTPLoginCompletionConfig) (*PasswordOTPLoginCompletionService, error) {
	if c.Sender == nil || c.Sender.state == nil || c.AttemptKeyVersion == 0 {
		return nil, invalidPasswordOTPCompletion()
	}
	if _, err := identity.ParseIdentifierID(c.ConfigurationID); err != nil {
		return nil, invalidPasswordOTPCompletion()
	}
	s := c.Sender.state()
	if s == nil || s.config.Issuance.CompletionContributor() == nil || c.SessionIssuer.MaximumDuration <= 0 || c.SessionIssuer.MaximumDuration > s.config.MaximumDuration {
		return nil, invalidPasswordOTPCompletion()
	}
	if _, err := session.NewMFAPasswordSessionIssuerWithCSRF(&passwordOTPCompletionDelivery{}, c.SessionIssuer, c.CSRF); err != nil {
		return nil, invalidPasswordOTPCompletion()
	}
	effect, err := sessionpg.NewMFAPasswordOTPCompletionEffect(s.config.Session, s.config.Profile)
	if err != nil {
		return nil, err
	}
	state := &passwordOTPCompletionState{config: c, sender: s, effect: effect}
	return &PasswordOTPLoginCompletionService{state: func() *passwordOTPCompletionState { return state }}, nil
}

// OtpSend delegates only to the selected original native sender. It cannot
// consume the child, change a factor or issue a session.
func (s *PasswordOTPLoginCompletionService) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (mfa.OtpSendResult, error) {
	if s == nil || s.state == nil {
		return mfa.OtpSendResult{}, invalidPasswordOTPCompletion()
	}
	return s.state().config.Sender.OtpSend(ctx, r)
}

// RecoverOtpSend performs code/proof-free original send reconciliation and
// never queues another message or renews its provenance.
func (s *PasswordOTPLoginCompletionService) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpSendResult, error) {
	if s == nil || s.state == nil {
		return mfa.OtpSendResult{}, invalidPasswordOTPCompletion()
	}
	return s.state().config.Sender.RecoverOtpSend(ctx, q, caller)
}

// OtpVerify authenticates original code/browser intent before mutable source
// reads. It restores the exact committed send and one retained native attempt,
// admits current password/factor/recipient/policy/risk, then atomically commits
// OTP, child, shared budget and session effects through the sole coordinator.
// Failure/unknown/replay withholds credentials. Original remember and password
// freshness cannot be replaced. This profile rejects enrollment/trusted devices.
func (s *PasswordOTPLoginCompletionService) OtpVerify(ctx context.Context, r mfa.OtpVerifyRequest) (out mfa.OtpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidPasswordOTPCompletion()
	}
	state := s.state()
	if r.Enrollment != nil || r.TrustDevice || !slices.Contains(state.sender.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.sender.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil && out.Outcome != identity.CommitOutcomeUnknown {
			err = ctx.Err()
		}
		if err != nil {
			clearPasswordOTPDelivery(&out)
		}
	}()
	p := &passwordOTPCompletionPhase{state: state, request: r, observedUntil: time.Now().UTC().Add(20 * time.Second)}
	if err = p.compose(); err != nil {
		return out, err
	}
	p.original, err = p.originalCommand()
	if err != nil {
		return out, err
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(state.sender.config.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.PreAuthID)}
	history, present, historyErr := p.coordinator.QueryMFAOTPCommand(ctx, p.original, caller)
	if present && (historyErr != nil || history.Outcome == identity.CommitOutcomeCommitted || history.Outcome == identity.CommitOutcomeNotCommitted || history.Outcome == identity.CommitOutcomeConflict) {
		return passwordOTPReceipt(r.CommandID, history), historyErr
	}
	if historyErr != nil {
		return out, historyErr
	}
	var retained identity.FeatureCommandSpec
	var retainedPlan kernel.CommandPlan
	if present {
		retained, retainedPlan, _, err = p.coordinator.QueryMFAOTPPreparation(ctx, p.original, caller)
		if err != nil {
			return passwordOTPReceipt(r.CommandID, history), err
		}
	}
	p.source, err = state.sender.readCompletionSource(ctx, r)
	if err != nil {
		return out, err
	}
	defer p.source.destroy()
	if err = p.prepareCommand(ctx, retained, retainedPlan, present); err != nil {
		return out, err
	}
	plan, err := p.declaration()
	if err != nil {
		return out, err
	}
	plan, err = p.coordinator.PrepareMFAOTPFeaturePlanWithOriginal(p.original, p.mapped, plan)
	if err != nil {
		return out, err
	}
	receipt, err := p.coordinator.ExecutePreparedMFAOTPFeature(ctx, p.original, p.mapped, plan)
	out = passwordOTPReceipt(r.CommandID, receipt)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || p.prepared == (session.PreparedIssuance{}) || !p.applied {
		return out, err
	}
	record, ok := p.prepared.Session()
	if !ok {
		return out, identity.UnavailableError{}
	}
	p.delivery.command, p.delivery.record, p.delivery.receipt, p.delivery.deliverable = p.command, record, receipt, true
	bound, err := p.issuer.BindMFA(p.prepared, p.command)
	if err != nil {
		return out, err
	}
	out.Session, err = p.issuer.Issue(ctx, bound)
	out.Outcome = out.Session.CommitOutcome
	if err == nil && out.Session.Token != (session.Token{}) {
		out.CSRFToken, err = bound.CSRFToken()
	}
	return out, err
}

func passwordOTPReceipt(id identity.CommandID, r identity.CommandResult) mfa.OtpVerifyResult {
	return mfa.OtpVerifyResult{Outcome: r.Outcome, Session: session.IssueResult{CommandID: id, CommitOutcome: r.Outcome, Replayed: r.Outcome == identity.CommitOutcomeCommitted, RetryAfter: r.RetryAfter}}
}
func clearPasswordOTPDelivery(r *mfa.OtpVerifyResult) {
	r.Session.Token = session.Token{}
	r.Session.Cookie = http.Cookie{}
	r.CSRFToken = session.CSRFToken{}
}

// RecoverOtpVerify reconciles only exact original command scope under current
// query policy, without code, proof, cookie, generation or credential delivery.
func (s *PasswordOTPLoginCompletionService) RecoverOtpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.OtpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != passwordOTPCompletionOperation().OperationID || q.UserID != "" || q.RecordID != "" || caller.Validate() != nil {
		return out, invalidPasswordOTPCompletion()
	}
	if _, err := identity.ParsePreAuthTransactionID(q.AnonymousFlowID); err != nil {
		return out, invalidPasswordOTPCompletion()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.sender.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = mfa.OtpVerifyResult{}
			err = identity.UnavailableError{}
		}
		clearPasswordOTPDelivery(&out)
	}()
	p := &passwordOTPCompletionPhase{state: state}
	if err = p.compose(); err != nil {
		return out, err
	}
	caller = caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	receipt, err := p.coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Feature != nil && receipt.Feature.Operation != passwordOTPCompletionOperation() {
		return out, identity.UnavailableError{}
	}
	return passwordOTPReceipt(q.CommandID, receipt), err
}

func (PasswordOTPLoginCompletionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordOTPLoginCompletionConfig(redacted)"))
}
func (PasswordOTPLoginCompletionConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
func (PasswordOTPLoginCompletionConfig) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
func (PasswordOTPLoginCompletionService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordOTPLoginCompletionService(redacted)"))
}
func (PasswordOTPLoginCompletionService) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
func (PasswordOTPLoginCompletionService) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

var _ mfa.OTPCompletionService = (*PasswordOTPLoginCompletionService)(nil)
