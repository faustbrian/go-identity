package reference

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// One synchronous invocation owns factor plaintext and original admission.
// The coordinator alone owns all transactions and durable outcomes.
type magicTOTPPhase struct {
	state          *magicLinkTOTPState
	input          *magicTOTPInput
	command        identity.Command
	admission      risk.ProtectedProviderAdmission
	counterCommand identity.Command
	counterPlan    kernel.CommandCounterPlan
	applied        bool
	correct        bool
	verifiedAt     time.Time
	coordinator    *kernel.Coordinator
	registry       *kernel.ContributorRegistry
	subject        risk.Subject
	issuer         *session.SessionIssuer
	prepared       session.PreparedIssuance
	delivery       *magicTOTPDelivery
	recovery       bool
	recoverySet    mfapg.RecoverySetMetadata
}

func (*magicTOTPPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *magicTOTPPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *magicTOTPPhase) operation() identity.FeatureOperation {
	if p != nil && p.recovery {
		return recoveryCompletionOperation()
	}
	return magicTOTPCompletionOperation()
}
func (p *magicTOTPPhase) completion() (kernel.MFACompletionPlan, error) {
	if p == nil || p.state == nil || p.input == nil || p.input.historical != nil {
		return kernel.MFACompletionPlan{}, invalidTOTPCompletion()
	}
	scope, err := p.input.continuation.ScopeDigest()
	if err != nil {
		return kernel.MFACompletionPlan{}, err
	}
	c := p.input.scope
	return kernel.MFACompletionPlan{ID: identity.CommandID(c.ID), UserID: identity.UserID(c.SubjectID), ScopeDigest: scope, PolicyVersion: c.PolicyVersion, FactorVersion: c.FactorVersion, ContinuationVersion: c.Version}, nil
}
func (p *magicTOTPPhase) ValidateMFACompletion(command identity.Command, child kernel.CapabilityPlan, completion kernel.MFACompletionPlan) error {
	expected, err := p.completion()
	if err != nil || command == (identity.Command{}) || (command != p.counterCommand && command != p.command) || child != p.input.child || completion != expected {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *magicTOTPPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != p.operation() || plan.MFACompletion == nil || plan.Capability == nil || plan.SubjectType != "authentication_attempt" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "session.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || plan.OTP != nil || plan.CapabilityIssuance != nil || plan.MFAContinuation != nil || plan.MagicLinkRegistration != nil || plan.CommandCounters == nil || *plan.CommandCounters != p.counterPlan || plan.RiskEvidence != nil || plan.Delivery != nil {
		return invalidTOTPCompletion()
	}
	return p.ValidateMFACompletion(command, *plan.Capability, *plan.MFACompletion)
}

func (p *magicTOTPPhase) check(ctx context.Context, now time.Time) error {
	if _, err := p.completion(); err != nil {
		return err
	}
	if ctx == nil {
		return invalidTOTPCompletion()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if now.Before(p.input.scope.IssuedAt) || !now.Before(p.input.scope.ExpiresAt) || !now.Before(p.input.scope.PrimaryProofExpiresAt) {
		return identity.ForbiddenError{}
	}
	return p.admission.CheckAt(ctx, now)
}

func (p *magicTOTPPhase) browser(ctx context.Context, command identity.Command, now time.Time) error {
	if err := p.check(ctx, now); err != nil {
		return err
	}
	flow, err := p.input.flow.Bindings()
	if err != nil {
		return err
	}
	cookie, ok := command.PreAuthCookie()
	if !ok {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	digest, err := token.PreAuthDigest(p.state.config.CookieKeys[flow.Cookie.KeyVersion], flow.Binding)
	if err != nil || p.input.flow.Check(now, flow.Binding, digest) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *magicTOTPPhase) directoryAdmission() kernel.DirectoryAuthorityAdmission {
	return kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.state.config.Profile.GlobalAuthorityID, TenantID: p.input.scope.TenantID}, GlobalVersion: p.input.directory.GlobalVersion, TenantVersion: p.input.directory.TenantVersion}
}
func (p *magicTOTPPhase) policyScope() policy.AuthorityScope {
	return policy.AuthorityScope{TenantID: authorization.TenantID(p.input.scope.TenantID), SubjectID: authorization.SubjectID(p.input.recipient.User.ID), PolicyNamespace: p.state.config.Profile.PolicyNamespace}
}

// Wrong-code accounting authenticates browser and current authority before
// taking factor locks. A correct comparison leaves no denial state; successful
// execution independently repeats comparison under its own native locks.
func (p *magicTOTPPhase) RecordMFATOTPAttemptDenial(ctx context.Context, w kernel.MFATOTPAttemptWork) (kernel.MFAAttemptDisposition, error) {
	if p != nil && p.recovery {
		return 0, identity.ForbiddenError{}
	}
	if _, err := p.completion(); err != nil {
		return 0, err
	}
	command, err := w.NativeCommand(p)
	if err != nil || command != p.counterCommand {
		return 0, identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return 0, err
	}
	if err = p.browser(ctx, command, now); err != nil {
		return 0, err
	}
	primary, err := p.input.primaryCommandID()
	if err != nil {
		return 0, err
	}
	if err = sessionpg.RequireMFAConsumedPreAuthAttempt(ctx, w, p, p.state.config.Session, p.input.flow, primary); err != nil {
		return 0, err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, p.directoryAdmission()); err != nil {
		return 0, err
	}
	if err = w.RequireRecipient(ctx, p, p.input.recipient); err != nil {
		return 0, err
	}
	if p.input.passwordPrimary != nil {
		credential, err := p.input.passwordCredential()
		if err != nil {
			return 0, err
		}
		if _, err := w.RequireRecipientCredential(ctx, p, p.input.recipient, credential); err != nil {
			return 0, err
		}
	}
	if err = policy.RequireAuthority(ctx, w, p.policyScope(), p.input.policy.Version, p.state.config.MaximumDuration); err != nil {
		return 0, err
	}
	disposition, err := w.ReserveCommandCounters(ctx, p)
	if err != nil {
		return 0, err
	}
	if disposition == kernel.CommandCounterDenied {
		return kernel.MFAAttemptDenied, nil
	}
	if p.input.missingFactor {
		if err := mfapg.RecordMissingTOTPAttemptDenial(ctx, w, p, string(p.input.request.FactorID)); err != nil {
			return 0, err
		}
		return kernel.MFAAttemptDenied, nil
	}
	locked, err := mfapg.LockTOTPAttempt(ctx, w, p, p.input.snapshot)
	if err != nil {
		return 0, err
	}
	metadata, now, err := locked.VerificationState()
	if err != nil {
		return 0, err
	}
	if err = p.check(ctx, now); err != nil {
		return 0, err
	}
	code, ok := command.OneTimeCode()
	if !ok {
		return 0, identity.ForbiddenError{}
	}
	_, err = p.state.verifier.Verify(ctx, p.input.secret, code, metadata.Profile, p.input.comparison, now, metadata.Replay)
	if err == nil {
		p.correct, p.verifiedAt = true, now
		return kernel.MFAAttemptUnchanged, nil
	}
	var denied identity.ForbiddenError
	if !errors.As(err, &denied) {
		return 0, err
	}
	if err = mfapg.RecordTOTPAttemptDenial(ctx, w, p, locked); err != nil {
		return 0, err
	}
	return kernel.MFAAttemptDenied, nil
}

func (p *magicTOTPPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if _, err := p.completion(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if command != p.command || command == (identity.Command{}) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.browser(ctx, command, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	primary, err := p.input.primaryCommandID()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = sessionpg.RequireMFAConsumedPreAuth(ctx, w, p, command, p.state.config.Session, p.input.flow, primary); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, p.directoryAdmission()); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireRecipient(ctx, p, p.input.recipient); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.input.passwordPrimary != nil {
		credential, err := p.input.passwordCredential()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := w.RequireRecipientCredential(ctx, p, p.input.recipient, credential); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err = policy.RequireAuthority(ctx, w, p.policyScope(), p.input.policy.Version, p.state.config.MaximumDuration); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.recovery {
		if p.state.recoveryEffect == nil {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		locked, err := mfapg.LockRecoveryCompletion(ctx, w, p, command, p.state.recoveryKeys)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err = mfapg.RecordRecoveryCompletion(ctx, w, p, locked); err != nil {
			return identity.FeatureReceipt{}, err
		}
		receipt, err := p.state.recoveryEffect.Apply(ctx, w, p, command, p.input.recipient, locked)
		if err == nil {
			p.applied = true
		}
		return receipt, err
	}
	locked, err := mfapg.LockTOTPCompletion(ctx, w, p, command, p.input.snapshot)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	metadata, now, err := locked.VerificationState()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.check(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	code, ok := command.OneTimeCode()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	step, err := p.state.verifier.Verify(ctx, p.input.secret, code, metadata.Profile, p.input.comparison, now, metadata.Replay)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = mfapg.RecordTOTPCompletion(ctx, w, p, locked, step); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.state.effect.Apply(ctx, w, p, command, p.input.recipient, locked)
	if err == nil {
		p.applied = true
	}
	return receipt, err
}

func (p *magicTOTPPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if _, err := p.completion(); err != nil {
		return err
	}
	if command != p.command || !p.applied {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	record, err := p.sessionRecord(command)
	if err != nil {
		return err
	}
	metadata, err := record.MFAAuthentication().Bindings()
	if err != nil || now.Before(metadata.VerifiedAt) || !now.Before(metadata.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return p.check(ctx, now)
}

func (p *magicTOTPPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p != nil && p.recovery {
		if p.state == nil || p.state.recoveryEffect == nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return p.state.recoveryEffect.Recover(ctx, w, p)
	}
	if p == nil || p.state == nil || p.state.effect == nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return p.state.effect.Recover(ctx, w, p)
}

var _ kernel.MFATOTPAttemptContributor = (*magicTOTPPhase)(nil)
