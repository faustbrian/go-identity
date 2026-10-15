package reference

import (
	"context"

	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// The existing coordinator owns this callback's shared-budget transaction.
// Only an actual correct comparison may plan prospective set metadata; it is
// not proof and must be rolled back and independently repeated during Apply.
func (p *magicTOTPPhase) RecordMFARecoveryAttemptDenial(ctx context.Context, w kernel.MFARecoveryAttemptWork) (kernel.MFAAttemptDisposition, error) {
	if _, err := p.completion(); err != nil {
		return 0, err
	}
	if !p.recovery || p.input.recovery == nil {
		return 0, identity.ForbiddenError{}
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
	if err = sessionpg.RequireMFAConsumedPreAuthRecoveryAttempt(ctx, w, p, p.state.config.Session, p.input.flow, primary); err != nil {
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
		if _, err = w.RequireRecipientCredential(ctx, p, p.input.recipient, credential); err != nil {
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
	locked, matched, err := mfapg.CompareRecoveryAttempt(ctx, w, p, p.state.recoveryKeys)
	if err != nil {
		return 0, err
	}
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return 0, err
	}
	if err = p.check(ctx, now); err != nil {
		return 0, err
	}
	if matched {
		p.recoverySet, err = locked.MatchedSet()
		if err != nil {
			return 0, err
		}
		p.correct, p.verifiedAt = true, now
		return kernel.MFAAttemptUnchanged, nil
	}
	if err = mfapg.RecordRecoveryAttemptDenial(ctx, w, p, locked); err != nil {
		return 0, err
	}
	return kernel.MFAAttemptDenied, nil
}

var _ kernel.MFARecoveryAttemptContributor = (*magicTOTPPhase)(nil)

func (p *magicTOTPPhase) sessionFields(record session.Session) ([]identity.FeatureField, error) {
	if p.recovery {
		return sessionpg.MFARecoveryCompletionSessionFields(record)
	}
	return sessionpg.MFATOTPCompletionSessionFields(record)
}

func (p *magicTOTPPhase) sessionRecord(command identity.Command) (session.Session, error) {
	if p.recovery {
		return sessionpg.MFARecoveryCompletionSession(command)
	}
	return sessionpg.MFATOTPCompletionSession(command)
}
