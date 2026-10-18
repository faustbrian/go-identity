package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// RequireVerificationSignupPreAuth fences the original browser already
// consumed by genuine signup, for the exact native verification-MFA challenge
// owner. It never consumes/reactivates signup or treats confirmation as signup.
// Original flow and signup ID must come from authenticated retained input; the
// owner separately proves submitted-cookie possession, parent and live factor.
// Preparation, Apply and final checks share the sole Work and its locks.
func RequireVerificationSignupPreAuth(ctx context.Context, w kernel.Work, owner kernel.EmailVerificationMFAChallengeContributor, command identity.Command, c Config, original session.PreAuthTransaction, signup identity.CommandID) error {
	if ctx == nil || owner == nil {
		return session.ErrInvalidSessionCommand
	}
	b, f, life, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	op := verificationSigninOperation()
	if err != nil || !ok || !cookie || s.Binding != b || s.Operation != op || f.Operation != op || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || life.EventType != "mfa.challenge.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return identity.ForbiddenError{}
	}
	flow, err := original.Bindings()
	if err != nil {
		return err
	}
	// This local lookup key is not a command or an authentication assertion.
	// The closed owner above already matched the real user-targeted command.
	b.AnonymousFlowID = string(flow.Binding.ID)
	return requireMFAConsumedPreAuthMode(ctx, w, w.DatabaseTime, b, c, original, signup, true)
}

// RequireMFAVerificationConsumedPreAuth fences genuine signup custody for the
// explicit TOTP completion of a verification-origin child. Signup is already
// consumed and is never reactivated. Its ID comes from the authenticated native
// primary, not the completion command or a caller-supplied parent assertion.
// The exact native factor owner separately authenticates cookie and child.
func RequireMFAVerificationConsumedPreAuth(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, c Config, original session.PreAuthTransaction, signup identity.CommandID) error {
	if ctx == nil || owner == nil {
		return session.ErrInvalidSessionCommand
	}
	b, f, life, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	if err != nil || !ok || !cookie || !code || s.Binding != b || s.Operation != mfaTOTPCompletionSessionOperation() || f.Operation != s.Operation || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || life.EventType != "session.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 0 {
		return identity.ForbiddenError{}
	}
	return requireMFAConsumedPreAuthMode(ctx, w, w.DatabaseTime, b, c, original, signup, true)
}

// RequireMFAVerificationConsumedPreAuthAttempt applies the same immutable
// signup fence before a counted TOTP comparison or shared-budget debit. Foreign
// or returned callbacks deny; this operation cannot compare or charge a factor,
// consume/reactivate signup, or create a session. Propagate every error.
func RequireMFAVerificationConsumedPreAuthAttempt(ctx context.Context, w kernel.MFATOTPAttemptWork, owner kernel.MFATOTPAttemptContributor, c Config, original session.PreAuthTransaction, signup identity.CommandID) error {
	if ctx == nil || owner == nil {
		return session.ErrInvalidSessionCommand
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	command, err := w.NativeCommand(owner)
	if err != nil {
		return err
	}
	s, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	if !ok || !cookie || !code || s.Binding != b.Command || s.Operation != mfaTOTPCompletionSessionOperation() || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return identity.ForbiddenError{}
	}
	return requireMFAConsumedPreAuthMode(ctx, w, w.DatabaseTime, b.Command, c, original, signup, true)
}
