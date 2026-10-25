package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// ReserveMFAPasskeyPreAuth reserves the original pending passkey browser for
// this exact protected TOTP completion. Acquire current account/credential and
// factor locks first, matching native passkey assertion order; do not take a
// browser share lock earlier in the same Work and then upgrade it. The native
// owner must authenticate original assertion/child/browser custody first and
// propagate every error. Only live Apply with provisionally consumed child and
// matching original-primary session metadata is admitted; preparation denies.
// This uses the existing pre-auth state machine and original timeline, not a
// new replay authority, transaction or authentication proof.
func ReserveMFAPasskeyPreAuth(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, c Config, original session.PreAuthTransaction) error {
	use, err := mfaPasskeyPreAuthUse(ctx, w, owner, command, original)
	if err != nil {
		return err
	}
	return transitionPreAuthProfile(ctx, w, c, original, use, false, true)
}

// FinalizeMFAPasskeyPreAuth consumes only this Work's original reservation,
// after successful native factor and session effects in the same transaction.
// It cannot consume an issued flow directly or reuse another command's custody.
// Later failure must abort all browser/child/factor/session effects together.
// Exact retries and ambiguous outcomes use the original coordinator receipt;
// never re-run this transition or release the browser on an uncertain commit.
func FinalizeMFAPasskeyPreAuth(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, c Config, original session.PreAuthTransaction) error {
	use, err := mfaPasskeyPreAuthUse(ctx, w, owner, command, original)
	if err != nil {
		return err
	}
	return transitionPreAuthProfile(ctx, w, c, original, use, true, true)
}

func mfaPasskeyPreAuthUse(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, original session.PreAuthTransaction) (PreAuthUse, error) {
	if ctx == nil {
		return PreAuthUse{}, identity.InvalidInputError{Field: "session_mfa_preauth"}
	}
	if err := ctx.Err(); err != nil {
		return PreAuthUse{}, err
	}
	deny := func() (PreAuthUse, error) { return PreAuthUse{}, identity.ForbiddenError{} }
	b, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || w.RequireFeatureCommand(ctx, owner, command) != nil {
		return deny()
	}
	consumed, completion, err := w.MFACompletionConsumption(owner)
	if err != nil || consumed.Command != b || consumed.Fingerprint != fingerprint || consumed.Generation != generation {
		return deny()
	}
	record, err := MFATOTPCompletionSession(command)
	if err != nil {
		return deny()
	}
	s, err := record.Bindings()
	m, merr := record.MFAAuthentication().Bindings()
	f, ferr := original.Bindings()
	remember, rerr := f.Binding.Intent.Remember.Bindings()
	if err != nil || merr != nil || ferr != nil || rerr != nil || s.Authentication.Proof.Purpose != session.PasskeyMFAPrimaryPurpose || s.Authentication.Proof.Method != "passkey" || string(s.Authentication.Proof.ID) != string(m.PrimaryCommandID) || m.CommandID != b.CommandID || m.ContinuationID != completion.ID || m.ContinuationScopeDigest != completion.ScopeDigest || m.FactorAuthorityVersion != completion.FactorVersion || m.ContinuationVersion != completion.ContinuationVersion || s.UserID != completion.UserID || m.Remember != remember {
		return deny()
	}
	use := PreAuthUse{Command: b, Fingerprint: fingerprint, Generation: generation}
	if !validMFAPasskeyPreAuthUse(use, f) {
		return deny()
	}
	return use, nil
}

func validMFAPasskeyPreAuthUse(use PreAuthUse, original session.PreAuthTransactionSpec) bool {
	b, intent := use.Command, original.Binding.Intent
	// Passkey's native challenge leaves this browser pending. Reference's
	// single-use pre-auth contract requires completion to consume it alongside
	// the session, under its OWN MFA command/policy rather than a fabricated
	// passkey command. The sealed Apply guard above alone selects this relation.
	return b.ValidateFor(mfaTOTPCompletionSessionOperation()) == nil && b.UserID == "" && b.AnonymousFlowID == string(original.Binding.ID) && b.TenantID == intent.TenantID && b.PolicyVersion == intent.PolicyVersion && intent.Purpose == session.PreAuthSessionIssuance && intent.Action == "identity.passkey.signin-verify" && use.Fingerprint != ([32]byte{}) && use.Generation != 0
}
