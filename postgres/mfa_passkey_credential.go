package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// RequireMFAPasskeyPreparationCredential checks the original passkey's current
// eligibility only during the exact native owner's input-admission callback.
// command must retain the coordinator's original opaque custody and its frozen
// anonymous TOTP completion plan. The original subject is selected from that
// plan, never from a caller's user identifier. Primary user/credential locks,
// expiry checks and poisoned-error semantics match RequireMFAPasskeyCredential.
// This performs no consumption, generation, mutation or authentication and
// cannot replace the consumed-child check in Apply or final commit checks.
func (w Work) RequireMFAPasskeyPreparationCredential(ctx context.Context, owner MFACompletionContributor, command identity.Command, expected CredentialAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	b, _, _, err := w.FeatureScope(owner)
	p := w.state.featurePreparationPlan
	if err != nil || p == nil || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != command || p.binding != b || p.registry != w.state.registry || w.state.featureApplying || w.state.mfaConsumed || w.state.mfaFinalized || p.mfaCompletion == nil || p.capability == nil || p.capability.Purpose != "identity.mfa.complete" || p.capability.MaxUses != 1 || p.capability.CapabilityID != string(p.mfaCompletion.ID) {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	selected, err := mfaPasskeyCredentialBinding(b, *p.mfaCompletion, expected)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	return w.requireActiveCredential(ctx, selected, expected)
}

// RequireMFAPasskeyCredential checks the exact original primary credential for
// the subject frozen in this native anonymous TOTP completion plan. The child
// must already be provisionally consumed in this same Work. Apply and final
// checks retain the existing user/credential locks and current database-time
// expiry checks; every live failure poisons Work. It never changes the command's
// original anonymous scope or creates a recipient, proof, session or transaction.
// The native owner must independently authenticate original assertion/browser/
// child custody and the factor, authorize the operation and fence RP mapping.
// This method supplies current credential eligibility, not authentication.
func (w Work) RequireMFAPasskeyCredential(ctx context.Context, owner MFACompletionContributor, expected CredentialAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	b, _, _, err := w.FeatureScope(owner)
	// Coordinator.Commit provisionally finalizes the child before invoking
	// CheckFeatureCommit (domain.go). Eligibility must still be rechecked there;
	// FeatureScope confines this access to the live original owner callback.
	if err != nil || !w.state.mfaConsumed || w.state.execution == nil || w.state.execution.reservation == nil || w.state.execution.reservation.plan == nil {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	p := w.state.execution.reservation.plan
	if p.mfaCompletion == nil || p.capability == nil || p.capability.Purpose != "identity.mfa.complete" || p.capability.MaxUses != 1 || p.capability.CapabilityID != string(p.mfaCompletion.ID) {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	selected, err := mfaPasskeyCredentialBinding(b, *p.mfaCompletion, expected)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	now, err := w.requireActiveCredential(ctx, selected, expected)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	return now, nil
}

// RequirePasskeyCredential applies the identical exact-subject eligibility
// check before counted TOTP comparison/denial. It borrows only this original
// native callback's scope, SQL budget and cancellation. No child is consumed,
// factor compared, attempt charged or authentication granted. A current
// credential is a prerequisite to charging; failures poison the transaction.
func (w MFATOTPAttemptWork) RequirePasskeyCredential(ctx context.Context, owner MFATOTPAttemptContributor, expected CredentialAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	b, err := w.Binding(owner)
	native, original, err := otpAuthorityScope(ctx, w.state.work, b.Command, err)
	if err != nil {
		return time.Time{}, err
	}
	selected, err := mfaPasskeyCredentialBinding(original, b.Plan, expected)
	if err != nil {
		return time.Time{}, otpAuthorityFailure(ctx, native, err)
	}
	now, err := native.requireActiveCredential(ctx, selected, expected)
	if err != nil {
		return time.Time{}, otpAuthorityFailure(ctx, native, err)
	}
	return now, nil
}

func mfaPasskeyCredentialBinding(b identity.CommandBinding, p MFACompletionPlan, e CredentialAdmission) (identity.CommandBinding, error) {
	if b.OperationID != "identity.mfa.totp-verify" || b.SchemaID != "mfa-totp-verify" || b.SchemaVersion != 1 || b.UserID != "" || b.AnonymousFlowID == "" || p.UserID == "" || e.Credential.Kind != identity.CredentialPasskey || e.Credential.Owner != "passkey" || e.Credential.Validate(b.TenantID, p.UserID) != nil || e.UserAuthorityVersion == 0 || e.IdentifierAuthorityVersion == 0 || e.CredentialAuthorityVersion == 0 {
		return identity.CommandBinding{}, invalidWork()
	}
	// Only the existing owner's local eligibility lookup is selected. Journal,
	// policy, audit and recovery retain the original anonymous command unchanged.
	b.UserID = p.UserID
	return b, nil
}
