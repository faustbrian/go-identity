package mfapostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequirePasskeySigninFactors locks the original positive factor generation in
// an exact self-user native passkey-primary challenge Work. A confirmed TOTP is
// required; a passkey primary is not itself an enrolled second factor. Call in
// Apply and final checks, returning every error to abort the sole transaction.
// The registered owner must separately verify its genuine assertion and bind
// original expiry, browser, policy, credential/passkey epochs and continuation.
// Missing, empty, changed or unrelated state denies. No factor is enrolled,
// generation adopted, attempt consumed, proof minted or session issued here.
// Work/resources remain borrowed; earlier cancellation wins over the owner bound.
func RequirePasskeySigninFactors(ctx context.Context, w kernel.Work, owner kernel.PasskeyMFAChallengeContributor, command identity.Command, user identity.UserID, version uint64) error {
	if ctx == nil || owner == nil || version == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, ok := command.Feature()
	b, feature, life, err := w.FeatureScope(owner)
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err != nil || !ok || feature.Operation != op || feature.Contributor != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) || b.ValidateFor(op) != nil || spec.Binding != b || spec.Operation != op || b.UserID != user || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(user) || b.RecordID != string(b.CommandID) || life != (kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}) {
		return invalidAuthority()
	}
	state, err := readFactorAuthority(ctx, w, b, user, version)
	if err != nil {
		return err
	}
	if state.RequireEmailRecovery(b.TenantID, user) == nil {
		return identity.ForbiddenError{}
	}
	// The authority row's exclusive lock is the existing factor lifecycle fence.
	// Confirmation alone without actual retained factor custody is insufficient.
	present, err := passwordSigninFactorPresent(ctx, w, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL LIMIT 1`, b.TenantID, user)
	if err != nil {
		return err
	}
	if !present {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
