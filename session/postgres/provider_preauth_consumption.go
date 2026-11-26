package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RequireProviderPreAuth locks the exact issued Google One Tap callback flow
// against the selected provider, client, mode and original database deadline.
// This is current-row admission, not proof of browser possession, verified
// Google identity or one-use capability admission. Use the original owner's
// bounded primary transaction; old or unrelated flows fail closed.
func RequireProviderPreAuth[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, record session.PreAuthTransaction, selected session.PreAuthProviderBinding) error {
	if !oneTapPreAuthProvider(selected) {
		return identity.InvalidInputError{Field: "session_preauth_provider"}
	}
	return requireSelectedPreAuth(ctx, q, c, record, selected)
}

// ReserveProviderPreAuth binds an issued Google One Tap flow to the exact
// callback command, fingerprint and Work generation. Invoke only inside the
// consuming OAuth owner's sole coordinator Work, after proving the browser,
// Google credential and one-use capability. This does not replace the
// capability participant or grant session issuance. On error abort Work.
func ReserveProviderPreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, selected session.PreAuthProviderBinding, use PreAuthUse) error {
	return transitionOneTapPreAuth(ctx, q, c, record, use, preAuthTransitionSelection{provider: selected})
}

// FinalizeProviderPreAuth consumes that exact reservation in the original
// transaction retaining the protected identity, capability and session effects.
// A late failure must roll back all effects together. Terminal historical
// outcomes belong to coordinator recovery; this call never reopens a flow.
func FinalizeProviderPreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, selected session.PreAuthProviderBinding, use PreAuthUse) error {
	return transitionOneTapPreAuth(ctx, q, c, record, use, preAuthTransitionSelection{final: true, provider: selected})
}

func transitionOneTapPreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, use PreAuthUse, transition preAuthTransitionSelection) error {
	if !oneTapPreAuthProvider(transition.provider) {
		return identity.InvalidInputError{Field: "session_preauth_provider"}
	}
	return transitionSelectedPreAuth(ctx, q, c, record, use, transition)
}

func oneTapPreAuthProvider(selected session.PreAuthProviderBinding) bool {
	return selected.Mode == session.PreAuthProviderCallback && selected.ProviderID == "google"
}

func validOneTapPreAuthUse(use PreAuthUse, record session.PreAuthTransactionSpec) bool {
	const oneTapStart = "identity.oauth.onetap-start"
	operation := identity.FeatureOperation{
		Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", SchemaID: "oauth-onetap-callback-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
	command := use.Command
	binding := record.Binding
	intent := binding.Intent
	// Starts and callbacks are distinct product operations. Keep the start bound
	// into the immutable cookie and admit only its matching anonymous callback.
	sameFlow := command.AnonymousFlowID == string(binding.ID) && command.RecordID == string(binding.ID) && command.TenantID == intent.TenantID
	samePolicy := command.PolicyID == intent.PolicyID && command.PolicyVersion == intent.PolicyVersion
	return intent.Action == oneTapStart && sameFlow && samePolicy && command.ActorKind == authorization.SubjectServiceAccount &&
		use.Fingerprint != ([32]byte{}) && use.Generation != 0 && command.ValidateFor(operation) == nil
}
