package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// OneTapCallbackEffect stages the original Google One Tap browser consumption
// and a new existing-account session in the native owner's same Work. The
// configured provider is immutable; the effect authenticates no browser or
// provider, releases no token and owns no resources. Its zero value is invalid.
type OneTapCallbackEffect struct {
	base     *OAuthSigninEffect
	provider session.PreAuthProviderBinding
}

// NewOneTapCallbackEffect selects one startup-configured Google profile and
// the existing provider single-factor session reader contract. Install the
// selected One Tap session issuance migration before serving its callback.
func NewOneTapCallbackEffect(c Config, profile IdentifierAdmissionConfig, provider session.PreAuthProviderBinding) (*OneTapCallbackEffect, error) {
	if !oneTapPreAuthProvider(provider) || provider.ProviderVersion == 0 || len(provider.ClientID) > 1024 || !visibleAdmissionText(provider.ClientID) {
		return nil, session.ErrInvalidSessionCommand
	}
	base, err := NewOAuthSigninEffect(c, profile)
	if err != nil {
		return nil, err
	}
	provider.ClientID = strings.Clone(provider.ClientID)
	return &OneTapCallbackEffect{base: base, provider: provider}, nil
}

// Format redacts correlated runtime configuration.
func (*OneTapCallbackEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OneTapCallbackEffect(redacted)"))
}

// MarshalJSON refuses implicit configuration export.
func (*OneTapCallbackEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit configuration and map-key export.
func (*OneTapCallbackEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Apply requires the exact original callback, verified browser transaction and
// provisional one-use consumption. Any error aborts the caller's Work. The
// callback owner must invoke CheckCurrent in its final admission after later
// participants. Provisional success grants no token or cookie disclosure.
func (e *OneTapCallbackEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.base == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || !oneTapSessionScope(b, feature, transition) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	consumption, err := w.OneTapCallbackConsumption(owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := OneTapCallbackSession(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	flow, err := preauth.ProviderBindings()
	if err != nil || flow.Provider != e.provider || consumption.Command != b {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	spec, _ := record.Bindings()
	remember, _ := spec.Remember.Bindings()
	originalRemember, err := flow.Transaction.Binding.Intent.Remember.Bindings()
	use := PreAuthUse{Command: b, Fingerprint: consumption.Fingerprint, Generation: consumption.Generation}
	if err != nil || remember != originalRemember || !validOneTapPreAuthUse(use, flow.Transaction) ||
		spec.Authentication.Proof.ExpiresAt.After(consumption.Plan.ExpiresAt) ||
		spec.Authentication.Proof.ExpiresAt.After(flow.Transaction.Binding.ExpiresAt) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.base.config.MaximumDuration)
	defer stop()
	if err := e.checkAuthority(bounded, w, owner, command, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := ReserveProviderPreAuth(bounded, w, e.base.config, preauth, e.provider, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.base.native.requireIssueFamily(bounded, w, spec, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireProviderSigninIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.base.native.writeIssuedSession(bounded, w, b, transition, record, spec); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := FinalizeProviderPreAuth(bounded, w, e.base.config, preauth, e.provider, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.CheckCurrent(bounded, w, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: transition.BeforeVersion, AfterVersion: transition.AfterVersion}, nil
}

// CheckCurrent fences the prospective account, current directory and policy,
// exact known-empty factor generation, and persisted session. It cannot renew
// proof validity or switch to a newer epoch or another account.
func (e *OneTapCallbackEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || e == nil || e.base == nil {
		return session.ErrInvalidSessionCommand
	}
	record, err := OneTapCallbackSession(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.base.config.MaximumDuration)
	defer stop()
	if err := e.checkAuthority(bounded, w, owner, command, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.base.config, record); err != nil {
		return err
	}
	return requireProviderSigninIssueTime(bounded, w, record)
}

func (e *OneTapCallbackEffect) checkAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	account, err := kernel.OneTapCallbackAccount(command)
	if err != nil {
		return err
	}
	directory, policy, err := oauthSigninSessionAdmission(e.base.profile, record, account)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := w.RequireOneTapCallbackAccount(ctx, owner, command); err != nil {
		return err
	}
	if err := authority.RequireAuthority(ctx, w, policy.Scope, policy.Version, e.base.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.ForbiddenError{}
		}
		return readError(ctx, err)
	}
	spec, _ := record.Bindings()
	vector, _ := spec.Authority.Bindings()
	if _, err := mfapg.RequireOneTapCallbackFactors(ctx, w, owner, command, vector.Factor.Binding.Version); err != nil {
		return err
	}
	return requireProviderSigninIssueTime(ctx, w, record)
}

// Recover observes only the retained original issuance evidence; it grants
// neither a current session nor the ability to redeliver any credential.
func (e *OneTapCallbackEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.base == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || !oneTapSessionScope(b, feature, transition) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.base.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.base.native.schema, b, transition, oneTapCallbackIssuanceDigest)
	return status, err
}

func oneTapSessionScope(b identity.CommandBinding, feature kernel.FeatureRegistration, transition kernel.LifecyclePlan) bool {
	return b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == b.AnonymousFlowID && b.ValidateFor(kernel.OneTapCallbackOperation()) == nil &&
		feature.Operation == kernel.OneTapCallbackOperation() &&
		feature.Contributor == (kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-completion", Version: 1}) &&
		transition == (kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2})
}

func oneTapCallbackIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-onetap-callback-issuance-v1\x00", binding, user, id, family, record)
}
