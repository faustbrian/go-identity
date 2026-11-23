package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// SSOOIDCSigninEffect persists an existing linked member's original enterprise
// session and browser use through the SSO callback's sole transaction. It does
// not authenticate a provider, verify a browser cookie or disclose credentials.
// Provider verification and organization role decisions remain with native owners.
// Immutable configuration may be used concurrently by distinct serial Works.
type SSOOIDCSigninEffect struct {
	effect *ssoSigninEffect
}

type ssoSigninEffect struct {
	native       Repository
	config       Config
	profile      IdentifierAdmissionConfig
	organization OrganizationSessionAuthority
}

// SSOOIDCOrganizationUpdate applies provider-owned organization changes in the
// original callback Work after its native session and browser writes, before
// organization admission locks are acquired. Implementations must execute
// synchronously, use only the supplied Work, and neither retain it nor start or
// finish a transaction. The command and session retain their original authority;
// an update must not replace that evidence. The callback owner must return any
// error to abort the transaction.
type SSOOIDCOrganizationUpdate interface {
	UpdateSSOOIDCOrganization(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command, session.Session) error
}

func (*SSOOIDCSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOIDCSigninEffect(redacted)"))
}

func (*SSOOIDCSigninEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (*SSOOIDCSigninEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSSOOIDCSigninEffect opts into native static enterprise OIDC session
// issuance. The organization owner must use the same primary transaction and
// require the current selected member. Install both SSO issuance migrations
// before selecting this effect. Construction performs no IO.
func NewSSOOIDCSigninEffect(c Config, p IdentifierAdmissionConfig, org OrganizationSessionAuthority) (*SSOOIDCSigninEffect, error) {
	effect, err := newSSOSigninEffect(c, p, org, "sso-oidc")
	if err != nil {
		return nil, err
	}
	return &SSOOIDCSigninEffect{effect}, nil
}

func newSSOSigninEffect(c Config, p IdentifierAdmissionConfig, org OrganizationSessionAuthority, method string) (*ssoSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute ||
		!p.valid() || p.AuthenticationMethod != method || p.CredentialKind != identity.CredentialProvider || p.CredentialOwner != "sso" || nilIssueDependency(org) {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &ssoSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p, organization: org}, nil
}

func (e *SSOOIDCSigninEffect) core() *ssoSigninEffect {
	if e == nil {
		return nil
	}
	return e.effect
}

// Apply needs the exact original command, the SSO-authenticated browser and
// the provisionally consumed enterprise grant in this Work. The cookie was
// authenticated by SSO; the immutable original browser is now reserved and
// consumed with the new session and issuance history. Return every error to
// abort the transaction. Provisional success does not permit disclosure.
func (e *SSOOIDCSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	return e.core().apply(ctx, w, owner, command, preauth, nil)
}

// ApplyWithOrganizationUpdate has Apply's contract and also invokes update
// exactly once after native session/browser persistence and before the first
// organization fence and final expiry check. This ordering lets the organization
// owner acquire mutation locks without upgrading admission's shared locks.
// The synchronous update shares Apply's bounded context and sole transaction;
// return every error to abort all effects. Nil and typed-nil updates fail closed.
func (e *SSOOIDCSigninEffect) ApplyWithOrganizationUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction, update SSOOIDCOrganizationUpdate) (identity.FeatureReceipt, error) {
	if nilIssueDependency(update) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	return e.core().apply(ctx, w, owner, command, preauth, update)
}

func (e *ssoSigninEffect) apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction, update SSOOIDCOrganizationUpdate) (identity.FeatureReceipt, error) {
	if !e.valid(ctx) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	consumption, err := e.consumption(w, owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := e.session(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := record.Bindings()
	use, err := ssoOIDCSigninPreAuth(spec, preauth, consumption)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || !e.scope(feature, transition) || b != use.Command {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAccountAuthority(bounded, w, owner, command, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := ReservePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, spec); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := FinalizePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if update != nil {
		if err := update.UpdateSSOOIDCOrganization(bounded, w, owner, command, record); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	// Organization operations lock in session→organization order. Both newly
	// written rows are held here; final admission uses the same order below.
	if err := e.organization.RequireOrganizationSession(bounded, w, owner, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireProviderSigninIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: transition.BeforeVersion, AfterVersion: transition.AfterVersion}, nil
}

// CheckCurrent requires the exact original command and complete persisted
// session plus current account, factor, policy and organization authority in
// Apply or final admission. The native owner must run it after later writes;
// no check replaces an original version or renews evidence.
func (e *SSOOIDCSigninEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return e.core().checkCurrent(ctx, w, owner, command)
}

func (e *ssoSigninEffect) checkCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if !e.valid(ctx) {
		return session.ErrInvalidSessionCommand
	}
	record, err := e.session(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAccountAuthority(bounded, w, owner, command, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return err
	}
	if err := e.organization.RequireOrganizationSession(bounded, w, owner, record); err != nil {
		return err
	}
	return requireProviderSigninIssueTime(bounded, w, record)
}

// Recover reports only the historical exact issuance outcome through the
// original callback's RecoveryWork. It cannot reconstruct a bearer, renew an
// authority snapshot or read the provider. Missing evidence does not prove the
// outcome of the other callback participants.
func (e *SSOOIDCSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	return e.core().recover(ctx, w, owner)
}

func (e *ssoSigninEffect) recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if !e.valid(ctx) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || !e.scope(feature, transition) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	digest := ssoOIDCSigninIssuanceDigest
	switch e.profile.AuthenticationMethod {
	case "sso-oauth2":
		digest = ssoOAuth2SigninIssuanceDigest
	case "sso-saml":
		digest = ssoSAMLSigninIssuanceDigest
	}
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, digest)
	return status, err
}

func (e *ssoSigninEffect) valid(ctx context.Context) bool {
	return ctx != nil && e != nil && e.config.MaximumDuration > 0
}

func (e *ssoSigninEffect) scope(feature kernel.FeatureRegistration, lifecycle kernel.LifecyclePlan) bool {
	operation, contract := ssoOIDCSessionOperation(), "sso.oidc-login-callback"
	switch e.profile.AuthenticationMethod {
	case "sso-oauth2":
		operation, contract = ssoOAuth2SessionOperation(), "sso.oauth2-login-callback"
	case "sso-saml":
		operation, contract = kernel.SSOSAMLSigninOperation(), "sso.saml-login-callback"
	}
	return feature.Operation == operation &&
		feature.Contributor == (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: contract, Version: 1}) &&
		lifecycle == (kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2})
}

func ssoOIDCSigninPreAuth(spec session.SessionSpec, preauth session.PreAuthTransaction, consumption kernel.CapabilityReservationBinding) (PreAuthUse, error) {
	flow, err := preauth.Bindings()
	if err != nil || flow.Version != 1 || consumption.Generation == 0 || consumption.Fingerprint == ([32]byte{}) {
		return PreAuthUse{}, session.ErrInvalidSessionCommand
	}
	intent, binding := flow.Binding.Intent, consumption.Command
	if string(flow.Binding.ID) != binding.AnonymousFlowID || intent.Purpose != session.PreAuthSessionIssuance ||
		intent.TenantID != binding.TenantID || intent.Action != binding.OperationID || intent.PolicyID != binding.PolicyID ||
		intent.PolicyVersion != binding.PolicyVersion || intent.Remember == (session.RememberPolicy{}) || intent.Remember != spec.Remember {
		return PreAuthUse{}, session.ErrInvalidSessionCommand
	}
	expires := spec.Authentication.Proof.ExpiresAt
	if expires.After(consumption.Plan.ExpiresAt) || expires.After(flow.Binding.ExpiresAt) {
		return PreAuthUse{}, session.ErrInvalidSessionCommand
	}
	return PreAuthUse{Command: binding, Fingerprint: consumption.Fingerprint, Generation: consumption.Generation}, nil
}

func (e *ssoSigninEffect) requireAccountAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	decodeAccount := kernel.SSOOIDCSigninAccount
	fenceAccount := w.RequireSSOOIDCSigninProviderAccount
	fenceFactors := mfapg.RequireSSOOIDCSigninFactors
	switch e.profile.AuthenticationMethod {
	case "sso-oauth2":
		decodeAccount = kernel.SSOOAuth2SigninAccount
		fenceAccount, fenceFactors = w.RequireSSOOAuth2SigninProviderAccount, mfapg.RequireSSOOAuth2SigninFactors
	case "sso-saml":
		decodeAccount = kernel.SSOSAMLSigninAccount
		fenceAccount, fenceFactors = w.RequireSSOSAMLSigninProviderAccount, mfapg.RequireSSOSAMLSigninFactors
	}
	account, err := decodeAccount(command)
	if err != nil {
		return err
	}
	spec, _ := record.Bindings()
	vector, _ := spec.Authority.Bindings()
	key, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || key != vector.Factor.Binding.ScopeKey || account.Account.Validate(spec.TenantID, spec.UserID) != nil || account.SocialLinkVersion == 0 {
		return session.ErrInvalidSessionCommand
	}
	// Derive the account's current authority keys without changing the original
	// callback actor, anonymous flow, aggregate or exact Work command identity.
	selected := identity.CommandBinding{TenantID: spec.TenantID, UserID: spec.UserID, ActorKind: authorization.SubjectUser, ActorID: identity.ActorID(spec.UserID)}
	directory, credential, policy, err := credentialSessionAdmissionBindingsWithOrganization(e.profile, record, selected, spec.SessionID, spec.Version, vector.Factor, session.OptionalAuthorityBinding{}, vector.Organization, auth.AssuranceSingleFactor)
	if err != nil || credential != account.Credential {
		return session.ErrInvalidSessionCommand
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := fenceAccount(ctx, owner, command); err != nil {
		return err
	}
	if err := authority.RequireAuthority(ctx, w, policy.Scope, policy.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.ForbiddenError{}
		}
		return readError(ctx, err)
	}
	if _, err := fenceFactors(ctx, w, owner, command, vector.Factor.Binding.Version); err != nil {
		return err
	}
	return requireProviderSigninIssueTime(ctx, w, record)
}

func ssoOIDCSigninIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-sso-oidc-signin-issuance-v1\x00", binding, user, id, family, record)
}
