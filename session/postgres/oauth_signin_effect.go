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

// OAuthSigninEffect stages the complete provider session, new family and
// original browser consumption in the OAuth owner's sole coordinator Work.
// It does not exchange a code, authenticate a provider/browser, issue a bearer,
// start a transaction or retain resources. Configuration is immutable; concurrent
// calls use independent serial Work handles. Zero is invalid.
type OAuthSigninEffect struct {
	native  Repository
	config  Config
	profile IdentifierAdmissionConfig
}

// Format redacts correlated deployment configuration for every verb.
func (*OAuthSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OAuthSigninEffect(redacted)"))
}

// MarshalJSON rejects implicit deployment configuration export.
func (*OAuthSigninEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit configuration and map-key export.
func (*OAuthSigninEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewOAuthSigninEffect snapshots an existing-account single-factor provider
// profile without IO. Install the matching session issuance history before
// selecting this effect. Known-empty MFA is mandatory, never inferred. The
// native owner must supply actual original provider/state/browser authentication;
// applications cannot substitute a caller-selected account or transaction.
func NewOAuthSigninEffect(c Config, p IdentifierAdmissionConfig) (*OAuthSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() || p.AuthenticationMethod != "oauth" || p.CredentialKind != identity.CredentialProvider || p.CredentialOwner != "identity/oauth" {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &OAuthSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

// Apply requires the exact command and genuine same-transaction provisional
// callback-state consumption. The native owner must first authenticate retained
// provider output and original browser possession. This effect correlates the
// frozen account/credential/session and fences current directory, authorization
// and known-empty MFA before browser/session locks. Original provider validity
// cannot outlive the consumed state or original browser. Session, family,
// issuance and browser use remain atomic; propagate every error to abort Work.
// Provisional success grants no credential disclosure. Final admission must
// call CheckCurrent after all later participants and journal writes.
func (e *OAuthSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	consumption, err := w.OAuthSigninConsumption(owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := OAuthSigninSession(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := record.Bindings()
	flow, err := preauth.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	remember, _ := spec.Remember.Bindings()
	flowRemember, rememberErr := flow.Binding.Intent.Remember.Bindings()
	b := consumption.Command
	intent := flow.Binding.Intent
	sameOriginalFlow := string(flow.Binding.ID) == b.AnonymousFlowID && rememberErr == nil && remember == flowRemember && intent.TenantID == b.TenantID && intent.Action == b.OperationID && intent.PolicyID == b.PolicyID && intent.PolicyVersion == b.PolicyVersion
	validityContained := !spec.Authentication.Proof.ExpiresAt.After(consumption.Plan.ExpiresAt) && !spec.Authentication.Proof.ExpiresAt.After(flow.Binding.ExpiresAt)
	if !sameOriginalFlow || !validityContained {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.checkAuthority(bounded, w, owner, command, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	use := PreAuthUse{Command: b, Fingerprint: consumption.Fingerprint, Generation: consumption.Generation}
	if err := ReservePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.requireIssueFamily(bounded, w, spec, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireOAuthSigninIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, feature, transition, err := w.FeatureScope(owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, spec); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := FinalizePreAuth(bounded, w, e.config, preauth, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.CheckCurrent(bounded, w, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation}, nil
}

// CheckCurrent repeats the original account, factor, policy and exclusive-time
// checks and verifies the exact persisted session in Apply or final admission.
// It never changes an epoch, adopts a new account, renews freshness or writes.
func (e *OAuthSigninEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return session.ErrInvalidSessionCommand
	}
	record, err := OAuthSigninSession(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.checkAuthority(bounded, w, owner, command, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return err
	}
	return requireOAuthSigninIssueTime(bounded, w, record)
}

func (e *OAuthSigninEffect) checkAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	account, err := kernel.OAuthSigninAccount(command)
	if err != nil {
		return err
	}
	directory, policy, err := oauthSigninSessionAdmission(e.profile, record, account)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := w.RequireOAuthSigninProviderAccount(ctx, owner, command); err != nil {
		return err
	}
	if err := authority.RequireAuthority(ctx, w, policy.Scope, policy.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.ForbiddenError{}
		}
		return readError(ctx, err)
	}
	spec, _ := record.Bindings()
	vector, _ := spec.Authority.Bindings()
	if _, err := mfapg.RequireOAuthSigninFactors(ctx, w, owner, command, vector.Factor.Binding.Version); err != nil {
		return err
	}
	return requireOAuthSigninIssueTime(ctx, w, record)
}

func oauthSigninSessionAdmission(profile IdentifierAdmissionConfig, record session.Session, account kernel.ProviderAccountAdmission) (kernel.DirectoryAuthorityAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.UserAuthorizationAdmission{}, session.ErrInvalidSessionCommand
	}
	if !oauthSigninRecord(record) || profile.AuthenticationMethod != "oauth" || profile.CredentialKind != identity.CredentialProvider || profile.CredentialOwner != "identity/oauth" {
		return deny()
	}
	spec, _ := record.Bindings()
	vector, _ := spec.Authority.Bindings()
	key, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || vector.Factor.Binding.ScopeKey != key || account.Account.Validate(spec.TenantID, spec.UserID) != nil || account.SocialLinkVersion == 0 {
		return deny()
	}
	// Only owner-key derivation uses the selected user. Work and command retain
	// their original anonymous flow, service actor and historical identity.
	selected := identity.CommandBinding{TenantID: spec.TenantID, UserID: spec.UserID, ActorKind: authorization.SubjectUser, ActorID: identity.ActorID(spec.UserID)}
	directory, credential, policy, err := credentialSessionAdmissionBindings(profile, record, selected, spec.SessionID, spec.Version, vector.Factor, session.OptionalAuthorityBinding{}, auth.AssuranceSingleFactor)
	if err != nil || credential != account.Credential {
		return deny()
	}
	return directory, policy, nil
}

func requireOAuthSigninIssueTime(ctx context.Context, w kernel.Work, record session.Session) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	spec, _ := record.Bindings()
	lifetime, err := record.Lifetime(now)
	if err != nil || now.Before(spec.IssuedAt) || !lifetime.Fresh || spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: now}) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover reads only retained session-owned issuance evidence during the exact
// original coordinator recovery. It returns no session/bearer or current access,
// and cleanup of the live session cannot erase this historical commitment.
func (e *OAuthSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != oauthSessionOperation() || feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}) || transition != (kernel.LifecyclePlan{EventType: "session.created.v1"}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, oauthSigninIssuanceDigest)
	return status, err
}

func oauthSigninIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-oauth-signin-issuance-v1\x00", binding, user, id, family, record)
}
