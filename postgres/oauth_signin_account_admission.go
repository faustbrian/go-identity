package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const oauthSigninAccountPrefix = "oauth.signin.account."

func oauthSigninAccountOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func validSigninAccount(a ProviderAccountAdmission) bool {
	account, credential := a.Account, a.Credential
	return account.Validate(account.TenantID, account.UserID) == nil && a.SocialLinkVersion != 0 &&
		credential.Credential.Validate(account.TenantID, account.UserID) == nil &&
		credential.Credential.Kind == identity.CredentialProvider && credential.Credential.Owner == "identity/oauth" &&
		credential.UserAuthorityVersion != 0 && credential.IdentifierAuthorityVersion != 0 && credential.CredentialAuthorityVersion != 0
}

// OAuthSigninAccountFields freezes the existing account and its independent
// link/credential/user epochs into the native signin callback's keyed intent.
// Values are correlated private metadata, not provider proof or authentication.
// Construct only after the owning provider validates its assertion and resolves
// this exact tenant account. No IO, lookup, issuance or freshness renewal runs.
func OAuthSigninAccountFields(a ProviderAccountAdmission) ([]identity.FeatureField, error) {
	if !validSigninAccount(a) {
		return nil, invalidWork()
	}
	fields := make([]identity.FeatureField, 0, 13)
	text := func(name, value string) {
		fields = append(fields, identity.FeatureField{Name: oauthSigninAccountPrefix + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}})
	}
	number := func(name string, value uint64) {
		fields = append(fields, identity.FeatureField{Name: oauthSigninAccountPrefix + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}})
	}
	text("tenant", string(a.Account.TenantID))
	text("user", string(a.Account.UserID))
	text("id", string(a.Account.ID))
	text("provider", a.Account.Provider)
	text("issuer", a.Account.Issuer)
	text("subject", a.Account.Subject)
	number("version", a.Account.Version)
	number("link-version", a.SocialLinkVersion)
	text("credential", string(a.Credential.Credential.ID))
	number("credential-version", a.Credential.Credential.Version)
	number("authority.user", a.Credential.UserAuthorityVersion)
	number("authority.identifier", a.Credential.IdentifierAuthorityVersion)
	number("authority.credential", a.Credential.CredentialAuthorityVersion)
	return fields, nil
}

// OAuthSigninAccount decodes only the exact anonymous native signin callback
// carrying original preauth-cookie custody. Missing, unknown or mistyped account
// fields and mixed/foreign profiles deny. Other namespaces belong to their
// native owners. The result is a frozen observation, never authenticated user
// authority. Bind the selected session and actual provider assertion to it and
// repeat primary admission before committing; do not rediscover a newer account.
func OAuthSigninAccount(command identity.Command) (ProviderAccountAdmission, error) {
	f, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !cookie || code || recovery || bearer || f.Operation != oauthSigninAccountOperation() || f.Binding.UserID != "" || f.Binding.AnonymousFlowID == "" || f.Binding.ActorKind != authorization.SubjectServiceAccount {
		return ProviderAccountAdmission{}, invalidWork()
	}
	fields := make(map[string]identity.FeatureValue, 13)
	for _, field := range f.Fields {
		if name, selected := strings.CutPrefix(field.Name, oauthSigninAccountPrefix); selected {
			fields[name] = field.Value
		}
	}
	valid := true
	text := func(name string) string {
		v, exists := fields[name]
		delete(fields, name)
		if !exists || v.Kind != identity.FeatureText {
			valid = false
		}
		return v.Text
	}
	number := func(name string) uint64 {
		v, exists := fields[name]
		delete(fields, name)
		if !exists || v.Kind != identity.FeatureUint64 {
			valid = false
		}
		return v.Uint64
	}
	a := identity.Account{
		TenantID: identity.TenantID(text("tenant")), UserID: identity.UserID(text("user")),
		ID: identity.AccountID(text("id")), Provider: text("provider"),
		Issuer: text("issuer"), Subject: text("subject"), Version: number("version"),
	}
	credential := identity.CredentialRef{
		TenantID: a.TenantID, UserID: a.UserID, ID: identity.CredentialID(text("credential")),
		Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: number("credential-version"),
	}
	out := ProviderAccountAdmission{
		Account: a, SocialLinkVersion: number("link-version"),
		Credential: CredentialAdmission{
			Credential: credential, UserAuthorityVersion: number("authority.user"),
			IdentifierAuthorityVersion: number("authority.identifier"), CredentialAuthorityVersion: number("authority.credential"),
		},
	}
	if !valid || len(fields) != 0 || a.TenantID != f.Binding.TenantID || !validSigninAccount(out) {
		return ProviderAccountAdmission{}, invalidWork()
	}
	return out, nil
}

// RequireOAuthSigninProviderAccount fences the command's original selected
// provider account without retargeting its anonymous flow, service actor, audit
// or replay identity. Only the exact native signin participant's synchronous
// Apply or final commit check may call it with the original command instance;
// reconstructed metadata cannot acquire this custody. Invalid/stale/foreign
// input poisons live Work. Generic admission cannot select a provider subject.
//
// It borrows the existing user/credential/account/association lock and exclusive
// expiry checks; all locks remain with the sole coordinator until Work closes.
// The returned primary clock sample is not a validity lease. The native owners
// must still verify provider proof, original browser possession, current policy,
// factors and risk. They consume state with session effects in the original
// transaction. This check creates no transaction, callback, session, exchange
// or renewed authority.
func (w Work) RequireOAuthSigninProviderAccount(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	// The coordinator retains the original instance separately for its final
	// check. Apply-only command identity intentionally remains unavailable there.
	// Do not broaden RequireFeatureCommand or infer custody from equal metadata.
	if w.state.featureApplying {
		if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
			return time.Time{}, err
		}
	} else if w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	expected, decodeErr := OAuthSigninAccount(command)
	spec, _ := command.Feature()
	if decodeErr != nil || spec.Binding != b || f.Operation != oauthSigninAccountOperation() || f.Contributor != (ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}) || life.BeforeVersion != 0 || life.AfterVersion != 0 {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	// Only the lookup key uses the provider-selected user. Work retains the
	// original anonymous command for every effect, audit and recovery phase.
	b.UserID = expected.Account.UserID
	return w.requireActiveProviderAccount(ctx, b, expected)
}
