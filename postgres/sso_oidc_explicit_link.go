package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const ssoOIDCExplicitLinkField = "sso.oidc.explicit-link.identity-intent"

// SSOOIDCExplicitLinkCallbackOperation selects the authenticated-member
// schema of the existing enterprise OIDC callback. Anonymous sign-in cannot
// select it. Declaration and command shape do not authenticate an actor or
// authorize use; the owning participant must bind fresh local consent and the
// original provider transaction to the same member.
func SSOOIDCExplicitLinkCallbackOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oidc", OperationID: ssoOIDCSigninPurpose,
		SchemaID: "sso-enterprise-oidc-explicit-link-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func validSSOOIDCExplicitLinkBinding(b identity.CommandBinding) bool {
	start, err := identity.ParseCommandID(b.RecordID)
	return err == nil && start != b.CommandID && b.ValidateFor(SSOOIDCExplicitLinkCallbackOperation()) == nil &&
		b.ActorKind == authorization.SubjectUser && string(b.ActorID) == string(b.UserID)
}

// SSOOIDCExplicitLinkIntent describes a new provider credential for the exact
// existing member authorized by the original link flow. The actor credential
// and deadline are the owner's original evidence, not an authorization grant.
// This profile neither matches an email nor reactivates a retired subject.
// Callers must not mutate Change.Method during or between uses of the intent.
type SSOOIDCExplicitLinkIntent struct {
	Change          identity.AccountLinkChange
	ActorCredential CredentialAdmission
	ValidUntil      time.Time
}

// Format redacts provider subjects and correlated authority.
func (SSOOIDCExplicitLinkIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOIDCExplicitLinkIntent(redacted)"))
}

// MarshalJSON rejects export of private intent.
func (SSOOIDCExplicitLinkIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidSSOOIDCExplicitLink()
}

func invalidSSOOIDCExplicitLink() error {
	return identity.InvalidInputError{Field: "sso_oidc_explicit_link"}
}

// SSOOIDCExplicitLinkField freezes a detached, digest-only commitment over
// the exact new enterprise account and credential, original actor credential
// and security epochs, and the original evidence deadline. This structural
// check performs no I/O and grants no authority.
func SSOOIDCExplicitLinkField(i SSOOIDCExplicitLinkIntent) (identity.FeatureField, error) {
	c, a := i.Change, i.ActorCredential
	if c.Mode != identity.AccountLinkExplicit || c.ExpectedAccountVersion != 0 || c.ExpectedSocialLinkVersion != 1 || !validSSOOIDCJITProviderNamespace(c.Account.Provider) || c.Method == nil {
		return identity.FeatureField{}, invalidSSOOIDCExplicitLink()
	}
	m := *c.Method
	c.Method = &m
	if m.Credential.Kind != identity.CredentialProvider || m.Credential.Owner != "sso" || m.Credential.Version != 1 || !m.Usable || !m.ExpiresAt.IsZero() {
		return identity.FeatureField{}, invalidSSOOIDCExplicitLink()
	}
	if a.Credential.Validate(c.Account.TenantID, c.Account.UserID) != nil || a.Credential.ID == m.Credential.ID ||
		a.UserAuthorityVersion == 0 || a.IdentifierAuthorityVersion == 0 || a.CredentialAuthorityVersion != c.ExpectedCredentialVersion || !postgresExactTime(i.ValidUntil) {
		return identity.FeatureField{}, invalidSSOOIDCExplicitLink()
	}
	change, err := identity.AccountLinkIntentDigest(c)
	if err != nil {
		return identity.FeatureField{}, invalidSSOOIDCExplicitLink()
	}
	wire := cborMap(map[string][]byte{
		"domain":                cborText("golib.sso.oidc.explicit-link.identity-intent.v1"),
		"change":                cborBytes(change[:]),
		"actor_credential":      cborText(string(a.Credential.ID)),
		"actor_kind":            cborUint(uint64(a.Credential.Kind)),
		"actor_owner":           cborText(a.Credential.Owner),
		"actor_record_version":  cborUint(a.Credential.Version),
		"user_authority":        cborUint(a.UserAuthorityVersion),
		"identifier_authority":  cborUint(a.IdentifierAuthorityVersion),
		"original_evidence_end": cborText(i.ValidUntil.UTC().Format(time.RFC3339Nano)),
	})
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return identity.FeatureField{Name: ssoOIDCExplicitLinkField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
}

type ssoOIDCExplicitLinkProgress struct {
	account     ProviderAccountAdmission
	actor       CredentialAdmission
	userVersion uint64
	validUntil  time.Time
}

// ApplySSOOIDCExplicitLink provisionally links a previously unseen subject to
// the exact active member in the original authenticated callback. The caller
// must prove the original session/consent, provider assertion, current provider
// and membership authority inside the same Work. The kernel requires the
// actual callback capability consumption and rechecks its own credential and
// subject authority. Any denial poisons Work.
//
// This reuses the account writer. It does not create a user, membership or
// session. It advances the existing user's credential epoch once; callers
// must not treat the pre-link session as newly authenticated. Install the
// same account and retired-subject index history as for enterprise OIDC JIT.
func (r *Repository) ApplySSOOIDCExplicitLink(ctx context.Context, w Work, owner FeatureExecutionContributor, command identity.Command, intent SSOOIDCExplicitLinkIntent) (ProviderAccountAdmission, error) {
	zero := ProviderAccountAdmission{}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return zero, err
	}
	fail := func(err error) (ProviderAccountAdmission, error) { return zero, w.fail(ctx, err) }
	operation := SSOOIDCExplicitLinkCallbackOperation()
	binding, feature, lifecycle, err := w.FeatureScope(owner)
	profile, _ := providerSigninProfile(operation)
	if err != nil || feature.Operation != operation || feature.Contributor != profile.Contrib || lifecycle != profile.Lifecycle ||
		r == nil || r.read == nil || w.state.ssoOIDCExplicitLink != nil || !validSSOOIDCExplicitLinkBinding(binding) {
		return fail(invalidSSOOIDCExplicitLink())
	}
	consumed, err := w.providerSigninConsumption(owner, operation)
	if err != nil || intent.ValidUntil.After(consumed.Plan.ExpiresAt) || !enlistedSSOOIDCLinkRepository(r, w.state.execution.reservation.plan) {
		return fail(invalidSSOOIDCExplicitLink())
	}
	change := intent.Change
	if change.Account.TenantID != binding.TenantID || change.Account.UserID != binding.UserID || !matchesSSOOIDCExplicitLinkCommand(command, binding, intent) {
		return fail(invalidSSOOIDCExplicitLink())
	}
	method := *change.Method
	change.Method = &method
	now, err := w.requireActiveCredentialLock(ctx, binding, intent.ActorCredential, true, change.ExpectedUserVersion)
	if err != nil {
		return zero, err
	}
	if !now.Before(intent.ValidUntil) || intent.ValidUntil.Sub(now) > 20*time.Second {
		return fail(identity.ForbiddenError{})
	}
	if err := requireUnoccupiedSSOOIDCSubject(ctx, w, change.Account); err != nil {
		return zero, err
	}
	state, now, err := lockAccountLinkState(ctx, w, change)
	if err != nil {
		return zero, err
	}
	if !now.Before(intent.ValidUntil) {
		return fail(identity.ForbiddenError{})
	}
	mutation, err := identity.ApplyAccountLink(state, change, now)
	if err != nil {
		return fail(err)
	}
	if err := persistAccountLinkMutation(ctx, w, change, mutation); err != nil {
		return zero, err
	}
	actor := intent.ActorCredential
	actor.CredentialAuthorityVersion = mutation.CredentialVersion
	linked := actor
	linked.Credential = method.Credential
	account := ProviderAccountAdmission{Account: mutation.Account, SocialLinkVersion: mutation.SocialLinkVersion, Credential: linked}
	w.state.ssoOIDCExplicitLink = &ssoOIDCExplicitLinkProgress{account: account, actor: actor, userVersion: mutation.Access.User.Version, validUntil: intent.ValidUntil}
	return account, nil
}

func enlistedSSOOIDCLinkRepository(repository *Repository, plan *admittedKernelPlan) bool {
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == repository {
			return true
		}
	}
	return false
}

func matchesSSOOIDCExplicitLinkCommand(command identity.Command, binding identity.CommandBinding, intent SSOOIDCExplicitLinkIntent) bool {
	spec, ok := command.Feature()
	_, bearer := command.SessionToken()
	if !ok || !bearer || spec.Binding != binding || spec.Operation != SSOOIDCExplicitLinkCallbackOperation() {
		return false
	}
	wanted, err := SSOOIDCExplicitLinkField(intent)
	if err != nil {
		return false
	}
	for _, field := range spec.Fields {
		if field.Name == wanted.Name {
			return field.Value.Kind == wanted.Value.Kind && bytes.Equal(field.Value.Bytes, wanted.Value.Bytes)
		}
	}
	return false
}

func (w Work) checkSSOOIDCExplicitLinkFinal() error {
	progress := w.state.ssoOIDCExplicitLink
	ctx, binding := w.state.ctx, w.state.binding
	if progress == nil || w.state.oauthSigninStage != oauthSigninStateFinalized {
		return w.fail(ctx, invalidSSOOIDCExplicitLink())
	}
	// Check the exact successor created by this Work, not a new observation
	// that would renew the actor's original proof after the epoch changed.
	if _, err := w.requireActiveCredentialLock(ctx, binding, progress.actor, false, progress.userVersion); err != nil {
		return err
	}
	now, err := w.requireActiveProviderAccount(ctx, binding, progress.account)
	if err != nil {
		return err
	}
	if !now.Before(progress.validUntil) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
