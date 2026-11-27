package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"strings"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// OneTapCompletionConfig selects existing-linked-account Google One Tap with
// opaque cookie sessions. FlowKeys is the bounded versioned set of retained
// browser-flow keys. The issuer uses the start owner's authoritative clock.
// HostedDomain is a trusted signed-claim restriction, never a client option.
type OneTapCompletionConfig struct {
	ConfigurationID, PolicyNamespace, Audience, HostedDomain string
	FlowKeys                                                 map[uint32]session.DigestKey
	Issuer                                                   session.IssuerConfig
	CSRF                                                     session.CSRFKey
}

// OneTapCompletionService composes existing owners for one tenant and exact
// Google provider profile. It starts no resources. Borrowed dependencies must
// outlive calls; each callback has independent temporary credential custody.
type OneTapCompletionService struct {
	start     *OneTapStartService
	config    OneTapCompletionConfig
	profile   [32]byte
	validator *onetap.ProviderBoundValidator
	policy    *authoritypg.AuthorityStore
	effect    *sessionpg.OneTapCallbackEffect
}

// NewOneTapCompletionService freezes trusted callback policy without IO,
// entropy or migration. It does not select link, signup, or MFA bypass.
func NewOneTapCompletionService(start *OneTapStartService, c OneTapCompletionConfig) (*OneTapCompletionService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_onetap_completion"}
	if start == nil || start.config == nil || start.selected.Mode != session.PreAuthProviderCallback || !rpASCII(c.ConfigurationID, 1, 128) || len(c.FlowKeys) < 1 || len(c.FlowKeys) > 32 || c.Issuer.Authority != nil {
		return nil, invalid
	}
	base := start.config()
	if c.Issuer.MaximumDuration > base.MaximumDuration {
		return nil, invalid
	}
	c.Issuer.Clock = base.Issuance.Clock
	if _, err := session.NewOneTapSessionIssuerWithCSRF(&oneTapCallbackPhase{}, c.Issuer, c.CSRF); err != nil {
		return nil, invalid
	}
	for version := range c.FlowKeys {
		if version == 0 {
			return nil, invalid
		}
	}
	validator, err := onetap.NewProviderBoundValidator(onetap.ProviderBoundConfig{Provider: base.Provider, TenantID: base.TenantID,
		Origin: base.Issuance.Origin, PolicyID: base.Issuance.PolicyID, PolicyVersion: base.Issuance.PolicyVersion, Clock: base.Issuance.Clock, HostedDomain: c.HostedDomain})
	if err != nil {
		return nil, invalid
	}
	effect, err := sessionpg.NewOneTapCallbackEffect(base.Session, sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: base.GlobalAuthorityID,
		PolicyNamespace: c.PolicyNamespace, Audience: c.Audience, AuthenticationMethod: "oauth", CredentialKind: identity.CredentialProvider, CredentialOwner: "identity/oauth"}, start.selected)
	if err != nil {
		return nil, invalid
	}
	policy, err := authoritypg.NewAuthorityStore(start.pool.Raw(), base.MaximumDuration)
	if err != nil {
		return nil, invalid
	}
	frame, err := json.Marshal(struct {
		Start                                 [32]byte
		ID, Namespace, Audience, HostedDomain string
	}{start.profile, c.ConfigurationID, c.PolicyNamespace, c.Audience, c.HostedDomain})
	if err != nil {
		return nil, invalid
	}
	defer clear(frame)
	c.ConfigurationID, c.PolicyNamespace, c.Audience, c.HostedDomain = strings.Clone(c.ConfigurationID), strings.Clone(c.PolicyNamespace), strings.Clone(c.Audience), strings.Clone(c.HostedDomain)
	c.FlowKeys = maps.Clone(c.FlowKeys)
	return &OneTapCompletionService{start: start, config: c, profile: sha256.Sum256(frame), validator: validator, policy: policy, effect: effect}, nil
}

// OneTapCallbackRequest is borrowed only for the synchronous call. FlowCookie
// must be the original identity browser cookie; Callback carries Google's
// separate double-submit proof. Network comes from the trusted transport.
type OneTapCallbackRequest struct {
	FlowID     identity.PreAuthTransactionID
	FlowCookie auth.BearerCredential
	Callback   onetap.Callback
	Network    netip.Addr
	Device     string
}

// OneTapCallbackResult delivers bearer and CSRF custody only after a fresh
// original commit. Recovery is separate and returns receipt metadata only.
type OneTapCallbackResult struct {
	Session session.IssueResult
	CSRF    session.CSRFToken
}

func (s *OneTapCompletionService) coordinator(p *oneTapCallbackPhase) (*kernel.Coordinator, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.start.directory, a, l, p, capabilitypg.NewParticipant()})
	if err != nil {
		return nil, err
	}
	p.registry = registry
	return kernel.NewCoordinator(s.start.pool, registry, s.start.config().Coordinator)
}

// Callback verifies the original browser and submitted Google credential, then
// commits the linked account's new session and consumes the browser and grant
// atomically. A browser retry cannot deliver credentials again. Use authorised
// receipt-only recovery after an unknown outcome, not another callback.
func (s *OneTapCompletionService) Callback(ctx context.Context, r OneTapCallbackRequest) (out OneTapCallbackResult, err error) {
	if ctx == nil || s == nil || s.start == nil {
		return out, identity.InvalidInputError{Field: "oauth_onetap_callback"}
	}
	c := s.start.config()
	x := r.Callback
	if x.Origin != c.Issuance.Origin || x.Redirect != "" || len(x.CSRFCookies) != 1 || len(x.CSRFBody) != 1 ||
		len(x.CSRFCookies[0]) < 1 || len(x.CSRFCookies[0]) > 1024 || len(x.CSRFBody[0]) < 1 || len(x.CSRFBody[0]) > 1024 ||
		len(x.Credential.IDToken) == 0 || len(x.Credential.IDToken) > c.Provider.Profile().MaxTokenBytes ||
		(!r.Network.IsValid() && r.Device == "") || r.Network.Zone() != "" || len(r.Device) > 128 {
		return out, identity.ForbiddenError{}
	}
	csrfCookie, csrfBody := sha256.Sum256([]byte(x.CSRFCookies[0])), sha256.Sum256([]byte(x.CSRFBody[0]))
	if subtle.ConstantTimeCompare(csrfCookie[:], csrfBody[:]) != 1 {
		return out, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out = OneTapCallbackResult{Session: session.IssueResult{CommandID: out.Session.CommandID, CommitOutcome: out.Session.CommitOutcome}}
			err = identity.UnavailableError{}
		}
	}()
	readStarted := c.Issuance.Clock.Now().UTC()
	record, original, digest, err := s.start.readOneTapCallbackBrowser(ctx, r.FlowID, r.FlowCookie, s.config.FlowKeys)
	if err != nil {
		return out, err
	}
	grant, err := s.start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		return out, err
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	b, err := oneTapCallbackBinding(grant.Original)
	if err != nil {
		return out, err
	}
	proof, err := s.start.issuer.PrepareOneTapCallbackConsumption(ctx, grant.Original, grant.Proof, grant.Grant.ReplayKeyVersion)
	if err != nil {
		return out, err
	}
	if proof != grant.Grant {
		return out, identity.ForbiddenError{}
	}
	q := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: b.TenantID}
	directory, err := s.start.directory.GetDirectoryAuthority(ctx, q)
	if err != nil {
		return out, err
	}
	if !directory.Enabled {
		return out, identity.ForbiddenError{}
	}
	intent := oneTapCallbackIntent(c.IntentKey, digest, x)
	cmd, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: kernel.OneTapCallbackOperation(), Fields: []identity.FeatureField{
		{Name: "onetap.callback.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent[:]}},
		{Name: "onetap.callback.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}},
		{Name: "onetap.callback.directory.global", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: directory.GlobalVersion}},
		{Name: "onetap.callback.directory.tenant", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: directory.TenantVersion}},
	}}, r.FlowCookie)
	if err != nil {
		return out, err
	}
	p := &oneTapCallbackPhase{service: s, request: r, original: cmd, binding: b, browser: record, browserSpec: original,
		cookie: digest, grant: grant, readStarted: readStarted, directory: kernel.DirectoryAuthorityAdmission{Query: q, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}}
	p.issuer, err = session.NewOneTapSessionIssuerWithCSRF(p, s.config.Issuer, s.config.CSRF)
	if err != nil {
		return out, err
	}
	coordinator, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	plan, err = coordinator.PrepareFeaturePreparationPlan(cmd, plan)
	if err != nil {
		return out, err
	}
	out.Session.CommandID = b.CommandID
	receipt, err := coordinator.ExecutePreparedFeature(ctx, cmd, plan)
	out.Session.CommitOutcome, out.Session.RetryAfter = receipt.Outcome, receipt.RetryAfter
	out.Session.Replayed = receipt.Outcome == identity.CommitOutcomeCommitted
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	if !p.applied || p.prepared == (session.PreparedIssuance{}) {
		return out, nil
	}
	out.Session.Replayed = false
	p.receipt, p.deliverable = receipt, true
	bound, err := p.issuer.BindOneTap(p.prepared, p.command)
	if err != nil {
		return out, err
	}
	issued, err := p.issuer.Issue(ctx, bound)
	if err != nil {
		return out, err
	}
	csrf, err := bound.CSRFToken()
	if err != nil {
		return out, err
	}
	return OneTapCallbackResult{Session: issued, CSRF: csrf}, nil
}

// RecoverCallback returns historical metadata through current recovery policy
// and the original flow scope. It never needs a browser, Google or session
// credential and does not release the original cookie or CSRF token.
func (s *OneTapCompletionService) RecoverCallback(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (session.IssueResult, error) {
	if ctx == nil || s == nil || s.start == nil {
		return session.IssueResult{}, identity.InvalidInputError{Field: "oauth_onetap_recovery"}
	}
	c := s.start.config()
	if q.OperationID != oneTapCallbackPurpose || q.TenantID != c.TenantID || q.ActorID != c.Issuance.ActorID || q.ActorKind != authorization.SubjectServiceAccount ||
		q.AnonymousFlowID == "" || q.RecordID != q.AnonymousFlowID || q.UserID != "" || q.LinkMode != 0 {
		return session.IssueResult{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	coordinator, err := s.coordinator(&oneTapCallbackPhase{service: s})
	if err != nil {
		return session.IssueResult{}, err
	}
	receipt, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Binding.CommandID == "" {
		return session.IssueResult{}, err
	}
	if receipt.Feature == nil || receipt.Feature.Operation != kernel.OneTapCallbackOperation() {
		return session.IssueResult{}, identity.UnavailableError{}
	}
	return session.IssueResult{CommandID: receipt.Binding.CommandID, CommitOutcome: receipt.Outcome, Replayed: true, RetryAfter: receipt.RetryAfter}, err
}

func (OneTapCompletionConfig) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }
func (OneTapCompletionConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (OneTapCompletionConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (OneTapCallbackRequest) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[REDACTED]")) }
func (OneTapCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (OneTapCallbackRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (OneTapCallbackResult) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("[REDACTED]")) }
func (OneTapCallbackResult) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (OneTapCallbackResult) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
