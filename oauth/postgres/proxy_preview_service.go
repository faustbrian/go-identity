package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// ProxyPreviewConfig selects one trusted preview and its production issuer.
// Codec, Clock and the existing signin service are borrowed. The preview must
// install its own binding and ordinary OAuth signin histories before use.
type ProxyPreviewConfig struct {
	TenantID             identity.TenantID
	ActorID              identity.ActorID
	ProductionDeployment string
	Target               oauthproxy.PreviewTarget
	Codec                *oauth.ProxyOIDCEvidenceCodec
	Clock                oauth.Clock
}

// ProxyPreviewBindRequest carries the expected binding from the acknowledged
// trusted production Start response, not from a browser callback or envelope.
// Origin, Network and Device come from the trusted preview transport.
type ProxyPreviewBindRequest struct {
	Binding                 oauth.ProxyOIDCEvidenceBinding
	FlowCookie              auth.BearerCredential
	Origin, Network, Device string
}

// ProxyPreviewCallbackRequest carries one browser callback. FlowID is a
// non-secret locator; the original preview cookie and handoff must both verify.
type ProxyPreviewCallbackRequest struct {
	FlowID          identity.PreAuthTransactionID
	Handoff         oauthproxy.PreviewCompletionRequest
	Network, Device string
}

// ProxyPreviewService binds and completes only the selected native existing-
// account preview signin. It never exchanges provider codes or writes to the
// production database. Both commands reuse the ordinary OAuth coordinator.
type ProxyPreviewService struct {
	signin    *SigninCompletionService
	config    ProxyPreviewConfig
	admission *oauthproxy.PreviewCompletionAdmission
	crypto    capability.Service
}

func NewProxyPreviewService(signin *SigninCompletionService, c ProxyPreviewConfig) (*ProxyPreviewService, error) {
	if signin == nil || signin.start == nil || signin.effect == nil || !rpDirectoryID(string(c.ActorID)) {
		return nil, oauthproxy.CompletionInvalid
	}
	start := signin.start
	if c.Target.Origin != start.config.Origin || start.config.Coordinator.AdmissionPolicy == nil {
		return nil, oauthproxy.CompletionInvalid
	}
	if _, err := oauth.NewValidatedCallbackURL(c.Target.Redirect, start.config.CallbackAllowlist); err != nil {
		return nil, oauthproxy.CompletionInvalid
	}
	admission, err := oauthproxy.NewPreviewCompletionAdmission(oauthproxy.PreviewCompletionConfig{
		TenantID: c.TenantID, ProductionDeployment: c.ProductionDeployment, Target: c.Target,
		PolicyID: start.config.PolicyID, PolicyVersion: start.config.Coordinator.AdmissionPolicy.PolicyVersion,
		FlowKeys: start.config.FlowKeys, Codec: c.Codec, Clock: c.Clock, MaximumDuration: min(start.config.MaximumDuration, 20*time.Second),
	})
	if err != nil {
		return nil, err
	}
	crypto, err := capability.NewService(start.config.Capability.Crypto)
	if err != nil {
		return nil, oauthproxy.CompletionInvalid
	}
	return &ProxyPreviewService{signin: signin, config: c, admission: admission, crypto: crypto}, nil
}

func (s *ProxyPreviewService) registered(b oauth.ProxyOIDCEvidenceBinding) (oauth.ProviderProfile, bool) {
	p, ok := s.signin.start.profiles[b.ProviderID]
	c := s.config
	return p, ok && p.ValidateQueryCallback() == nil && p.Version == b.ProviderVersion && p.Issuer == b.Issuer && p.ClientID == b.ClientID &&
		b.TenantID == c.TenantID && b.ProductionDeployment == c.ProductionDeployment && b.PreviewDeployment == c.Target.Deployment &&
		b.PreviewOrigin == c.Target.Origin && b.PreviewRedirect == c.Target.Redirect && b.Recipient == c.Target.Recipient
}

func (s *ProxyPreviewService) originCommand(l proxyPreviewBindingLocator) identity.CommandBinding {
	op := rpSigninStartOperation()
	c := s.signin.start.config
	return identity.CommandBinding{CommandID: l.OriginCommand, TenantID: l.Tenant, ActorID: s.config.ActorID, ActorKind: authorization.SubjectServiceAccount,
		AnonymousFlowID: string(l.Flow), RecordID: string(l.Flow), CorrelationID: string(l.OriginCommand), OperationID: op.OperationID,
		SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion}
}

// Complete authenticates and consumes the handoff under the original browser
// command. An acknowledged fresh commit alone may disclose a preview session.
// Replay and unknown settlement never reissue the original bearer or CSRF.
func (s *ProxyPreviewService) Complete(ctx context.Context, r ProxyPreviewCallbackRequest) (out oauth.SigninCallbackResult, err error) {
	if s == nil || s.signin == nil || ctx == nil || r.Handoff.Origin != s.config.Target.Origin ||
		!rpASCII(r.Device, 1, 128) || !rpASCII(r.Network, 1, 128) || len(r.Handoff.Envelope) == 0 || len(r.Handoff.Envelope) > 8192 {
		return out, oauthproxy.CompletionInvalid
	}
	if _, err := identity.ParsePreAuthTransactionID(string(r.FlowID)); err != nil {
		return out, oauthproxy.CompletionInvalid
	}
	defer func() {
		if recover() != nil {
			out, err = oauth.SigninCallbackResult{}, oauthproxy.CompletionUnavailable
		}
	}()
	start, tenant := s.signin.start, s.config.TenantID
	ctx, stop := context.WithTimeout(ctx, start.config.MaximumDuration)
	defer stop()
	readStarted := s.config.Clock.Now().UTC()
	row, err := readProxyPreviewRow(ctx, start.pool.Raw(), start.config.Schema, tenant, r.FlowID)
	if err != nil {
		return out, err
	}
	defer row.clear()
	binding, digest, err := openProxyPreviewBinding(ctx, start.envelopes, row.locator, row.binding)
	if err != nil {
		return out, oauthproxy.CompletionDenied
	}
	provider, selected := s.registered(binding.Evidence)
	if !selected {
		return out, oauthproxy.CompletionDenied
	}
	flow, err := sessionpg.ReadPreAuth(ctx, start.pool.Raw(), start.config.Session, tenant, r.FlowID)
	if err != nil {
		return out, err
	}
	flowDigest, err := signinFlowDigest(flow)
	l := row.locator
	origin := s.originCommand(l)
	browser := signinBrowserScope{Tenant: tenant, FlowID: r.FlowID, Cookie: r.Handoff.FlowCookie, Origin: r.Handoff.Origin,
		Callback: s.config.Target.Redirect, Remember: binding.Evidence.Remember}
	if err != nil || flowDigest != binding.PreAuthDigest || checkSigninOriginalBrowser(browser, flow, start.config.FlowKeys, origin.PolicyID, origin.PolicyVersion, s.config.Clock.Now().UTC()) != nil {
		return out, oauthproxy.CompletionDenied
	}
	grant, err := s.openGrant(ctx, row, digest, origin)
	if err != nil {
		return out, err
	}
	wire := bytes.Clone(r.Handoff.Envelope)
	defer clear(wire)
	r.Handoff.Envelope = wire
	command, err := s.previewCallbackCommand(origin, l.CallbackCommand, digest, r)
	if err != nil {
		return out, err
	}
	// Supply the common phase with original browser/provider metadata only.
	// Its preview branch neither creates a synthetic OAuth callback nor opens PKCE.
	p := &signinCallbackPhase{service: s.signin, original: command,
		request: oauth.SigninCallbackRequest{TenantID: tenant, Origin: r.Handoff.Origin, FlowCookie: r.Handoff.FlowCookie, Network: r.Network, Device: r.Device},
		flow: signinCallbackFlow{original: flow, statePlan: grant, loadedAt: readStarted,
			binding: signinRPBinding{Provider: provider, IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt, CallbackCommandID: l.CallbackCommand,
				Input: signinStartInput{Binding: rpStoredBinding(origin), Callback: s.config.Target.Redirect, GlobalVersion: binding.GlobalVersion, TenantVersion: binding.TenantVersion}}},
		preview: &proxyPreviewCallbackInput{row: row, binding: binding, admission: s.admission, request: r.Handoff},
	}
	return s.complete(ctx, p)
}

func (s *ProxyPreviewService) previewCallbackCommand(origin identity.CommandBinding, callback identity.CommandID, digest [32]byte, r ProxyPreviewCallbackRequest) (identity.Command, error) {
	op := signinCallbackOperation()
	b := identity.CommandBinding{CommandID: callback, TenantID: origin.TenantID, ActorID: origin.ActorID, ActorKind: origin.ActorKind,
		AnonymousFlowID: origin.AnonymousFlowID, CorrelationID: string(callback), OperationID: op.OperationID,
		SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: origin.PolicyID, PolicyVersion: origin.PolicyVersion}
	wire := sha256.Sum256(r.Handoff.Envelope)
	input, err := json.Marshal([]string{r.Handoff.Origin, r.Network, r.Device})
	if err != nil {
		return identity.Command{}, oauthproxy.CompletionInvalid
	}
	defer clear(input)
	scope := sha256.Sum256(input)
	return identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{
		previewField("oauth.proxy.expected", digest), previewField("oauth.proxy.envelope", wire), previewField("oauth.proxy.browser", scope),
		previewField("oauth.signin.profile", s.signin.profile),
	}}, r.Handoff.FlowCookie)
}

func (s *ProxyPreviewService) complete(ctx context.Context, p *signinCallbackPhase) (out oauth.SigninCallbackResult, err error) {
	signin := s.signin
	p.issuer, err = session.NewOAuthSessionIssuerWithCSRF(p, signin.config.Issuer, signin.config.CSRF)
	if err != nil {
		return out, err
	}
	coordinator, err := signin.coordinator(p)
	if err != nil {
		return out, err
	}
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || ctx.Err() != nil {
		if err == nil {
			err = oauthproxy.CompletionUnavailable
		}
		return out, err
	}
	if p.prepared == (session.PreparedIssuance{}) || p.execution == nil {
		return out, oauthproxy.CompletionDenied
	}
	p.receipt, p.deliverable = receipt, true
	bound, err := p.issuer.BindOAuth(p.prepared, p.command)
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
	callback, err := oauth.NewValidatedCallbackURL(s.config.Target.Redirect, signin.start.config.CallbackAllowlist)
	if err != nil {
		return out, err
	}
	account := p.execution.account.Account
	spec, err := p.execution.record.Bindings()
	if err != nil || ctx.Err() != nil || !s.config.Clock.Now().Before(spec.Authentication.Proof.ExpiresAt) {
		return out, oauthproxy.CompletionUnavailable
	}
	// Unlike a plain signin result, preview handoff delivery is limited by the
	// exact encrypted observation and original browser cutoff as well as the
	// native authority evidence. Do not derive a new transport lifetime.
	issued.DeliveryValidUntil = spec.Authentication.Proof.ExpiresAt
	result := oauth.IdentityResult{ProviderID: account.Provider, ProviderSubject: account.Subject, UserID: account.UserID,
		AccountID: account.ID, RememberPolicy: p.preview.binding.Evidence.Remember, Outcome: "signin"}
	return oauth.NewSigninCallbackResult(receipt, result, callback, issued, csrf)
}

func previewField(name string, digest [32]byte) identity.FeatureField {
	return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}
}

func (ProxyPreviewBindRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProxyPreviewBindRequest(redacted)"))
}

func (ProxyPreviewCallbackRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProxyPreviewCallbackRequest(redacted)"))
}

func (ProxyPreviewBindRequest) MarshalJSON() ([]byte, error) {
	return nil, oauthproxy.CompletionInvalid
}
func (ProxyPreviewBindRequest) MarshalText() ([]byte, error) {
	return nil, oauthproxy.CompletionInvalid
}
func (ProxyPreviewCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, oauthproxy.CompletionInvalid
}
func (ProxyPreviewCallbackRequest) MarshalText() ([]byte, error) {
	return nil, oauthproxy.CompletionInvalid
}
