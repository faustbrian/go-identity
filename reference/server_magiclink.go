package reference

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	magichttp "github.com/faustbrian/go-identity/http/magiclink"
	"github.com/faustbrian/go-identity/session"
)

// HTTPMagicLinkConfiguration independently selects request and/or explicit
// consumption. Neither false is invalid: omit the selection to expose nothing.
// The native original-flow issuer and selected HTTPPreAuth/device/rate graph
// are required. ActorID equals the original issuer's trusted service actor;
// PolicyRevision equals native query/admission/request-key revisions. Consume
// requires a dedicated nonzero verification HMAC key/namespace. No routes,
// migration, worker or network operation starts during construction.
type HTTPMagicLinkConfiguration struct {
	Request, Consume      bool
	ActorID               identity.ActorID
	PolicyRevision        authorization.Revision
	VerificationNamespace string
	VerificationKey       [32]byte
}

// Format redacts deployment rate custody.
func (HTTPMagicLinkConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPMagicLinkConfiguration(redacted)")
}

// MarshalJSON rejects implicit key export.
func (HTTPMagicLinkConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit key export.
func (HTTPMagicLinkConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type magicLinkHTTPState struct {
	config          HTTPMagicLinkConfiguration
	preauth         MagicLinkPreAuthConfiguration
	policy          string
	version         uint64
	cookie          session.CookiePolicy
	audience        string
	timeout         time.Duration
	rate            *identityhttp.ChallengeVerificationRateLimiter
	mfaContinuation bool
	proofLimits     capability.Limits
}

func composeMagicLinkHTTP(c StoreConfiguration, base *preAuthHTTPState, rate *httpRateState) (*magicLinkHTTPState, error) {
	if c.HTTPMagicLink == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_magic_link"}
	if c.MagicLink == nil || c.MagicLink.PreAuth == nil || base == nil || base.device == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	h, n, p := *c.HTTPMagicLink, c.MagicLink.Request, *c.MagicLink.PreAuth
	if !h.Request && !h.Consume || p.FlowTTL != 5*time.Minute || p.Origin != base.deployment.Origin || p.ActorID != h.ActorID || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(h.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(h.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion || uint64(h.PolicyRevision) != n.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.Coordinator.QueryPolicy.Authorization, n.RequestKeys.Policy.Authorization) || !sameServerAuthorization(n.Coordinator.AdmissionPolicy.Authorization, n.RequestKeys.Policy.Authorization) {
		return nil, invalid
	}
	if (authorization.DecisionContext{PolicyRevision: h.PolicyRevision, Request: authorization.Request{Tenant: "configuration", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(h.ActorID)}, Action: "identity.magic-link.request", Resource: authorization.Resource{Type: "identity.magic-link"}}}).Validate() != nil {
		return nil, invalid
	}
	state := &magicLinkHTTPState{config: h, preauth: p, policy: n.PolicyID, version: n.Coordinator.AdmissionPolicy.PolicyVersion, timeout: n.MaximumDuration}
	if h.Consume {
		if c.MagicLink.Consume == nil {
			return nil, invalid
		}
		state.cookie, state.audience = c.MagicLink.Consume.Issuer.Cookie, n.Issuer.Audience
		state.mfaContinuation = c.MagicLink.Consume.MFA != nil
		state.proofLimits = n.Issuer.Crypto.Limits
		owner, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: h.VerificationNamespace, Key: h.VerificationKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return nil, invalid
		}
		state.rate = owner
	}
	return state, nil
}

func (s *Server) magicLinkFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpMagicLink
	if h == nil {
		return nil, nil
	}
	base := s.state.features.httpPreAuth
	selection := magichttp.FeatureConfig{}
	if h.config.Request {
		owner, err := f.MagicLinkRequest()
		if err != nil {
			return nil, err
		}
		selection.Request = &magichttp.RequestConfig{Network: network, Service: owner, Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Device: *base.device, Now: time.Now, MaximumDuration: h.timeout}
	}
	if h.config.Consume {
		owner, err := f.MagicLinkConsume()
		if err != nil {
			return nil, err
		}
		selection.Consume = &magichttp.ConsumeConfig{Network: network, Service: owner, Rate: h.rate, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, SessionCookie: h.cookie, Device: *base.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: h.audience, Now: time.Now, MaximumDuration: h.timeout, MFAContinuation: h.mfaContinuation, ProofLimits: h.proofLimits}
	}
	feature, err := magichttp.NewFeature(selection)
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
