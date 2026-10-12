package reference

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/session"
)

// HTTPMFAConfiguration explicitly selects the native magic-link/TOTP completion
// route. It requires its actual native TOTP and original pre-auth/device graph;
// no enrollment, trusted-device, OTP or recovery-code route is implied. Actor
// and revision match the trusted primary issuance/admission policy. Namespace
// and key select existing strict shared verification quotas, not MFA authority.
// Omit configuration to expose no route, OpenAPI operation or capability.
type HTTPMFAConfiguration struct {
	TOTPVerify            bool
	ActorID               identity.ActorID
	PolicyRevision        authorization.Revision
	VerificationNamespace string
	VerificationKey       [32]byte
}

type mfaHTTPState struct {
	config   HTTPMFAConfiguration
	preauth  MagicLinkPreAuthConfiguration
	cookie   session.CookiePolicy
	audience string
	timeout  time.Duration
	rate     *identityhttp.ChallengeVerificationRateLimiter
}

func composeMFAHTTP(c StoreConfiguration, base *preAuthHTTPState, rate *httpRateState) (*mfaHTTPState, error) {
	if c.HTTPMFA == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa"}
	if !c.HTTPMFA.TOTPVerify || c.MagicLink == nil || c.MagicLink.TOTP == nil || c.MagicLink.PreAuth == nil || c.MagicLink.Consume == nil || c.MagicLink.Consume.MFA == nil || !c.MagicLink.Request.MFAContinuation || base == nil || base.device == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	h, n, p := *c.HTTPMFA, c.MagicLink.Request, *c.MagicLink.PreAuth
	if p.Origin != base.deployment.Origin || p.ActorID != h.ActorID || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(h.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(h.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, invalid
	}
	if (authorization.DecisionContext{PolicyRevision: h.PolicyRevision, Request: authorization.Request{Tenant: "configuration", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(h.ActorID)}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: "configuration"}}}).Validate() != nil {
		return nil, invalid
	}
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: h.VerificationNamespace, Key: h.VerificationKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &mfaHTTPState{config: h, preauth: p, cookie: c.MagicLink.Consume.Issuer.Cookie, audience: n.Issuer.Audience, timeout: c.MagicLink.TOTP.MaximumDuration, rate: limiter}, nil
}

func (s *Server) mfaFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpMFA
	if h == nil {
		return nil, nil
	}
	owner, err := f.MagicLinkTOTP()
	if err != nil {
		return nil, err
	}
	native, ok := owner.(mfahttp.TOTPVerifyService)
	if !ok {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa"}
	}
	selection := mfahttp.TOTPVerifyConfig{Network: network, Service: native, Rate: h.rate, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, SessionCookie: h.cookie, Device: *s.state.features.httpPreAuth.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: h.audience, Now: time.Now, MaximumDuration: h.timeout}
	feature, err := mfahttp.NewFeature(mfahttp.FeatureConfig{TOTPVerify: &selection})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

// Format redacts deployment and rate key configuration.
func (HTTPMFAConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPMFAConfiguration(redacted)"))
}

// MarshalJSON denies implicit key export.
func (HTTPMFAConfiguration) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit export and map-key disclosure.
func (HTTPMFAConfiguration) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits only a fixed redacted marker.
func (HTTPMFAConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFAConfiguration(redacted)")
}
