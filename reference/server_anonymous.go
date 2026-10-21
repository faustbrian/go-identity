package reference

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

// HTTPAnonymousConfiguration selects each browser operation independently.
// Read extends the existing session GET with a separate unprivileged guest
// projection; it requires HTTPSession cookie selection. Signin adds the named
// anonymous original-flow method. All selected mutations require the original
// signed device/origin profile; Deletion and Upgrade share one native keyed
// secret-rate namespace/key across both routes. Omission advertises nothing.
type HTTPAnonymousConfiguration struct {
	Signin, Read, Deletion, Upgrade bool
	SecretNamespace                 string
	SecretKey                       [32]byte
}

func (HTTPAnonymousConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.HTTPAnonymousConfiguration(redacted)")
}
func (HTTPAnonymousConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (HTTPAnonymousConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type anonymousHTTPState struct {
	config HTTPAnonymousConfiguration
	secret *identityhttp.KeyedSecretRateLimiter
}

func (s *anonymousHTTPState) close() {
	if s != nil && s.secret != nil {
		s.secret.Close()
	}
}

func composeAnonymousHTTP(c StoreConfiguration, n *anonymousState, p *preAuthHTTPState, rate *httpRateState) (*anonymousHTTPState, error) {
	if c.HTTPAnonymous == nil {
		return nil, nil
	}
	h := *c.HTTPAnonymous
	invalid := identity.InvalidInputError{Field: "reference_http_anonymous"}
	if n == nil || c.Anonymous == nil || c.HTTPRate == nil || rate == nil || p == nil || p.device == nil || (!h.Signin && !h.Read && !h.Deletion && !h.Upgrade) || n.preauthConfig.FlowTTL != 5*time.Minute || n.preauthConfig.Origin != p.deployment.Origin || h.Deletion && n.deletion == nil || h.Upgrade && (n.upgrade == nil || c.Session == nil || c.PasswordVerification == nil) || h.Read && (c.HTTPSession == nil || c.HTTPSession.Transport != session.CredentialCookie) {
		return nil, invalid
	}
	flow, e := n.preauthConfig.Cookie.DeletionAttributes()
	base, e2 := p.deployment.Cookie.DeletionAttributes()
	if e != nil || e2 != nil || flow.Name != "__Host-identity_flow" || flow.String() != base.String() {
		return nil, invalid
	}
	out := &anonymousHTTPState{config: h}
	if h.Deletion || h.Upgrade {
		var err error
		out.secret, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: h.SecretNamespace, Key: h.SecretKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return nil, invalid
		}
	}
	return out, nil
}

func (s *Server) anonymousFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	f := s.state.features
	if f == nil || f.httpAnonymous == nil {
		return nil, nil
	}
	h, n := f.httpAnonymous, f.anonymous
	if n == nil || f.httpPreAuth == nil || f.httpPreAuth.device == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_anonymous"}
	}
	if !h.config.Signin && !h.config.Deletion && !h.config.Upgrade {
		return nil, nil
	}
	var c anonymoushttp.FeatureConfig
	if h.config.Signin {
		c.Signin = &anonymoushttp.SigninConfig{Network: network, Service: n.signin, Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(n.preauthConfig.Origin), CallbackURL: n.preauthConfig.CallbackURL, Lifetime: f.httpPreAuth.lifetime, FlowCookie: n.preauthConfig.Cookie, SessionCookie: n.cookie, Device: *f.httpPreAuth.device, ActorID: n.preauthConfig.ActorID, PolicyRevision: authorization.Revision(n.version), Audience: n.profile.Audience, Now: time.Now, MaximumDuration: f.timeout}
	}
	if h.config.Deletion {
		c.Deletion = &anonymoushttp.DeletionConfig{Network: network, Service: n.deletion, Rate: h.secret, Cookie: n.cookie, Origin: identityhttp.Origin(n.preauthConfig.Origin), Device: *f.httpPreAuth.device, Now: time.Now, MaximumDuration: f.timeout}
	}
	if h.config.Upgrade {
		if f.passwordVerification == nil || f.passwordVerification.proofs == nil || f.session == nil {
			return nil, identity.InvalidInputError{Field: "reference_http_anonymous_upgrade"}
		}
		c.Upgrade = &anonymoushttp.UpgradeConfig{Network: network, Service: n.upgrade, Sessions: f.session.reader, Proofs: f.passwordVerification.proofs, Subjects: n.subjects, Rate: h.secret, GuestCookie: n.cookie, TargetCookie: f.session.config.Cookie, Origin: identityhttp.Origin(n.preauthConfig.Origin), Device: *f.httpPreAuth.device, PolicyRevision: authorization.Revision(n.version), Audience: n.profile.Audience, Now: time.Now, MaximumDuration: f.timeout}
	}
	feature, err := anonymoushttp.NewFeature(c)
	if err != nil {
		return nil, err
	}
	ops := feature.Operations()
	for i := range ops {
		ops[i].Handler = s.guardSessionLifetime(ops[i].Handler)
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/anonymous", Operations: ops})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

func (s *Server) anonymousGetSelection() (*sessionhttp.AnonymousGetConfig, error) {
	f := s.state.features
	if f == nil || f.httpAnonymous == nil || !f.httpAnonymous.config.Read {
		return nil, nil
	}
	if f.anonymous == nil || f.anonymous.reader == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_anonymous_read"}
	}
	return &sessionhttp.AnonymousGetConfig{Sessions: f.anonymous.reader, Cookie: f.anonymous.cookie}, nil
}
