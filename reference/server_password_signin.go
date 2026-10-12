package reference

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPasswordSigninConfiguration explicitly selects browser password login and
// the password method on shared original-flow initiation. Nil exposes neither
// login nor method metadata. Native password signin, its PreAuth owner, shared
// HTTP rate admission and original browser-device profile are required. ActorID
// and revision are trusted service policy; callback, keys, cookies, lifetime and
// audience are taken from selected native owners, never independently defaulted.
type HTTPPasswordSigninConfiguration struct {
	ActorID        identity.ActorID
	PolicyRevision authorization.Revision
}

// Format hides trusted service policy.
func (HTTPPasswordSigninConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.HTTPPasswordSigninConfiguration(redacted)")
}

// MarshalJSON rejects implicit runtime composition export.
func (HTTPPasswordSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText rejects implicit runtime composition export.
func (HTTPPasswordSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

type passwordSigninHTTPState struct {
	config           HTTPPasswordSigninConfiguration
	preauth          PasswordPreAuthConfiguration
	sessionCookie    session.CookiePolicy
	audience, policy string
	version          uint64
	mfaContinuation  bool
}

func composePasswordSigninHTTP(c StoreConfiguration, original *preAuthHTTPState) (*passwordSigninHTTPState, error) {
	if c.HTTPPasswordSignin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_password_signin"}
	if c.PasswordSignin == nil || c.PasswordSignin.PreAuth == nil || c.HTTPRate == nil || original == nil || original.device == nil {
		return nil, invalid
	}
	p, n, selection := *c.PasswordSignin.PreAuth, c.PasswordSignin.Native, *c.HTTPPasswordSignin
	if selection.ActorID == "" || selection.ActorID != p.ActorID || selection.PolicyRevision == 0 || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || uint64(selection.PolicyRevision) != n.Coordinator.QueryPolicy.PolicyVersion || uint64(selection.PolicyRevision) != n.Coordinator.AdmissionPolicy.PolicyVersion || p.FlowTTL != 5*time.Minute || p.Origin != original.deployment.Origin {
		return nil, invalid
	}
	flow, err := p.Cookie.DeletionAttributes()
	base, e := original.deployment.Cookie.DeletionAttributes()
	if err != nil || e != nil || flow.Name != "__Host-identity_flow" || flow.String() != base.String() {
		return nil, invalid
	}
	return &passwordSigninHTTPState{config: selection, preauth: p, sessionCookie: n.Issuance.Cookie, audience: n.Profile.Audience, policy: n.PolicyID, version: n.Coordinator.AdmissionPolicy.PolicyVersion, mfaContinuation: c.PasswordSignin.MFA != nil}, nil
}

func (s *Server) passwordSigninHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*passwordhttp.SigninConfig, error) {
	h := s.state.features.httpPasswordSignin
	if h == nil {
		return nil, nil
	}
	p := s.state.features.httpPreAuth
	if p == nil || p.device == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_password_signin"}
	}
	owner, err := f.PasswordSignin()
	if err != nil {
		return nil, err
	}
	// FeatureSet exclusively constructs this guarded native owner handle.
	native := owner.(composedPasswordSignin)
	config := passwordhttp.SigninConfig{Network: network, Service: native, Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(h.preauth.Origin), CallbackURL: h.preauth.CallbackURL, Lifetime: p.lifetime, FlowCookie: h.preauth.Cookie, SessionCookie: h.sessionCookie, Device: *p.device, ActorID: h.config.ActorID, PolicyRevision: h.config.PolicyRevision, Audience: h.audience, Now: time.Now, MaximumDuration: s.state.features.timeout}
	config.MFAContinuation = h.mfaContinuation
	return &config, nil
}

// Each canonical owner contributes once, even when reset and signin coexist.
func (s *Server) passwordFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	config, err := s.passwordResetHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	config.Signin, err = s.passwordSigninHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	config.Signup, err = s.passwordSignupHTTPConfig(network, f)
	if err != nil {
		return nil, err
	}
	if err := s.passwordProtectionHTTPConfig(network, f, &config); err != nil {
		return nil, err
	}
	if config.ResetRequest == nil && config.ResetComplete == nil && config.Signin == nil && config.Signup == nil && config.Change == nil && config.CookieVerification == nil && config.BrowserDeviceBearerVerification == nil {
		return nil, nil
	}
	feature, err := passwordhttp.NewFeature(config)
	if err != nil {
		return nil, err
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range ops {
		id := ops[i].Record.OperationID
		if id == "identity.password.verify" || id == "identity.password.change" {
			ops[i].Handler = s.guardPasswordProtectionLifetime(ops[i].Handler, id)
		}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/password", Operations: ops})
	return &feature, err
}
