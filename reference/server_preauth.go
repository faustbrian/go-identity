package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPreAuthConfiguration explicitly enables the original-flow HTTP route.
// Nil selects no route/metadata. Lifetime is the shared eventual-session policy;
// Device optionally selects non-authenticating correlation. Trusted origin,
// action, callback, cookie and policy come from the same native issuer config.
// Selected HTTP issuance requires its canonical five-minute flow lifetime;
// the direct native issuer retains its independently supported lifetime range.
// Construction copies key slices; callers must not mutate concurrently.
type HTTPPreAuthConfiguration struct {
	Lifetime session.LifetimeConfig
	Device   *session.BrowserDeviceConfig
}

// Format redacts retained device keys and deployment policy.
func (HTTPPreAuthConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPPreAuthConfiguration(redacted)")
}

// MarshalJSON rejects implicit export of retained browser-device custody.
func (HTTPPreAuthConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText rejects implicit export of retained browser-device custody.
func (HTTPPreAuthConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

type preAuthHTTPState struct {
	deployment     OTPPreAuthConfiguration
	lifetime       session.LifetimeConfig
	device         *session.BrowserDeviceConfig
	action, policy string
	version        uint64
}

func composePreAuthHTTP(c StoreConfiguration) (*preAuthHTTPState, error) {
	if c.HTTPPreAuth == nil {
		return nil, nil
	}
	if c.OTP == nil || c.OTP.PreAuth == nil || c.HTTPRate == nil || c.OTP.PreAuth.FlowTTL != 5*time.Minute {
		return nil, identity.InvalidInputError{Field: "reference_http_preauth"}
	}
	p := c.HTTPPreAuth
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, p.Lifetime); err != nil {
		return nil, err
	}
	state := &preAuthHTTPState{deployment: *c.OTP.PreAuth, lifetime: p.Lifetime, action: c.OTP.PreAuthAction, policy: c.OTP.PolicyID, version: c.OTP.PolicyVersion}
	if p.Device != nil {
		device := *p.Device
		device.Keys = slices.Clone(device.Keys)
		if _, err := session.NewBrowserDeviceCodec(device); err != nil {
			return nil, err
		}
		state.device = &device
	}
	return state, nil
}

func (s *Server) preAuthFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPreAuth
	if h == nil {
		return nil, nil
	}
	owner, err := f.PreAuth()
	if err != nil {
		return nil, err
	}
	c := sessionhttp.PreAuthConfig{Network: network, Service: owner, Rate: s.state.httpRate.limiter, Cookie: h.deployment.Cookie, Lifetime: h.lifetime, Origin: identityhttp.Origin(h.deployment.Origin), Action: h.action, CallbackURL: h.deployment.CallbackURL, PolicyID: h.policy, PolicyVersion: h.version, Now: time.Now, MaximumDuration: s.state.features.timeout}
	if selected := s.state.features.httpPasswordSignin; selected != nil {
		password, err := f.PasswordPreAuth()
		if err != nil {
			return nil, err
		}
		c.Methods = []sessionhttp.PreAuthMethod{{Name: "password", Service: password, Action: "identity.password.signin", CallbackURL: selected.preauth.CallbackURL, PolicyID: selected.policy, PolicyVersion: selected.version}}
	}
	if selected := s.state.features.httpPasswordSignup; selected != nil {
		owner, err := f.SignupPreAuth()
		if err != nil {
			return nil, err
		}
		c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "signup", Service: owner, Action: "identity.password.signup", CallbackURL: selected.preauth.CallbackURL, PolicyID: selected.policy, PolicyVersion: selected.version})
	}
	var feature identityhttp.Feature
	if selected := s.state.features.httpAnonymous; selected != nil && selected.config.Signin {
		native := s.state.features.anonymous
		if native == nil || native.preauth == nil {
			return nil, identity.InvalidInputError{Field: "reference_http_anonymous_preauth"}
		}
		c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "anonymous", Service: composedPreAuth{state: s.state, issuer: native.preauth}, Action: "identity.anonymous.signin", CallbackURL: native.preauthConfig.CallbackURL, PolicyID: native.policy, PolicyVersion: native.version})
	}
	if username := s.state.features.httpUsername; username != nil {
		if selected := username.signup; selected != nil {
			owner, err := f.UsernameSignupPreAuth()
			if err != nil {
				return nil, err
			}
			c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "username-signup", Service: owner, Action: "identity.username.signup", CallbackURL: selected.preauth.CallbackURL, PolicyID: selected.policy, PolicyVersion: selected.version})
		}
		if selected := username.signin; selected != nil {
			owner, err := f.UsernameSigninPreAuth()
			if err != nil {
				return nil, err
			}
			c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "username", Service: owner, Action: "identity.username.signin", CallbackURL: selected.preauth.CallbackURL, PolicyID: selected.policy, PolicyVersion: selected.version})
		}
	}
	if selected := s.state.features.httpMagicLink; selected != nil {
		owner, err := f.MagicLinkPreAuth()
		if err != nil {
			return nil, err
		}
		c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "magic-link", Service: owner, Action: "identity.magic-link.consume", CallbackURL: selected.preauth.CallbackURL, PolicyID: selected.policy, PolicyVersion: selected.version})
	}
	if selected := s.state.features.httpPhoneSignin; selected != nil {
		owner, err := f.PhoneSigninPreAuth()
		if err != nil {
			return nil, err
		}
		c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "phone-password", Service: owner, IdentifierBinder: owner, Action: "identity.phone.password-signin", CallbackURL: selected.preauth.CallbackURL, PolicyID: selected.policy, PolicyVersion: selected.version})
	}
	if s.state.features.httpPhoneOTPSignin != nil {
		owner, err := f.PhoneOTPSigninPreAuth()
		if err != nil {
			return nil, err
		}
		c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "phone-otp", Service: owner, IdentifierBinder: owner, Action: "identity.phone.signin", CallbackURL: h.deployment.CallbackURL, PolicyID: h.policy, PolicyVersion: h.version})
	}
	if s.state.features.httpPhonePasswordReset != nil {
		owner, err := f.PhonePasswordResetPreAuth()
		if err != nil {
			return nil, err
		}
		native := s.state.features.phonePasswordReset
		c.Methods = append(c.Methods, sessionhttp.PreAuthMethod{Name: "phone-reset", Service: owner, IdentifierBinder: owner, Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", CallbackURL: native.preauthConfig.CallbackURL, PolicyID: native.policyID, PolicyVersion: native.policyVersion})
	}
	if h.device != nil {
		feature, err = sessionhttp.NewPreAuthFeatureWithBrowserDevice(c, *h.device)
	} else {
		feature, err = sessionhttp.NewPreAuthFeature(c)
	}
	if err != nil {
		return nil, err
	}
	return &feature, nil
}
