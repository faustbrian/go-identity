package reference

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
)

// HTTPUsernameConfiguration selects each username route independently. Nil
// exposes no route or original-flow method. Signup/Signin require the native
// profile, original browser-device issuer and HTTP rate owner; ActorID and
// PolicyRevision are trusted service policy for those anonymous entry points.
// Availability borrows the native durable advisory owner. Rename independently
// selects cookie-only protected transport with explicit origins and rate keys;
// the graph supplies its actual signed proof source and session cookie policy.
// Native username MFA continuation is not selected; enrolled/unknown state denies.
type HTTPUsernameConfiguration struct {
	Signup, Signin, Availability bool
	ActorID                      identity.ActorID
	PolicyRevision               authorization.Revision
	Rename                       *HTTPPasswordProtectionConfiguration
}

type usernameHTTPState struct {
	signup    *passwordSignupHTTPState
	signin    *passwordSigninHTTPState
	available bool
	rename    *HTTPPasswordProtectionConfiguration
	rate      *identityhttp.KeyedSecretRateLimiter
	revision  authorization.Revision
}

func (h *usernameHTTPState) close() {
	if h != nil && h.rate != nil {
		h.rate.Close()
	}
}

func composeUsernameHTTP(c StoreConfiguration, native *usernameState, original *preAuthHTTPState, proofs *passwordVerificationState, rate *httpRateState) (*usernameHTTPState, error) {
	if c.HTTPUsername == nil {
		return nil, nil
	}
	h := *c.HTTPUsername
	invalid := identity.InvalidInputError{Field: "reference_http_username"}
	if c.Username == nil || native == nil || !h.Signup && !h.Signin && !h.Availability && h.Rename == nil {
		return nil, invalid
	}
	state := &usernameHTTPState{available: h.Availability}
	if h.Availability && native.available == nil {
		return nil, invalid
	}
	if h.Signup {
		if native.signup == nil || native.signupPreauth == nil {
			return nil, invalid
		}
		selected := c
		selected.HTTPPasswordSignup = &HTTPPasswordSignupConfiguration{ActorID: h.ActorID, PolicyRevision: h.PolicyRevision}
		var err error
		state.signup, err = composePasswordSignupHTTP(selected, original)
		if err != nil {
			return nil, err
		}
	}
	if h.Signin {
		if native.signin == nil || native.signinPreauth == nil || c.PasswordSignin == nil {
			return nil, invalid
		}
		selected, profile := c, *c.PasswordSignin
		profile.MFA, profile.TOTP, profile.Recovery, profile.OTP = nil, nil, nil, nil
		selected.PasswordSignin = &profile
		selected.HTTPPasswordSignin = &HTTPPasswordSigninConfiguration{ActorID: h.ActorID, PolicyRevision: h.PolicyRevision}
		var err error
		state.signin, err = composePasswordSigninHTTP(selected, original)
		if err != nil {
			return nil, err
		}
	}
	if h.Rename != nil {
		if native.rename == nil || proofs == nil || proofs.proofs == nil || proofs.cookie == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.OTP == nil || c.HTTPRate == nil || rate == nil {
			return nil, invalid
		}
		protection, err := copyPasswordProtectionHTTP(h.Rename, true)
		if err != nil || protection.Transport != session.CredentialCookie {
			return nil, invalid
		}
		state.rename = &protection
		state.revision = authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion)
		state.rate, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: protection.RateNamespace, Key: protection.RateKey, Now: c.Session.Native.Execution.Clock.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (s *Server) usernameFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpUsername
	if h == nil {
		return nil, nil
	}
	config := passwordhttp.UsernameFeatureConfig{}
	p := s.state.features.httpPreAuth
	if selected := h.signup; selected != nil {
		owner, err := f.UsernameSignup()
		if err != nil {
			return nil, err
		}
		config.Signup = &passwordhttp.SignupConfig{Network: network, Service: owner.(composedUsernameSignup), Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(selected.preauth.Origin), CallbackURL: selected.preauth.CallbackURL, Lifetime: p.lifetime, FlowCookie: selected.preauth.Cookie, Device: *p.device, FieldSchema: selected.fields, ActorID: selected.config.ActorID, PolicyRevision: selected.config.PolicyRevision, Now: time.Now, MaximumDuration: s.state.features.timeout}
	}
	if selected := h.signin; selected != nil {
		owner, err := f.UsernameSignin()
		if err != nil {
			return nil, err
		}
		config.Signin = &passwordhttp.SigninConfig{Network: network, Service: owner.(composedUsernameSignin), Rate: s.state.httpRate.limiter, Origin: identityhttp.Origin(selected.preauth.Origin), CallbackURL: selected.preauth.CallbackURL, Lifetime: p.lifetime, FlowCookie: selected.preauth.Cookie, SessionCookie: selected.sessionCookie, Device: *p.device, ActorID: selected.config.ActorID, PolicyRevision: selected.config.PolicyRevision, Audience: selected.audience, Now: time.Now, MaximumDuration: s.state.features.timeout}
	}
	if h.available {
		owner, err := f.UsernameAvailability()
		if err != nil {
			return nil, err
		}
		config.Available = &passwordhttp.UsernameAvailabilityConfig{Network: network, Service: owner, MaximumDuration: s.state.features.timeout}
	}
	if h.rename != nil {
		owner, err := f.UsernameRename()
		if err != nil {
			return nil, err
		}
		config.Rename = &passwordhttp.UsernameRenameConfig{Network: network, Service: owner, Proofs: s.state.features.passwordVerification.proofs, Rate: h.rate, Cookie: s.state.features.session.config.Cookie, TrustedOrigins: h.rename.TrustedOrigins, PolicyRevision: h.revision, MaximumDuration: s.state.features.timeout}
	}
	feature, err := passwordhttp.NewUsernameFeature(config)
	if err != nil {
		return nil, err
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range ops {
		if ops[i].Record.OperationID == "identity.username.update" {
			ops[i].Handler = s.guardPasswordProtectionLifetime(ops[i].Handler, "identity.username.update")
		}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/username", Operations: ops})
	return &feature, err
}

// Format redacts deployment policy and rate keys.
func (HTTPUsernameConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPUsernameConfiguration(redacted)")
}

// MarshalJSON refuses implicit policy/key export.
func (HTTPUsernameConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText refuses implicit policy/key export.
func (HTTPUsernameConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}
