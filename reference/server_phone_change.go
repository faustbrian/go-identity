package reference

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPhoneChangeConfiguration opts into cookie-only replacement sending,
// completion and original recovery. PhoneChange and real proof/session/shared
// admission owners are required. The canonical sending route conflicts with
// HTTPPhoneVerification: selecting both fails rather than replacing a handler.
// Device is the existing signed browser profile; sending never mints one.
type HTTPPhoneChangeConfiguration struct {
	Origin         string
	Device         session.BrowserDeviceConfig
	PolicyRevision authorization.Revision
}

type phoneChangeHTTPState struct {
	common *emailOTPVerificationHTTPState
	rate   *identityhttp.KeyedSecretRateLimiter
}

func (h *phoneChangeHTTPState) close() {
	h.common.rate.Close()
	h.rate.Close()
}

func composePhoneChangeHTTP(c StoreConfiguration, owner *phoneChangeState, sessions *sessionState, proofs *passwordVerificationState, shared *httpRateState) (*phoneChangeHTTPState, error) {
	if c.HTTPPhoneChange == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_phone_change"}
	if c.HTTPPhoneVerification != nil || c.PhoneChange == nil || owner == nil || owner.owner == nil || proofs == nil || proofs.proofs == nil || c.PhoneChange.SendPrimary.Transport != session.CredentialCookie || c.PhoneChange.UpdatePrimary.Transport != session.CredentialCookie {
		return nil, invalid
	}
	p := *c.HTTPPhoneChange
	common, err := composeEmailOTPHTTPState(c, HTTPEmailOTPVerificationConfiguration{Origin: p.Origin, Device: p.Device, PolicyRevision: p.PolicyRevision}, c.PhoneChange.Native.RequestKeys.Policy.PolicyVersion, sessions, shared)
	if err != nil {
		return nil, err
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: c.Session.Native.Execution.Clock.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		common.rate.Close()
		return nil, invalid
	}
	return &phoneChangeHTTPState{common: common, rate: rate}, nil
}

func (s *Server) phoneChangeFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPhoneChange
	if h == nil {
		return nil, nil
	}
	if network.Limits.MaximumFields < 44 || network.Limits.MaximumDepth < 3 {
		return nil, identity.InvalidInputError{Field: "reference_http_phone_change"}
	}
	owner, err := f.PhoneChange()
	if err != nil {
		return nil, err
	}
	c := h.common
	feature, err := phonehttp.NewChangeFeature(phonehttp.ChangeConfig{Network: network, Service: owner, Source: owner, Proofs: s.state.features.passwordVerification.proofs, NumberPolicy: s.state.features.phoneChange.policy, DeliveryRate: s.state.httpRate.limiter, UpdateRate: h.rate, RecoveryRate: c.rate, Cookie: s.state.features.session.config.Cookie, Origin: c.origin, CSRFKeys: c.csrf, Device: c.device, PolicyRevision: c.revision, Now: c.now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

// Format redacts signed browser configuration.
func (HTTPPhoneChangeConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPPhoneChangeConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (HTTPPhoneChangeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit configuration and map-key export.
func (HTTPPhoneChangeConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
