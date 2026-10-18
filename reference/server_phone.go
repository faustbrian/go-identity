package reference

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPhoneVerificationConfiguration explicitly selects cookie-only native
// existing-account phone enrollment/verification/history. It requires native
// Phone, sessions, password proof storage and strong shared HTTP admission, not
// their HTTP routes. Device is the existing signed browser deployment profile;
// send never mints a device. Nil exposes no phone route or metadata.
type HTTPPhoneVerificationConfiguration struct {
	Origin         string
	Device         session.BrowserDeviceConfig
	PolicyRevision authorization.Revision
}

func composePhoneVerificationHTTP(c StoreConfiguration, owner *phoneState, sessions *sessionState, shared *httpRateState) (*emailOTPVerificationHTTPState, error) {
	if c.HTTPPhoneVerification == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_phone"}
	if c.Phone == nil || owner == nil || owner.owner == nil || c.Phone.Primary.Transport != session.CredentialCookie || len(c.Phone.Primary.CSRFKeys) == 0 {
		return nil, invalid
	}
	p := *c.HTTPPhoneVerification
	// This existing helper owns only common cookie/Origin/device/strong-rate
	// configuration, not email workflow authority, route or operation selection.
	return composeEmailOTPHTTPState(c, HTTPEmailOTPVerificationConfiguration{Origin: p.Origin, Device: p.Device, PolicyRevision: p.PolicyRevision}, c.Phone.Native.RequestKeys.Policy.PolicyVersion, sessions, shared)
}

func (s *Server) phoneVerificationFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPhoneVerification
	if h == nil {
		return nil, nil
	}
	if network.Limits.MaximumFields < 44 || network.Limits.MaximumDepth < 3 {
		return nil, identity.InvalidInputError{Field: "reference_http_phone"}
	}
	owner, err := f.Phone()
	if err != nil {
		return nil, err
	}
	proofs := s.state.features.passwordVerification
	if proofs == nil || proofs.proofs == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_phone"}
	}
	feature, err := phonehttp.NewVerificationFeature(phonehttp.VerificationConfig{Network: network, Service: owner, Source: owner, Proofs: proofs.proofs, NumberPolicy: s.state.features.phone.policy, DeliveryRate: s.state.httpRate.limiter, VerificationRate: h.rate, Cookie: s.state.features.session.config.Cookie, Origin: h.origin, CSRFKeys: h.csrf, Device: h.device, PolicyRevision: h.revision, Now: h.now, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

// Format redacts signed device key configuration.
func (HTTPPhoneVerificationConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPPhoneVerificationConfiguration(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (HTTPPhoneVerificationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit text/map-key configuration export.
func (HTTPPhoneVerificationConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
