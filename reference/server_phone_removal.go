package reference

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPhoneRemovalConfiguration explicitly selects cookie-only authenticated
// phone self-removal. Native PhoneRemoval, proof storage, session cookie policy
// and strong shared HTTPRate must exist; their HTTP routes are not required.
// Origin and PolicyRevision are trusted deployment inputs, never request claims.
// Nil adds neither a route nor advertised capability.
type HTTPPhoneRemovalConfiguration struct {
	Origin         string
	PolicyRevision authorization.Revision
}

type phoneRemovalHTTPState struct {
	config HTTPPhoneRemovalConfiguration
	rate   *identityhttp.KeyedSecretRateLimiter
}

func composePhoneRemovalHTTP(c StoreConfiguration, owner *phoneRemovalState, proofs *passwordVerificationState, shared *httpRateState) (*phoneRemovalHTTPState, error) {
	if c.HTTPPhoneRemoval == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_phone_removal"}
	if owner == nil || owner.owner == nil || proofs == nil || proofs.proofs == nil || c.PhoneRemoval == nil || c.PhoneRemoval.Primary.Transport != session.CredentialCookie || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.OTP == nil || shared == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	p := *c.HTTPPhoneRemoval
	if p.PolicyRevision == 0 || uint64(p.PolicyRevision) != c.OTP.RequestKeys.Policy.PolicyVersion || p.Origin == "" {
		return nil, invalid
	}
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: c.Session.Native.Execution.Clock.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &phoneRemovalHTTPState{config: p, rate: limiter}, nil
}

func (s *Server) phoneRemovalFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	h := s.state.features.httpPhoneRemoval
	if h == nil {
		return nil, nil
	}
	if network.Limits.MaximumFields < 6 || network.Limits.MaximumDepth < 1 {
		return nil, identity.InvalidInputError{Field: "reference_http_phone_removal"}
	}
	owner, err := f.PhoneRemoval()
	if err != nil {
		return nil, err
	}
	feature, err := phonehttp.NewRemovalFeature(phonehttp.RemovalConfig{Network: network, Service: owner, Proofs: s.state.features.passwordVerification.proofs, Rate: h.rate, NumberPolicy: s.state.features.phoneRemoval.policy, Cookie: s.state.features.session.config.Cookie, Origin: identityhttp.Origin(h.config.Origin), PolicyRevision: h.config.PolicyRevision, MaximumDuration: s.state.features.timeout})
	if err != nil {
		return nil, err
	}
	return &feature, nil
}

// Format redacts deployment selection.
func (HTTPPhoneRemovalConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPPhoneRemovalConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (HTTPPhoneRemovalConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit configuration export.
func (HTTPPhoneRemovalConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
