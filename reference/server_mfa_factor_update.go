package reference

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/session"
)

// HTTPMFAFactorUpdateConfiguration independently selects cookie-only native
// TOTP rename. Native management/session/original evidence and the shared strict
// rate backend are required, not enrollment, login or regeneration HTTP routes.
// Origins are exact native origins; namespace/key preserve shared quota identity.
type HTTPMFAFactorUpdateConfiguration struct {
	TrustedOrigins []identityhttp.Origin
	RateNamespace  string
	RateKey        [32]byte
}

type mfaFactorUpdateHTTPState struct {
	config              HTTPMFAFactorUpdateConfiguration
	proofs              auth.ReauthenticationSource
	rate                *identityhttp.KeyedSecretRateLimiter
	now                 func() time.Time
	revision            authorization.Revision
	timeout, maximumAge time.Duration
}

func composeMFAFactorUpdateHTTP(c StoreConfiguration, d ReferenceDependencies, owner *mfaEnrollmentState, rate *httpRateState) (*mfaFactorUpdateHTTPState, error) {
	if c.HTTPMFAFactorUpdate == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa_factor_update"}
	if owner == nil || owner.manage == nil || owner.stepup == nil || c.MFAEnrollment == nil || c.MFAEnrollment.FactorManagement == nil || c.MFAEnrollment.ActiveStepUp == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.HTTPRate == nil || rate == nil || c.OTP == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	h := *c.HTTPMFAFactorUpdate
	if len(h.TrustedOrigins) == 0 || len(h.TrustedOrigins) > 16 {
		return nil, invalid
	}
	h.TrustedOrigins = slices.Clone(h.TrustedOrigins)
	for i, origin := range h.TrustedOrigins {
		if !slices.Contains(c.MFAEnrollment.ActiveStepUp.AllowedOrigins, string(origin)) || slices.Contains(h.TrustedOrigins[:i], origin) {
			return nil, invalid
		}
	}
	source, err := mfapg.NewFactorVerificationSource(d.PostgreSQL, c.MFAEnrollment.Native.MaximumDuration)
	if err != nil {
		return nil, invalid
	}
	now := c.Session.Native.Execution.Clock.Now
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: h.RateNamespace, Key: h.RateKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &mfaFactorUpdateHTTPState{config: h, proofs: source, rate: limiter, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion), timeout: c.MFAEnrollment.Native.MaximumDuration, maximumAge: c.MFAEnrollment.FactorManagement.MaximumAge}, nil
}

func (s *Server) mfaFactorUpdateHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*mfahttp.FactorUpdateConfig, error) {
	h := s.state.features.httpMFAFactorUpdate
	if h == nil {
		return nil, nil
	}
	owner, err := f.MFAFactorManagement()
	if err != nil {
		return nil, err
	}
	if s.state.features.session == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_factor_update"}
	}
	sessions := s.state.features.session
	return &mfahttp.FactorUpdateConfig{Network: network, Sessions: sessions.reader, Proofs: h.proofs, Service: owner, Rate: h.rate, Cookie: sessions.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, PolicyRevision: h.revision, Now: h.now, MaximumDuration: h.timeout, MaximumAge: h.maximumAge}, nil
}

// Format redacts borrowed rate keys and deployment policy.
func (HTTPMFAFactorUpdateConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPMFAFactorUpdateConfiguration(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (HTTPMFAFactorUpdateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export.
func (HTTPMFAFactorUpdateConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue emits only a fixed redaction marker.
func (HTTPMFAFactorUpdateConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFAFactorUpdateConfiguration(redacted)")
}
