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

// HTTPMFADisableConfiguration independently selects native cookie-only disable.
// It requires actual selected disable/session/proof/rate owners, not factor-
// update or step-up HTTP. Trusted origins must match exact native origins.
type HTTPMFADisableConfiguration struct {
	TrustedOrigins []identityhttp.Origin
	RateNamespace  string
	RateKey        [32]byte
}

type mfaDisableHTTPState struct {
	config              HTTPMFADisableConfiguration
	proofs              auth.ReauthenticationSource
	rate                *identityhttp.KeyedSecretRateLimiter
	now                 func() time.Time
	revision            authorization.Revision
	timeout, maximumAge time.Duration
}

func composeMFADisableHTTP(c StoreConfiguration, d ReferenceDependencies, owner *mfaEnrollmentState, rate *httpRateState) (*mfaDisableHTTPState, error) {
	if c.HTTPMFADisable == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa_disable"}
	if owner == nil || owner.disable == nil || owner.stepup == nil || c.MFAEnrollment == nil || c.MFAEnrollment.Disable == nil || c.MFAEnrollment.ActiveStepUp == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.HTTPRate == nil || rate == nil || c.OTP == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	h := *c.HTTPMFADisable
	if len(h.TrustedOrigins) < 1 || len(h.TrustedOrigins) > 16 {
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
	return &mfaDisableHTTPState{config: h, proofs: source, rate: limiter, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion), timeout: c.MFAEnrollment.Native.MaximumDuration, maximumAge: c.MFAEnrollment.Disable.MaximumAge}, nil
}

func (s *Server) mfaDisableHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*mfahttp.DisableConfig, error) {
	h := s.state.features.httpMFADisable
	if h == nil {
		return nil, nil
	}
	owner, err := f.MFADisable()
	if err != nil {
		return nil, err
	}
	if s.state.features.session == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_disable"}
	}
	sessions := s.state.features.session
	return &mfahttp.DisableConfig{Network: network, Sessions: sessions.reader, Proofs: h.proofs, Service: owner, Rate: h.rate, Cookie: sessions.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, PolicyRevision: h.revision, Now: h.now, MaximumDuration: h.timeout, MaximumAge: h.maximumAge}, nil
}

// Format redacts policy and borrowed rate-key custody.
func (HTTPMFADisableConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.HTTPMFADisableConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment configuration export.
func (HTTPMFADisableConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit text/map-key configuration export.
func (HTTPMFADisableConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue exposes only a fixed redaction marker.
func (HTTPMFADisableConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFADisableConfiguration(redacted)")
}
