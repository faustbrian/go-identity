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

// HTTPMFARecoveryRegenerationConfiguration independently selects cookie-only
// whole-set replacement, not step-up issuance, enrollment or login routes.
// Native replacement/session/original proof and shared strict rate owners are
// required. Origins must be exact native allowed origins. Namespace/key retain
// stable shared secret quota identity; count/freshness come from native policy.
type HTTPMFARecoveryRegenerationConfiguration struct {
	TrustedOrigins []identityhttp.Origin
	RateNamespace  string
	RateKey        [32]byte
}

// Format redacts deployment policy and rate keys.
func (HTTPMFARecoveryRegenerationConfiguration) Format(s fmt.State, _ rune) {
	s.Write([]byte("reference.HTTPMFARecoveryRegenerationConfiguration(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (HTTPMFARecoveryRegenerationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export.
func (HTTPMFARecoveryRegenerationConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue returns only a fixed marker.
func (HTTPMFARecoveryRegenerationConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFARecoveryRegenerationConfiguration(redacted)")
}

type mfaRecoveryRegenerationHTTPState struct {
	config              HTTPMFARecoveryRegenerationConfiguration
	proofs              auth.ReauthenticationSource
	rate                *identityhttp.KeyedSecretRateLimiter
	now                 func() time.Time
	revision            authorization.Revision
	timeout, maximumAge time.Duration
	count               uint32
}

func composeMFARecoveryRegenerationHTTP(c StoreConfiguration, d ReferenceDependencies, owner *mfaEnrollmentState, rate *httpRateState) (*mfaRecoveryRegenerationHTTPState, error) {
	if c.HTTPMFARecoveryRegeneration == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa_regeneration"}
	if owner == nil || owner.regenerate == nil || owner.stepup == nil || c.MFAEnrollment == nil || c.MFAEnrollment.Regeneration == nil || c.MFAEnrollment.ActiveStepUp == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.HTTPRate == nil || rate == nil || c.OTP == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	h := *c.HTTPMFARecoveryRegeneration
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
	policy := c.MFAEnrollment.Regeneration
	return &mfaRecoveryRegenerationHTTPState{config: h, proofs: source, rate: limiter, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion), timeout: c.MFAEnrollment.Native.MaximumDuration, maximumAge: policy.MaximumAge, count: policy.CodeCount}, nil
}

func (s *Server) mfaRecoveryRegenerationHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*mfahttp.RecoveryRegenerateConfig, error) {
	h := s.state.features.httpMFARecoveryRegeneration
	if h == nil {
		return nil, nil
	}
	owner, err := f.MFARecoveryRegeneration()
	if err != nil {
		return nil, err
	}
	if s.state.features.session == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_regeneration"}
	}
	sessions := s.state.features.session
	return &mfahttp.RecoveryRegenerateConfig{Network: network, Sessions: sessions.reader, Proofs: h.proofs, Service: owner, Rate: h.rate, Cookie: sessions.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, PolicyRevision: h.revision, Now: h.now, MaximumDuration: h.timeout, MaximumAge: h.maximumAge, CodeCount: h.count}, nil
}
