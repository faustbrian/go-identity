package reference

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/session"
)

// HTTPMFAActiveStepUpConfiguration independently selects the authenticated
// TOTP step-up verify arm, not enrollment or login. Native active step-up,
// session and shared strict rate owners are required. Origins must be exact
// native allowed origins; namespace/key retain stable shared quota identity.
type HTTPMFAActiveStepUpConfiguration struct {
	// Purposes explicitly selects the finite native management targets. Empty
	// retains regeneration; non-default targets must be named in the request.
	Purposes              []auth.Purpose
	TrustedOrigins        []identityhttp.Origin
	VerificationNamespace string
	VerificationKey       [32]byte
}

// Format redacts rate keys and deployment policy.
func (HTTPMFAActiveStepUpConfiguration) Format(s fmt.State, _ rune) {
	s.Write([]byte("reference.HTTPMFAActiveStepUpConfiguration(redacted)"))
}

// MarshalJSON rejects implicit key/configuration export.
func (HTTPMFAActiveStepUpConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export.
func (HTTPMFAActiveStepUpConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue returns only a fixed marker.
func (HTTPMFAActiveStepUpConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFAActiveStepUpConfiguration(redacted)")
}

type mfaActiveStepUpHTTPState struct {
	config   HTTPMFAActiveStepUpConfiguration
	rate     *identityhttp.ChallengeVerificationRateLimiter
	now      func() time.Time
	revision authorization.Revision
	timeout  time.Duration
}

func composeMFAActiveStepUpHTTP(c StoreConfiguration, owner *mfaEnrollmentState, rate *httpRateState) (*mfaActiveStepUpHTTPState, error) {
	if c.HTTPMFAActiveStepUp == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa_step_up"}
	if owner == nil || owner.stepup == nil || c.MFAEnrollment == nil || c.MFAEnrollment.ActiveStepUp == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.HTTPRate == nil || rate == nil || c.OTP == nil {
		return nil, invalid
	}
	h := *c.HTTPMFAActiveStepUp
	if len(h.Purposes) > 3 {
		return nil, invalid
	}
	h.Purposes = slices.Clone(h.Purposes)
	for i, purpose := range h.Purposes {
		if purpose != "identity.mfa.recovery-regenerate" && purpose != "identity.mfa.factor-update" && purpose != "identity.mfa.disable" || slices.Contains(h.Purposes[:i], purpose) {
			return nil, invalid
		}
	}
	if len(h.TrustedOrigins) == 0 || len(h.TrustedOrigins) > 16 {
		return nil, invalid
	}
	h.TrustedOrigins = slices.Clone(h.TrustedOrigins)
	for i, origin := range h.TrustedOrigins {
		if !slices.Contains(c.MFAEnrollment.ActiveStepUp.AllowedOrigins, string(origin)) || slices.Contains(h.TrustedOrigins[:i], origin) {
			return nil, invalid
		}
	}
	now := c.Session.Native.Execution.Clock.Now
	limiter, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: h.VerificationNamespace, Key: h.VerificationKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &mfaActiveStepUpHTTPState{config: h, rate: limiter, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion), timeout: c.MFAEnrollment.Native.MaximumDuration}, nil
}

func (s *Server) mfaActiveStepUpHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*mfahttp.ActiveStepUpConfig, error) {
	h := s.state.features.httpMFAActiveStepUp
	if h == nil {
		return nil, nil
	}
	owner, err := f.MFAActiveStepUp()
	if err != nil {
		return nil, err
	}
	native, ok := owner.(mfahttp.ActiveStepUpService)
	if !ok || s.state.features.session == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_step_up"}
	}
	sessions := s.state.features.session
	return &mfahttp.ActiveStepUpConfig{Network: network, Sessions: sessions.reader, Service: native, Rate: h.rate, Cookie: sessions.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, PolicyRevision: h.revision, Now: h.now, MaximumDuration: h.timeout, Purposes: h.config.Purposes}, nil
}
