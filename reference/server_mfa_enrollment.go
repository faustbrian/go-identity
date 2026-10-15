package reference

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// HTTPMFAEnrollmentConfiguration independently selects cookie-only pending
// TOTP enrollment. Native enrollment, session, verification and strict shared
// HTTP rate owners are required. Origins must be exact members of native
// management policy. RecoveryCodes is 1..20; zero selects the reference default
// of ten. Namespace/key are stable rate identity, not signing/encryption keys.
// This selection does not enable login completion or imply an active factor.
type HTTPMFAEnrollmentConfiguration struct {
	// ProvisioningURI explicitly adds the separate one-time disclosure route.
	ProvisioningURI bool
	// Confirmation explicitly adds authenticated code activation on the shared
	// verify route, without enabling login or session issuance.
	Confirmation          bool
	VerificationNamespace string
	VerificationKey       [32]byte
	TrustedOrigins        []identityhttp.Origin
	RateNamespace         string
	RateKey               [32]byte
	RecoveryCodes         uint32
}

func (s *Server) mfaProvisioningHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet, enable *mfahttp.EnableConfig) (*mfahttp.URIConfig, error) {
	h := s.state.features.httpMFAEnrollment
	if h == nil || !h.config.ProvisioningURI {
		return nil, nil
	}
	if enable == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_uri"}
	}
	owner, err := f.MFAProvisioningURI()
	if err != nil {
		return nil, err
	}
	native, ok := owner.(mfahttp.URIService)
	if !ok {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_uri"}
	}
	return &mfahttp.URIConfig{Network: network, Sessions: enable.Sessions, Service: native, Rate: enable.Rate, Cookie: enable.Cookie, TrustedOrigins: enable.TrustedOrigins, PolicyRevision: enable.PolicyRevision, Now: enable.Now, MaximumDuration: enable.MaximumDuration}, nil
}

// Format redacts deployment policy and keys.
func (HTTPMFAEnrollmentConfiguration) Format(s fmt.State, _ rune) {
	s.Write([]byte("reference.HTTPMFAEnrollmentConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (HTTPMFAEnrollmentConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit text export.
func (HTTPMFAEnrollmentConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue returns only a fixed marker.
func (HTTPMFAEnrollmentConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.HTTPMFAEnrollmentConfiguration(redacted)")
}

type mfaEnrollmentHTTPState struct {
	config     HTTPMFAEnrollmentConfiguration
	rate       *identityhttp.KeyedSecretRateLimiter
	verifyRate *identityhttp.ChallengeVerificationRateLimiter
	now        func() time.Time
	revision   authorization.Revision
	timeout    time.Duration
}

func composeMFAEnrollmentHTTP(c StoreConfiguration, owner *mfaEnrollmentState, verification *passwordVerificationState, rate *httpRateState) (*mfaEnrollmentHTTPState, error) {
	if c.HTTPMFAEnrollment == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_mfa_enrollment"}
	if owner == nil || owner.enable == nil || verification == nil || verification.proofs == nil || c.MFAEnrollment == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.HTTPRate == nil || rate == nil || c.OTP == nil {
		return nil, invalid
	}
	h := *c.HTTPMFAEnrollment
	if len(h.TrustedOrigins) == 0 || len(h.TrustedOrigins) > 128 || h.RecoveryCodes > 20 {
		return nil, invalid
	}
	h.TrustedOrigins = slices.Clone(h.TrustedOrigins)
	for i, origin := range h.TrustedOrigins {
		if !slices.Contains(c.MFAEnrollment.AllowedOrigins, string(origin)) || slices.Contains(h.TrustedOrigins[:i], origin) {
			return nil, invalid
		}
	}
	if h.RecoveryCodes == 0 {
		h.RecoveryCodes = 10
	}
	now := c.Session.Native.Execution.Clock.Now
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: h.RateNamespace, Key: h.RateKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	var verify *identityhttp.ChallengeVerificationRateLimiter
	if h.Confirmation {
		if owner.confirm == nil {
			limiter.Close()
			return nil, invalid
		}
		verify, err = identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: h.VerificationNamespace, Key: h.VerificationKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			limiter.Close()
			return nil, invalid
		}
	} else if h.VerificationNamespace != "" || h.VerificationKey != ([32]byte{}) {
		limiter.Close()
		return nil, invalid
	}
	return &mfaEnrollmentHTTPState{config: h, rate: limiter, verifyRate: verify, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion), timeout: c.MFAEnrollment.Native.MaximumDuration}, nil
}

func (s *Server) mfaConfirmationHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet, enable *mfahttp.EnableConfig) (*mfahttp.EnrollmentConfirmationConfig, error) {
	h := s.state.features.httpMFAEnrollment
	if h == nil || !h.config.Confirmation {
		return nil, nil
	}
	if enable == nil || !h.verifyRate.Configured() {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_confirmation"}
	}
	owner, err := f.MFAEnrollmentConfirmation()
	if err != nil {
		return nil, err
	}
	native, ok := owner.(mfahttp.EnrollmentConfirmationService)
	if !ok {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_confirmation"}
	}
	return &mfahttp.EnrollmentConfirmationConfig{Network: network, Sessions: enable.Sessions, Service: native, Rate: h.verifyRate, Cookie: enable.Cookie, TrustedOrigins: enable.TrustedOrigins, PolicyRevision: enable.PolicyRevision, Now: enable.Now, MaximumDuration: enable.MaximumDuration}, nil
}

func (s *Server) mfaEnrollmentHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet) (*mfahttp.EnableConfig, error) {
	state := s.state.features
	h := state.httpMFAEnrollment
	if h == nil {
		return nil, nil
	}
	if state.session == nil || state.passwordVerification == nil || state.passwordVerification.proofs == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_mfa_enrollment"}
	}
	owner, err := f.MFAEnrollment()
	if err != nil {
		return nil, err
	}
	return &mfahttp.EnableConfig{Network: network, Sessions: state.session.reader, Proofs: state.passwordVerification.proofs, Enrollment: owner, Rate: h.rate, Cookie: state.session.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: h.config.RecoveryCodes}, PolicyRevision: h.revision, Now: h.now, MaximumDuration: h.timeout}, nil
}

// Preserve actual pipeline hook binding while joining preliminary session and
// proof reads, admission and mutation to the graph's cancellation/drain owner.
type mfaEnrollmentLifetimeHandler struct {
	state      *storeState
	next       http.Handler
	operation  string
	stepup     bool
	stepupOnly bool
}

func (h *mfaEnrollmentLifetimeHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.state == nil || h.next == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	next, err := identityhttp.WithOperationMiddleware(h.next, m)
	if err != nil {
		return nil, err
	}
	return &mfaEnrollmentLifetimeHandler{state: h.state, next: next, operation: h.operation, stepup: h.stepup, stepupOnly: h.stepupOnly}, nil
}
func (h *mfaEnrollmentLifetimeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, done, err := h.state.enterFeature(r.Context(), true)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusServiceUnavailable)
		body := "{\"enabled\":false,\"active\":false,\"commitOutcome\":\"none\",\"error\":\"unavailable\"}\n"
		if h.operation == "identity.mfa.totp-uri" {
			body = "{\"disclosed\":false,\"commitOutcome\":\"none\",\"error\":\"unavailable\"}\n"
		}
		if h.operation == "identity.mfa.recovery-regenerate" {
			body = "{\"regenerated\":false,\"commitOutcome\":\"none\",\"error\":\"unavailable\"}\n"
		}
		if h.operation == "identity.mfa.totp-verify" {
			body = "{\"activated\":false,\"commitOutcome\":\"none\",\"error\":\"unavailable\"}\n"
			selected := h.stepupOnly
			if h.stepup && !selected {
				count := 0
				for name, values := range r.Header {
					if strings.EqualFold(name, "X-MFA-Variant") {
						count++
						selected = len(values) == 1 && values[0] == "step-up"
					}
				}
				selected = selected && count == 1
			}
			if selected {
				body = "{\"verified\":false,\"commitOutcome\":\"none\",\"error\":\"unavailable\"}\n"
			}
		}
		w.Write([]byte(body))
		return
	}
	defer done()
	h.next.ServeHTTP(w, r.Clone(ctx))
}
