package reference

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// HTTPPasswordProtectionConfiguration selects the credential channel and
// deployment rate identity for one protected password operation. Use separate
// HTTPPasswordVerification and HTTPPasswordChange selections; neither enables
// the other. Cookie mode requires exact HTTPS origins and native CSRF custody;
// bearer mode rejects origins and never falls back to cookies. Namespace and
// RateKey are stable independent rate identity, not credential/signing keys.
// Verification also requires the existing signed browser-device issuer. Native
// owners supply cookie, policy revision, clock and transaction bounds.
type HTTPPasswordProtectionConfiguration struct {
	Transport      session.CredentialKind
	TrustedOrigins []identityhttp.Origin
	RateNamespace  string
	RateKey        [32]byte
}

type passwordVerificationHTTPState struct {
	config   HTTPPasswordProtectionConfiguration
	rate     *identityhttp.PasswordVerificationRateLimiter
	now      func() time.Time
	revision authorization.Revision
}

type passwordChangeHTTPState struct {
	config   HTTPPasswordProtectionConfiguration
	rate     *identityhttp.KeyedSecretRateLimiter
	now      func() time.Time
	revision authorization.Revision
}

func copyPasswordProtectionHTTP(c *HTTPPasswordProtectionConfiguration, cookieEnabled bool) (HTTPPasswordProtectionConfiguration, error) {
	if c == nil {
		return HTTPPasswordProtectionConfiguration{}, identity.InvalidInputError{Field: "reference_http_password_protection"}
	}
	h := *c
	switch h.Transport {
	case session.CredentialCookie:
		if !cookieEnabled || len(h.TrustedOrigins) == 0 || len(h.TrustedOrigins) > 128 {
			return HTTPPasswordProtectionConfiguration{}, identity.InvalidInputError{Field: "reference_http_password_protection"}
		}
	case session.CredentialBearer:
		if len(h.TrustedOrigins) != 0 {
			return HTTPPasswordProtectionConfiguration{}, identity.InvalidInputError{Field: "reference_http_password_protection"}
		}
	default:
		return HTTPPasswordProtectionConfiguration{}, identity.InvalidInputError{Field: "reference_http_password_protection"}
	}
	h.TrustedOrigins = slices.Clone(h.TrustedOrigins)
	return h, nil
}

func composePasswordVerificationHTTP(c StoreConfiguration, owner *passwordVerificationState, device *preAuthHTTPState, rate *httpRateState) (*passwordVerificationHTTPState, error) {
	if c.HTTPPasswordVerification == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_password_verification"}
	if owner == nil || owner.bearer == nil || c.PasswordVerification == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.OTP == nil || device == nil || device.device == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	h, err := copyPasswordProtectionHTTP(c.HTTPPasswordVerification, owner.cookie != nil)
	if err != nil {
		return nil, invalid
	}
	now := c.Session.Native.Execution.Clock.Now
	limiter, err := identityhttp.NewPasswordVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: rate.backend, Namespace: h.RateNamespace, Key: h.RateKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &passwordVerificationHTTPState{config: h, rate: limiter, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion)}, nil
}

func composePasswordChangeHTTP(c StoreConfiguration, owner *passwordChangeState, verification *passwordVerificationState, rate *httpRateState) (*passwordChangeHTTPState, error) {
	if c.HTTPPasswordChange == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_password_change"}
	if owner == nil || owner.bearer == nil || verification == nil || verification.proofs == nil || c.PasswordChange == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.OTP == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	h, err := copyPasswordProtectionHTTP(c.HTTPPasswordChange, owner.cookie != nil)
	if err != nil {
		return nil, invalid
	}
	now := c.Session.Native.Execution.Clock.Now
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: h.RateNamespace, Key: h.RateKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	return &passwordChangeHTTPState{config: h, rate: limiter, now: now, revision: authorization.Revision(c.OTP.RequestKeys.Policy.PolicyVersion)}, nil
}

func (s *Server) passwordProtectionHTTPConfig(network identityhttp.NetworkConfig, f FeatureSet, config *passwordhttp.FeatureConfig) error {
	state := s.state.features
	if h := state.httpPasswordVerification; h != nil {
		if state.session == nil || state.httpPreAuth == nil || state.httpPreAuth.device == nil {
			return identity.InvalidInputError{Field: "reference_http_password_verification"}
		}
		if h.config.Transport == session.CredentialCookie {
			owner, err := f.CookiePasswordVerification()
			if err != nil {
				return err
			}
			config.CookieVerification = &passwordhttp.CookieVerificationConfig{Network: network, Sessions: state.session.reader, Verification: owner, Rate: h.rate, Cookie: state.session.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, Device: *state.httpPreAuth.device, PolicyRevision: h.revision, Now: h.now, MaximumDuration: state.timeout}
		} else {
			owner, err := f.PasswordVerification()
			if err != nil {
				return err
			}
			config.BrowserDeviceBearerVerification = &passwordhttp.BrowserDeviceBearerVerificationConfig{Verification: passwordhttp.BearerVerificationConfig{Network: network, Sessions: state.session.reader, Verification: owner, Rate: h.rate, PolicyRevision: h.revision, Now: h.now, MaximumDuration: state.timeout}, Device: *state.httpPreAuth.device}
		}
	}
	if h := state.httpPasswordChange; h != nil {
		if state.session == nil || state.passwordVerification == nil || state.passwordVerification.proofs == nil {
			return identity.InvalidInputError{Field: "reference_http_password_change"}
		}
		change := passwordhttp.ChangeConfig{Network: network, Sessions: state.session.reader, Proofs: state.passwordVerification.proofs, Rate: h.rate, Transport: h.config.Transport, Cookie: state.session.config.Cookie, TrustedOrigins: h.config.TrustedOrigins, PolicyRevision: h.revision, Now: h.now, MaximumDuration: state.timeout}
		var err error
		if h.config.Transport == session.CredentialCookie {
			change.CookieChange, err = f.CookiePasswordChange()
		} else {
			change.BearerChange, err = f.PasswordChange()
		}
		if err != nil {
			return err
		}
		config.Change = &change
	}
	return nil
}

// Concrete primary readers/proof sources run before the guarded domain port.
// Join the whole request to graph cancellation/drain, not just the final mutation.
func (s *Server) guardPasswordProtectionLifetime(next http.Handler, operation string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, done, err := s.state.enterFeature(r.Context(), true)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusServiceUnavailable)
			if operation == "identity.password.verify" {
				_ = json.NewEncoder(w).Encode(passwordhttp.VerificationResponse{CommitOutcome: "none", Error: "unavailable"})
			} else if operation == "identity.username.update" {
				_ = json.NewEncoder(w).Encode(passwordhttp.UsernameRenameResponse{CommitOutcome: "none", Error: "unavailable"})
			} else {
				_ = json.NewEncoder(w).Encode(passwordhttp.ChangeResponse{CommitOutcome: "none", Error: "unavailable"})
			}
			return
		}
		defer done()
		next.ServeHTTP(w, r.Clone(ctx))
	})
}

// Format redacts deployment rate custody.
func (HTTPPasswordProtectionConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPPasswordProtectionConfiguration(redacted)")
}

// MarshalJSON denies implicit deployment export.
func (HTTPPasswordProtectionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key export.
func (HTTPPasswordProtectionConfiguration) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
