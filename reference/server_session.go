package reference

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

// HTTPSessionConfiguration explicitly selects session read and self-signout.
// Transport never falls back to another credential channel. Cookie mode
// requires exact HTTPS TrustedOrigins and the native CSRF owner; bearer mode
// rejects origins. Degraded must record each emergency rate decision within
// its context. One graph-owned bounded rate.safe budget serves both routes.
// Dependencies are borrowed and callbacks must be bounded/concurrency-safe.
type HTTPSessionConfiguration struct {
	Transport            session.CredentialKind
	TrustedOrigins       []identityhttp.Origin
	RateNamespace        string
	EmergencyMaximumKeys int
	Degraded             func(context.Context, identityhttp.SafeRateEvent) error
}

type sessionHTTPState struct {
	config HTTPSessionConfiguration
	rate   *identityhttp.SafeRateLimiter
}

func composeSessionHTTP(c StoreConfiguration, owner *sessionState, rate *httpRateState) (*sessionHTTPState, error) {
	if c.HTTPSession == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_session"}
	if c.Session == nil || owner == nil || rate == nil || c.HTTPRate == nil {
		return nil, invalid
	}
	h := *c.HTTPSession
	switch h.Transport {
	case session.CredentialCookie:
		if owner.cookie == nil || len(h.TrustedOrigins) == 0 || len(h.TrustedOrigins) > 128 {
			return nil, invalid
		}
	case session.CredentialBearer:
		if owner.bearer == nil || len(h.TrustedOrigins) != 0 {
			return nil, invalid
		}
	default:
		return nil, invalid
	}
	h.TrustedOrigins = slices.Clone(h.TrustedOrigins)
	limiter, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: rate.backend, Namespace: h.RateNamespace, Now: time.Now, Degraded: h.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: h.EmergencyMaximumKeys})
	if err != nil {
		return nil, invalid
	}
	return &sessionHTTPState{config: h, rate: limiter}, nil
}

// sessionFeature combines independent native contributions under the one
// canonical owner, retaining all original browser-device and named-flow wiring.
func (s *Server) sessionFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	preauth, err := s.preAuthFeature(network, f)
	if err != nil {
		return nil, err
	}
	h := s.state.features.httpSession
	if h == nil {
		return preauth, nil
	}
	owner := s.state.features.session
	if owner == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_session"}
	}
	c := sessionhttp.SignOutConfig{GetConfig: sessionhttp.GetConfig{Network: network, Sessions: owner.reader, Rate: h.rate, Transport: h.config.Transport, Cookie: owner.config.Cookie, Now: time.Now, MaximumDuration: owner.config.MaximumDuration}, TrustedOrigins: h.config.TrustedOrigins}
	if h.config.Transport == session.CredentialCookie {
		c.CookieSignOut = owner.cookie
	} else {
		c.BearerSignOut = owner.bearer
	}
	native, err := sessionhttp.NewFeature(c)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_http_session_native_feature"}
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{native}})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_http_session_descriptors"}
	}
	for i := range ops {
		ops[i].Handler = s.guardSessionLifetime(ops[i].Handler)
	}
	if preauth != nil {
		flow, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{*preauth}})
		if err != nil {
			return nil, err
		}
		ops = append(ops, flow...)
	}
	feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: ops})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_http_session_combined_feature"}
	}
	return &feature, err
}

// Concrete HTTP owner handles cannot use the guarded public port. Join their
// complete request to graph custody so shutdown cancels and drains owner IO.
func (s *Server) guardSessionLifetime(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, done, err := s.state.enterFeature(r.Context(), true)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "{\"error\":\"unavailable\"}\n")
			return
		}
		defer done()
		next.ServeHTTP(w, r.Clone(ctx))
	})
}

// Format redacts deployment callbacks and policy.
func (HTTPSessionConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPSessionConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (HTTPSessionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit configuration export.
func (HTTPSessionConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
