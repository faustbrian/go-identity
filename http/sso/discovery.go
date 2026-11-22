// Package ssohttp exposes opt-in, tenant-bound enterprise SSO transport.
package ssohttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

const (
	discoveryOperation = "identity.sso.discover"
	discoveryPath      = "/v1/sso/discover"
	discoveryQuery     = "emailOrDomain"
	maxDiscoveryBytes  = 320 // identity.sso.discover.request.v1
)

// BrowserDiscovery is implemented by the configured native discovery owner.
// It checks the transport-resolved tenant against its own configuration and
// binds only verified peer and device facts. Construction performs no lookup;
// the returned service performs the actual audited and counted discovery.
// Implementations must be immutable/concurrency-safe and may not fall back to
// a different tenant or bypass the native risk and provider authorities.
type BrowserDiscovery interface {
	ForTenantBrowser(identity.TenantID, netip.Addr, string) (*sso.Service, error)
}

// Config selects anonymous discovery for mapped HTTPS tenant hosts. Use the
// same browser-device policy as the existing pre-auth cookie issuer and the
// same shared Rate owner as other auth routes. Now is a trusted bounded clock.
// All borrowed dependencies must be safe for concurrent requests.
type Config struct {
	Network         identityhttp.NetworkConfig
	BrowserDevice   session.BrowserDeviceConfig
	Discovery       BrowserDiscovery
	Rate            *identityhttp.AuthRateLimiter
	Now             func() time.Time
	MaximumDuration time.Duration
	// SigninStart optionally adds the independently configured static OIDC
	// sign-in start to this tenant SSO contribution. Nil preserves discovery.
	SigninStart *SigninStartConfig
}

// NewFeature contributes the selected tenant SSO operations. When SigninStart
// is nil, only configured discovery is selected. Discovery can be omitted when
// selecting start, and the protocol callback remains a separate contribution.
func NewFeature(c Config) (identityhttp.Feature, error) {
	if c.Discovery == nil && c.SigninStart != nil {
		return NewSigninStartFeature(*c.SigninStart)
	}
	h, err := newDiscoveryHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "sso", OperationID: discoveryOperation, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 4096})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = discoveryWire()
	operations := []identityhttp.OperationDescriptor{op}
	if c.SigninStart != nil {
		start, err := NewSigninStartFeature(*c.SigninStart)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, start.Operations()...)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso", Operations: operations})
}

type discoveryRequestState struct {
	request sso.DiscoverRequest
	facts   identityhttp.NetworkFacts
	device  session.BrowserDevice
}

func newDiscoveryHandler(c Config) (http.Handler, error) {
	if !configuredOwner(c.Discovery) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || len(c.Network.TenantHosts) == 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	devices, err := session.NewBrowserDeviceCodec(c.BrowserDevice)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.BrowserDevice.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[discoveryRequestState]{
		MaximumDuration: c.MaximumDuration,
		Decode: func(r *http.Request) (discoveryRequestState, error) {
			input, err := decodeDiscoveryQuery(decoder, r)
			if err != nil {
				return discoveryRequestState{}, err
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.Scheme() != "https" || !discoveryHeadersAllowed(r, facts) {
				return discoveryRequestState{}, sso.ErrForbidden
			}
			return discoveryRequestState{request: input, facts: facts}, nil
		},
		Authenticate: func(r *http.Request, state discoveryRequestState) (discoveryRequestState, error) {
			// This cookie is same-origin browser correlation, not identity or
			// a session credential. The codec verifies exact tenant and origin.
			credential, _, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return discoveryRequestState{}, sso.ErrForbidden
			}
			verified, err := devices.Resolve(r.Context(), c.Now(), state.facts.TenantID(), state.facts.Origin(), credential.Token())
			if err != nil {
				return discoveryRequestState{}, sso.ErrForbidden
			}
			state.device = verified
			return state, nil
		},
		Admit: func(r *http.Request, state discoveryRequestState) error {
			result, err := c.Rate.AdmitSSODiscoveryIP(r.Context(), state.facts)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{result.RetryAfter}
			}
			if err != nil || !result.Allowed {
				return sso.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state discoveryRequestState) {
			if !state.device.ExpiresAt().After(c.Now()) {
				writeDiscoveryError(w, r, sso.ErrForbidden)
				return
			}
			service, err := c.Discovery.ForTenantBrowser(state.facts.TenantID(), state.facts.ClientIP(), state.device.DeviceID())
			if err != nil || service == nil {
				writeDiscoveryError(w, r, err)
				return
			}
			result, err := service.Discover(r.Context(), state.request)
			if err != nil || r.Context().Err() != nil {
				writeDiscoveryError(w, r, err)
				return
			}
			if !state.device.ExpiresAt().After(c.Now()) {
				writeDiscoveryError(w, r, sso.ErrForbidden)
				return
			}
			writeDiscoveryJSON(w, http.StatusOK, discoveryResponse{result.Matched, result.ProviderID, result.Protocol, result.RequiresConfirmation})
		},
		Reject: writeDiscoveryError,
	})
}

func decodeDiscoveryQuery(decoder *identityhttp.RequestDecoder, r *http.Request) (sso.DiscoverRequest, error) {
	if r == nil || r.URL == nil || r.Method != http.MethodGet || r.URL.EscapedPath() != discoveryPath || r.URL.Path != discoveryPath || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody {
		return sso.DiscoverRequest{}, identityhttp.ErrInvalidInput
	}
	if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return sso.DiscoverRequest{}, identityhttp.ErrInvalidInput
	}
	query, err := decoder.Query(r)
	if err != nil || len(query) != 1 {
		return sso.DiscoverRequest{}, identityhttp.ErrInvalidInput
	}
	value := query.Get(discoveryQuery)
	if len(value) == 0 || len(value) > maxDiscoveryBytes {
		return sso.DiscoverRequest{}, identityhttp.ErrInvalidInput
	}
	return sso.DiscoverRequest{EmailOrDomain: value}, nil
}

func discoveryHeadersAllowed(r *http.Request, facts identityhttp.NetworkFacts) bool {
	for name, values := range r.Header {
		if strings.EqualFold(name, "Origin") && (len(values) != 1 || values[0] != facts.Origin()) {
			return false
		}
		if strings.EqualFold(name, "Forwarded") && !facts.Forwarded() {
			return false
		}
	}
	return true
}

func configuredOwner(owner any) bool {
	if owner == nil {
		return false
	}
	v := reflect.ValueOf(owner)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.Interface:
		return !v.IsNil()
	}
	return true
}

type discoveryResponse struct {
	Matched              bool   `json:"matched"`
	ProviderID           string `json:"providerID,omitempty"`
	Protocol             string `json:"protocol,omitempty"`
	RequiresConfirmation bool   `json:"requiresConfirmation"`
}

type discoveryRateDenial struct{ retry time.Duration }

func (discoveryRateDenial) Error() string { return "identity.http.rate_limited" }

func writeDiscoveryError(w http.ResponseWriter, _ *http.Request, err error) {
	status, code := http.StatusServiceUnavailable, "unavailable"
	var limited discoveryRateDenial
	switch {
	case errors.As(err, &limited):
		status, code = http.StatusTooManyRequests, "rate_limited"
		retry := min(max(limited.retry, time.Second), time.Hour)
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
	case errors.Is(err, identityhttp.ErrInvalidInput), errors.Is(err, sso.ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, sso.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	}
	writeDiscoveryJSON(w, status, struct {
		Error string `json:"error"`
	}{code})
}

func writeDiscoveryJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
