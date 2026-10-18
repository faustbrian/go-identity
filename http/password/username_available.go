package passwordhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/username"
)

// UsernameAvailabilityConfig selects advisory discovery, not a reservation.
// Service must own canonical normalization, durable per-attempt risk/rate and
// fail-closed audit. It is borrowed, concurrent-safe and must outlive handlers.
// MaximumDuration is 1ms..30s; earlier deadlines win. Construction performs no IO.
type UsernameAvailabilityConfig struct {
	Network         identityhttp.NetworkConfig
	Service         username.AvailabilityService
	MaximumDuration time.Duration
}

// UsernameAvailabilityResponse discloses only advisory availability. A false
// response never distinguishes live ownership from retirement history.
type UsernameAvailabilityResponse struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// NewUsernameAvailabilityHandler selects only GET /v1/username/available with
// one bounded username query. It derives tenant/network from trusted transport,
// rejects alternate authority and invokes the native owner on every attempt.
func NewUsernameAvailabilityHandler(c UsernameAvailabilityConfig) (http.Handler, error) {
	return NewUsernameAvailabilityHandlerWithMiddleware(c, nil)
}

// NewUsernameAvailabilityHandlerWithMiddleware uses the existing typed public
// pipeline. Its state is redacted AvailabilityRequest; middleware is borrowed.
func NewUsernameAvailabilityHandlerWithMiddleware(c UsernameAvailabilityConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
		f := failure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		var specific failure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodGet)
		}
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(UsernameAvailabilityResponse{Error: f.code})
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[username.AvailabilityRequest]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (username.AvailabilityRequest, error) {
			var out username.AvailabilityRequest
			if r.URL.Path != "/v1/username/available" || r.URL.EscapedPath() != r.URL.Path {
				return out, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return out, failure{status: 405, code: "method_not_allowed"}
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
				return out, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return out, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return out, identityhttp.ErrInvalidInput
			}
			values, err := decoder.Query(r)
			if err != nil || len(values) != 1 || len(values["username"]) != 1 || len(values.Get("username")) == 0 || len(values.Get("username")) > username.MaximumBytes {
				return out, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return out, identityhttp.ErrInvalidInput
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return out, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return out, failure{status: 403, code: "https_required"}
			}
			return username.AvailabilityRequest{TenantID: string(facts.TenantID()), Network: facts.ClientIP().String(), Username: values.Get("username")}, nil
		},
		Authenticate: func(_ *http.Request, s username.AvailabilityRequest) (username.AvailabilityRequest, error) {
			return s, nil
		},
		Admit: func(_ *http.Request, _ username.AvailabilityRequest) error { return nil },
		Handle: func(w http.ResponseWriter, r *http.Request, s username.AvailabilityRequest) {
			result, err := c.Service.Available(r.Context(), s)
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil {
				switch {
				case errors.Is(err, username.ErrThrottled):
					err = failure{status: 429, code: "rate_limited"}
				case errors.Is(err, username.ErrDenied):
					err = failure{status: 403, code: "denied"}
				case errors.Is(err, username.ErrInvalid):
					err = identityhttp.ErrInvalidInput
				}
				reject(w, r, err)
				return
			}
			_ = json.NewEncoder(w).Encode(UsernameAvailabilityResponse{Available: result.Available})
		},
	})
	if err != nil {
		return nil, err
	}
	return &usernameAvailabilityPipeline{pipeline: pipeline}, nil
}

type usernameAvailabilityPipeline struct{ pipeline http.Handler }

func (p *usernameAvailabilityPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &usernameAvailabilityPipeline{pipeline: h}, nil
}
func (p *usernameAvailabilityPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	servePasswordPipeline(w, r, p.pipeline)
}

// Format redacts borrowed dependencies and network configuration.
func (UsernameAvailabilityConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordhttp.UsernameAvailabilityConfig(redacted)")
}

// LogValue redacts borrowed dependencies and network configuration.
func (UsernameAvailabilityConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.UsernameAvailabilityConfig(redacted)")
}

// MarshalJSON refuses implicit runtime configuration export.
func (UsernameAvailabilityConfig) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// MarshalText refuses implicit runtime configuration export.
func (UsernameAvailabilityConfig) MarshalText() ([]byte, error) { return nil, username.ErrDisclosure }
