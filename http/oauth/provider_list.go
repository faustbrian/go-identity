package oauthhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth/providers"
)

// ProviderListConfig selects public configured-provider discovery independently
// of linking, signin and callbacks. Catalog and Rate are borrowed, concurrency-
// safe owners that must outlive requests. Catalog must honor cancellation; Rate
// is the same shared rate.safe limiter used by other safe routes. Network policy
// is copied. MaximumDuration is 1ms..30s; an earlier request deadline wins.
// Construction performs no IO and creates no protocol, session or rate engine.
type ProviderListConfig struct {
	Network         identityhttp.NetworkConfig
	Catalog         providers.Catalog
	Rate            *identityhttp.SafeRateLimiter
	MaximumDuration time.Duration
	// Localization optionally selects safe public denial messages. Nil preserves
	// the original machine-only JSON contract; it never affects successful pages.
	Localization *ProviderListLocalizationConfig
}

// Format prevents borrowed catalog/configuration details from being disclosed.
func (ProviderListConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.ProviderListConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ProviderListConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText refuses implicit runtime configuration export.
func (ProviderListConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// ProviderListItem contains only the native catalog's safe public facts. Modes
// describe configured authentication input, not signup, token or logout support.
type ProviderListItem struct {
	ID             string                   `json:"id"`
	DisplayName    string                   `json:"displayName"`
	SupportedModes []providers.ProviderMode `json:"supportedModes"`
}

// ProviderListResponse is one stable bounded page. Page is always an array;
// NextCursor is absent at exhaustion and otherwise remains opaque. Reuse a
// continuation with the same limit and configured native catalog snapshot.
type ProviderListResponse struct {
	Page       []ProviderListItem `json:"page"`
	NextCursor string             `json:"nextCursor,omitempty"`
}

// NewProviderListFeature opts into only GET /v1/oauth/provider-list and its
// matching public wire contract. No OAuth signin/link/callback or metadata
// endpoint is enabled; omitting this feature exposes no catalog capability.
func NewProviderListFeature(c ProviderListConfig) (identityhttp.Feature, error) {
	h, err := NewProviderListHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/oauth/providers", OperationID: "identity.oauth.provider-list", Handler: h,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: maximumProviderListResponse,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = wireProviderList(c.Localization != nil)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth/providers", Operations: []identityhttp.OperationDescriptor{op}})
}

type providerListInput struct {
	facts   identityhttp.NetworkFacts
	request providers.ProviderListRequest
	limit   int
}

type providerListRejection struct {
	status int
	code   string
	retry  time.Duration
}

func (e providerListRejection) Error() string { return e.code }

// The transport buffers only the native bounded page (at most 100 safe rows)
// and optional 512-byte cursor before committing output. No raw owner is encoded.
const maximumProviderListResponse = 32768

// NewProviderListHandler accepts exact HTTPS GET on an allowlisted public or
// tenant host, with required canonical limit=1..100 and optional nonempty cursor.
// Bodies, trailers, Authorization and Idempotency-Key are forbidden. Ambient
// cookies confer no authority and are ignored; no Origin or CSRF token is needed.
// Native cursor authentication follows the one canonical anonymous IP rate
// admission, including its existing bounded emergency policy and event owner.
// Errors and successful pages are no-store/nosniff JSON with no credentials.
// The server owns raw IO/write deadlines; no goroutines or retries are started.
func NewProviderListHandler(c ProviderListConfig) (http.Handler, error) {
	if missing(c.Catalog) || !c.Rate.Configured() || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	localization, err := newProviderListLocalization(c.Localization)
	if err != nil {
		return nil, err
	}
	reject := func(w http.ResponseWriter, r *http.Request, cause error) {
		failure := providerListRejection{status: 503, code: "unavailable"}
		var invalid providers.ProviderListInvalidRequestError
		var denied providers.ProviderListAuthorizationDeniedError
		switch {
		case errors.Is(cause, identityhttp.ErrInvalidInput), errors.As(cause, &invalid):
			failure = providerListRejection{status: 400, code: "invalid_request"}
		case errors.As(cause, &denied):
			failure = providerListRejection{status: 403, code: "denied"}
		default:
			var transport providerListRejection
			if errors.As(cause, &transport) {
				failure = transport
			}
		}
		if failure.status == 405 {
			w.Header().Set("Allow", http.MethodGet)
		}
		if failure.status == 429 && failure.retry > 0 {
			seconds := failure.retry / time.Second
			if failure.retry%time.Second != 0 {
				seconds++
			}
			w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
		}
		body, locale := localization.response(r, failure)
		if localization != nil && providerListLocalizedStatus(failure.status) {
			w.Header().Add("Vary", "Accept-Language")
		}
		if locale != "" {
			w.Header().Set("Content-Language", locale)
		}
		w.WriteHeader(failure.status)
		if r == nil || r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[providerListInput]{
		MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(r *http.Request) (in providerListInput, err error) {
			if r.URL.Path != "/v1/oauth/provider-list" || r.URL.EscapedPath() != r.URL.Path {
				return in, providerListRejection{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return in, providerListRejection{status: 405, code: "method_not_allowed"}
			}
			if r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Body != nil && r.Body != http.NoBody || len(r.Trailer) != 0 {
				return in, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return in, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return in, identityhttp.ErrInvalidInput
			}
			query, err := decoder.Query(r)
			if err != nil || len(query["limit"]) != 1 || len(query) > 2 {
				return in, identityhttp.ErrInvalidInput
			}
			for name := range query {
				if name != "limit" && name != "cursor" {
					return in, identityhttp.ErrInvalidInput
				}
			}
			limit, err := strconv.Atoi(query.Get("limit"))
			if err != nil || strconv.Itoa(limit) != query.Get("limit") {
				return in, identityhttp.ErrInvalidInput
			}
			in.request.Limit, err = providers.NewPageLimit(limit)
			if err != nil {
				return in, err
			}
			in.limit = limit
			if values, present := query["cursor"]; present {
				if len(values) != 1 || values[0] == "" {
					return in, identityhttp.ErrInvalidInput
				}
				in.request.Cursor, err = providers.ParseCursor(values[0])
				if err != nil {
					return in, err
				}
			}
			in.facts, err = network.Resolve(r)
			if err != nil {
				return in, providerListRejection{status: 421, code: "misdirected_request"}
			}
			if in.facts.Scheme() != "https" {
				return in, identityhttp.ErrInvalidInput
			}
			return in, nil
		},
		Authenticate: func(_ *http.Request, in providerListInput) (providerListInput, error) { return in, nil },
		Admit: func(r *http.Request, in providerListInput) error {
			result, err := c.Rate.Admit(r.Context(), in.facts, "identity.oauth.provider-list", "")
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return providerListRejection{status: 429, code: "rate_limited", retry: result.RetryAfter}
			}
			if err != nil || !result.Allowed {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, in providerListInput) {
			result, err := c.Catalog.ProviderList(r.Context(), in.request)
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			items := result.Page.Providers()
			if len(items) > in.limit || len(items) == 0 && result.NextCursor.String() != "" {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out := ProviderListResponse{Page: make([]ProviderListItem, 0, len(items)), NextCursor: result.NextCursor.String()}
			for _, item := range items {
				out.Page = append(out.Page, ProviderListItem{ID: item.ID(), DisplayName: item.DisplayName(), SupportedModes: item.SupportedModes()})
			}
			body, err := json.Marshal(out)
			if err != nil || len(body) > maximumProviderListResponse || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			_, _ = w.Write(body)
		},
	})
	if err != nil {
		return nil, err
	}
	return &providerListHandler{pipeline: pipeline}, nil
}

type providerListHandler struct{ pipeline http.Handler }

func (h *providerListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.pipeline.ServeHTTP(w, r)
}

func (h *providerListHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	bound, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &providerListHandler{pipeline: bound}, nil
}

func wireProviderList(localized bool) *identityhttp.WireOperation {
	text := func(minimum, maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
	}
	item := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "displayName", "supportedModes"}, "properties": map[string]any{
		"id": text(1, 128), "displayName": text(1, 128), "supportedModes": map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "uniqueItems": true, "items": map[string]any{"const": string(providers.AuthorizationCodeMode)}},
	}}
	success := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"page"}, "properties": map[string]any{
		"page": map[string]any{"type": "array", "maxItems": 100, "items": item}, "nextCursor": text(1, 512),
	}}
	failure := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}}}
	response := func(schema any) any {
		return map[string]any{"description": "No-store safe projection without provider configuration or credentials.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known shared rate.safe denial, rounded up to seconds; absent on unavailable authority.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	parameters := []any{
		map[string]any{"name": "limit", "in": "query", "required": true, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}},
		map[string]any{"name": "cursor", "in": "query", "required": false, "schema": text(1, 512)},
	}
	if localized {
		localizedFailure := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{
			"error": failure["properties"].(map[string]any)["error"], "message": text(1, 8192),
		}}
		for _, status := range []string{"400", "403", "429", "503"} {
			selected := responses[status].(map[string]any)
			selected["content"] = response(localizedFailure).(map[string]any)["content"]
			headers, _ := selected["headers"].(map[string]any)
			if headers == nil {
				headers = make(map[string]any)
			}
			headers["Content-Language"] = map[string]any{"description": "Actual rendered catalog locale, including message fallback. Absent when no localized message is emitted.", "schema": text(1, 64)}
			headers["Vary"] = map[string]any{"schema": map[string]any{"type": "string", "const": "Accept-Language"}}
			selected["headers"] = headers
		}
		parameters = append(parameters, map[string]any{"name": "Accept-Language", "in": "header", "required": false, "description": "One bounded language preference field, at most 32 ranges. Duplicate fields and malformed/duplicate ranges use the configured default. Complete exclusions retain machine-only errors; no cookies or session preferences participate.", "schema": text(0, 4096)})
	}
	data, _ := json.Marshal(map[string]any{
		"operationId": "identity.oauth.provider-list", "security": []any{}, "responses": responses,
		"description": "Explicit public HTTPS configured-provider discovery. Required limit, optional opaque cursor bound to the native snapshot and same limit. Only safe IDs, display names and actual configured modes; no session, CSRF, Origin, Authorization, body or Idempotency-Key. Shared canonical rate.safe, not provider protocol admission.",
		"parameters":  parameters,
	})
	return &identityhttp.WireOperation{Definition: data}
}
