package identityhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// OpenapiDocumentRequest has no input. Export cannot select hosts, tenants,
// credentials, feature sets or another snapshot from request data.
type OpenapiDocumentRequest struct{}

// OpenapiDocumentResult preserves the exact immutable document and its digest.
// Accessors return detached storage; no authentication authority is conveyed.
type OpenapiDocumentResult struct {
	Document OpenAPIDocument
	Digest   [32]byte
}

// OpenapiDocument exports this previously constructed snapshot without IO,
// callbacks, rate debit or mutation. Holding the snapshot grants static export
// access, not permission to expose an HTTP endpoint. A zero document or nil
// context is invalid; cancellation retains its standard context identity.
// This direct in-process static export has no client-initiated rate policy.
func (d OpenAPIDocument) OpenapiDocument(ctx context.Context, _ OpenapiDocumentRequest) (OpenapiDocumentResult, error) {
	if ctx == nil || len(d.data) == 0 {
		return OpenapiDocumentResult{}, identity.InvalidInputError{Field: "openapi_document"}
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return OpenapiDocumentResult{}, identity.DeadlineExceededError{}
		}
		return OpenapiDocumentResult{}, identity.CancelledError{}
	}
	return OpenapiDocumentResult{Document: d, Digest: d.Digest()}, nil
}

// MetadataConfig explicitly opts into public GET /openapi.json. Public must
// be true; zero does not select exposure. This profile does not authenticate
// administrators or implement protected metadata: use no metadata endpoint
// until that deployment's protected-router composition is available.
// Network policy is copied; Rate is borrowed and shared with other safe routes.
// MaximumDuration is 1ms..30s and never extends an incoming deadline. Stores
// must honor it. A server additionally owns bounded response streaming.
type MetadataConfig struct {
	Public          bool
	Network         NetworkConfig
	Rate            *SafeRateLimiter
	MaximumDuration time.Duration
}

// NewDocumentedMetadataHandler explicitly selects the canonical metadata
// operation alongside services and returns their one validated immutable
// document and matching dispatcher. Existing constructors remain metadata-off.
// The export includes itself exactly once; collisions/missing dependencies
// fail atomically. Construction performs no IO or calls to feature handlers.
//
// Only exact HTTPS GET /openapi.json on an allowlisted public or tenant host is
// accepted, with no query/body/trailer/Idempotency-Key or Authorization header.
// Cookies confer no authority and are ignored. Trusted network facts feed the
// shared canonical rate.safe limiter once; malformed requests never debit it.
// Success serves exact JSON(), never a runtime-derived wrapper or revalidation.
// Errors are fixed no-store/nosniff JSON: 400 malformed, 421 unknown host, 429
// exhausted, 503 unavailable/canceled. Dispatcher additionally owns 404/405.
// No automatic HEAD, CORS, cache validators, cookies or coverage-report endpoint
// are added. The separate Coverage export retains disabled obligations, while
// wire paths/components contain only selected operations. This remains a
// selected public profile, not the complete NewRouter/security composition.
func NewDocumentedMetadataHandler(ctx context.Context, config DocumentConfig, metadata MetadataConfig, services FeatureServices) (http.Handler, OpenAPIDocument, error) {
	if !metadata.Public || !metadata.Rate.Configured() || metadata.MaximumDuration < time.Millisecond || metadata.MaximumDuration > 30*time.Second || len(services.Features) >= 64 {
		return nil, OpenAPIDocument{}, ErrInvalidInput
	}
	network, err := NewNetworkResolver(metadata.Network)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	decoder, err := NewRequestDecoder(metadata.Network.Limits)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	// The closure is published only after complete construction and snapshot
	// assignment. No feature callback can observe an incomplete document.
	var document OpenAPIDocument
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !probeRequest(w, r, "/openapi.json") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), metadata.MaximumDuration)
		defer cancel()
		r = r.WithContext(ctx)
		if ctx.Err() != nil {
			probeResponse(w, 503, `{"error":"unavailable"}`)
			return
		}
		if _, _, err := decoder.IdempotencyKey(r, HeaderForbidden); err != nil {
			probeResponse(w, 400, `{"error":"invalid_request"}`)
			return
		}
		if _, _, err := decoder.Bearer(r, HeaderForbidden); err != nil {
			probeResponse(w, 400, `{"error":"invalid_request"}`)
			return
		}
		facts, err := network.Resolve(r)
		if err != nil {
			probeResponse(w, 421, `{"error":"misdirected_request"}`)
			return
		}
		if facts.Scheme() != "https" {
			probeResponse(w, 400, `{"error":"invalid_request"}`)
			return
		}
		admission, err := metadata.Rate.Admit(ctx, facts, "identity.openapi.document", identity.UserID(""))
		if err != nil {
			if errors.Is(err, ErrRateLimited) {
				w.Header().Set("Retry-After", strconv.FormatInt(int64((admission.RetryAfter+time.Second-1)/time.Second), 10))
				probeResponse(w, 429, `{"error":"rate_limited"}`)
			} else {
				probeResponse(w, 503, `{"error":"unavailable"}`)
			}
			return
		}
		if ctx.Err() != nil {
			probeResponse(w, 503, `{"error":"unavailable"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(document.data)
	})
	op, err := NewCanonicalOperation(CanonicalOperationConfig{Owner: "identity/http", OperationID: "identity.openapi.document", Handler: handler, CSRF: CSRFPolicy{Mode: CSRFNone}, MaximumSerializedBytes: 16 << 20})
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	op.Wire = metadataWire()
	feature, err := NewFeature(FeatureConfig{ID: "identity/http", Operations: []OperationDescriptor{op}})
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	selected := FeatureServices{Features: append(append([]Feature(nil), services.Features...), feature)}
	dispatch, snapshot, err := NewDocumentedHandler(ctx, config, selected)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	document = snapshot
	return dispatch, snapshot, nil
}

func metadataWire() *WireOperation {
	response := func(schema any) any {
		return map[string]any{"description": "Fixed public metadata projection; no-store and nosniff.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	success := map[string]any{"type": "object", "required": []string{"openapi", "info", "paths"}, "properties": map[string]any{"openapi": map[string]any{"const": "3.1.1"}, "info": map[string]any{"type": "object"}, "paths": map[string]any{"type": "object"}}}
	errorSchema := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}}}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "404", "405", "421", "429", "503"} {
		responses[status] = response(errorSchema)
	}
	data, _ := json.Marshal(map[string]any{"operationId": "identity.openapi.document", "description": "Explicit public HTTPS GET on an allowlisted host; shared rate.safe. No body, query, trailers, retry key or Authorization. Exact immutable OpenAPI JSON; coverage inventory exported separately, never as enabled capability.", "security": []any{}, "responses": responses})
	return &WireOperation{Definition: data}
}
