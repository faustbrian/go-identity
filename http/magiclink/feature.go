package magiclinkhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// FeatureConfig selects only non-nil operations. Request exposes initiation;
// Consume selects explicit consumption, never scanner inspection. Empty selection
// denies; omit this feature from composition to expose no routes or metadata.
type FeatureConfig struct {
	Request *RequestConfig
	Consume *ConsumeConfig
}

// NewFeature contributes actual selected handlers and concrete wire schemas.
// Construction performs no native IO or global registration.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware binds hooks to real owned execution phases; selection
// is frozen and invalid dependencies return no partial feature.
func NewFeatureWithMiddleware(c FeatureConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if c.Request == nil && c.Consume == nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var ops []identityhttp.OperationDescriptor
	if c.Request != nil {
		h, err := NewRequestHandlerWithMiddleware(*c.Request, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/magiclink", OperationID: "identity.magic-link.request", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = requestWire(*c.Request)
		ops = append(ops, op)
	}
	if c.Consume != nil {
		h, err := NewConsumeHandlerWithMiddleware(*c.Consume, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = consumeWire(*c.Consume)
		if c.Request != nil {
			op.Wire.SecuritySchemes = nil
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/magiclink", Operations: ops})
}

func requestWire(c RequestConfig) *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, fields map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "denied", "unavailable", "conflict", "in_progress"}}
	success := object([]string{"accepted", "commitOutcome", "commandID"}, map[string]any{"accepted": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id})
	failed := object([]string{"accepted", "commitOutcome", "error"}, map[string]any{"accepted": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": codes})
	failureSchema := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), failed}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store enumeration-safe acknowledgement; no email, proof, retry key, cookie, session or redirect.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failureSchema)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission, without native request execution.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded whole seconds; preserve original attempt and key.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	mail := map[string]any{"type": "string", "minLength": 1, "maxLength": 4096, "writeOnly": true, "description": "Raw bounded mailbox; native frozen email policy owns canonicalization."}
	body := object([]string{"commandID", "email", "intent", "callbackURL", "preAuthID"}, map[string]any{"commandID": id, "email": mail, "intent": map[string]any{"type": "string", "enum": []string{"signin-only", "signup-if-allowed"}}, "callbackURL": map[string]any{"const": c.CallbackURL}, "preAuthID": id})
	definition := map[string]any{"operationId": "identity.magic-link.request", "description": "Opt-in initiation only. Exact HTTPS mapped tenant and Origin, original flow ID/cookie and one Idempotency-Key are required. IP admission precedes owning address normalization and destination admission. Native current browser, factor, recipient and risk authority still apply. Eligible and suppressed recipients receive identical acknowledgement. Preserve original command/key for explicit retry and proof-free recovery; unknown is not rollback. No automatic send, retry, redirect or session.", "security": []any{map[string]any{"MagicLinkOriginalFlow": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"const": string(c.Origin)}}, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": text(256)}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses}
	definition["security"] = []any{map[string]any{"MagicLinkOriginalFlow": []string{}, "MagicLinkBrowserDevice": []string{}}}
	data, _ := json.Marshal(definition)
	flow, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_flow", "description": "Original server-issued browser flow; possession is authenticated by the native workflow, not by transport metadata."})
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Signed original browser correlation under selected tenant/origin policy; not a session or MFA factor."})
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "MagicLinkOriginalFlow", Definition: flow}, {Name: "MagicLinkBrowserDevice", Definition: device}}}
}
