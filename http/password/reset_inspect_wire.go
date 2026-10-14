package passwordhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func resetInspectOperation(c ResetInspectConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	handler, err := NewResetInspectHandlerWithMiddleware(c, middleware)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.reset-inspect", Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store advisory valid/invalid state; no identity, credential, expiry, redirect or execution ticket.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(object([]string{"valid"}, map[string]any{"valid": map[string]any{"type": "boolean"}}))}
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "rate_limiter_unavailable", "unavailable"}}
	failure := map[string]any{"oneOf": []any{
		object([]string{"valid", "error"}, map[string]any{"valid": map[string]any{"const": false}, "error": codes}),
		object([]string{"error"}, map[string]any{"error": codes}),
	}}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no inspection.", "content": map[string]any{"text/plain": plain}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	definition := map[string]any{"operationId": "identity.password.reset-inspect", "description": "Origin-bound repeatable read of the original unused emailed reset proof and current recovery eligibility. Exactly token in bounded closed JSON; no URL/query bearer, idempotency key, identity override, consumption, hashing or automatic signin. Shared canonical secret budgets precede current native inspection. Positive UI state is not permission held across later completion.", "security": []any{}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "maxLength": 2048}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"token"}, map[string]any{"token": map[string]any{"type": "string", "minLength": 32, "maxLength": 4096, "writeOnly": true}})}}}, "responses": responses}
	encoded, err := json.Marshal(definition)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = &identityhttp.WireOperation{Definition: encoded}
	return op, nil
}
