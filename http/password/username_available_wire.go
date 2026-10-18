package passwordhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func usernameAvailabilityOperation(c UsernameAvailabilityConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewUsernameAvailabilityHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/username", OperationID: "identity.username.available", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 4096})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	object := func(required []string, p map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	response := func(s any) any {
		return map[string]any{"description": "No-store advisory observation, never a reservation or current authorization.", "content": map[string]any{"application/json": map[string]any{"schema": s}}}
	}
	responses := map[string]any{"200": response(object([]string{"available"}, map[string]any{"available": map[string]any{"type": "boolean"}}))}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(object([]string{"available", "error"}, map[string]any{"available": map[string]any{"const": false}, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}}))
	}
	definition, err := json.Marshal(map[string]any{"operationId": "identity.username.available", "description": "Explicit advisory username discovery. Exactly one raw username query; tenant/network derive from mapped HTTPS transport. Each request charges native durable risk/rate and canonical audit before normalization/occupancy. No credentials, reservation, identity/status details, cache or weaker-provider fallback.", "security": []any{}, "parameters": []any{map[string]any{"name": "username", "in": "query", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}}}, "responses": responses})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = &identityhttp.WireOperation{Definition: definition}
	return op, nil
}
