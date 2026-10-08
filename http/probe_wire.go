package identityhttp

import "encoding/json"

func probeWire(id string) *WireOperation {
	errorSchema := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "unavailable"}}}}
	response := func(schema any) any {
		return map[string]any{"description": "Fixed safe JSON; no-store and nosniff.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	success := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"status"}, "properties": map[string]any{"status": map[string]any{"const": "alive"}}}
	if id == "identity.readiness" {
		success = map[string]any{"type": "object", "additionalProperties": false, "required": []string{"ready"}, "properties": map[string]any{"ready": map[string]any{"const": true}}}
	}
	responses := map[string]any{"200": response(success), "400": response(errorSchema), "404": response(errorSchema), "405": response(errorSchema), "503": response(errorSchema)}
	if id == "identity.readiness" {
		responses["503"] = response(map[string]any{"oneOf": []any{errorSchema, map[string]any{"type": "object", "additionalProperties": false, "required": []string{"ready"}, "properties": map[string]any{"ready": map[string]any{"const": false}}}}})
	}
	definition, _ := json.Marshal(map[string]any{"operationId": id, "description": "Exact GET with no query, request body, trailers or Idempotency-Key. No implicit HEAD. Internal dependency codes and diagnostics never serialize.", "security": []any{}, "responses": responses})
	return &WireOperation{Definition: definition}
}
