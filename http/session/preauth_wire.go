package sessionhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func preAuthWire() *identityhttp.WireOperation {
	return preAuthWireProfile(false)
}

func preAuthWireProfile(device bool, methods ...PreAuthMethod) *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	date := map[string]any{"type": "string", "format": "date-time"}
	fields := map[string]any{"issued": map[string]any{"const": false}, "commandID": text(22), "flowID": text(22), "issuedAt": date, "expiresAt": date,
		"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}},
		"error":         map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable", "conflict", "in_progress"}}}
	success := map[string]any{}
	for k, v := range fields {
		if k != "error" {
			success[k] = v
		}
	}
	success["issued"] = map[string]any{"const": true}
	success["commitOutcome"] = map[string]any{"const": "committed"}
	errorSchema := map[string]any{"oneOf": []any{
		object([]string{"error"}, map[string]any{"error": fields["error"]}),
		object([]string{"issued", "issuedAt", "expiresAt", "commitOutcome", "error"}, fields),
	}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free original outcome. Cache-Control: no-store; X-Content-Type-Options: nosniff.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(object([]string{"issued", "commandID", "flowID", "issuedAt", "expiresAt", "commitOutcome"}, success))}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(errorSchema)
	}
	// Shared router origin admission runs before the session JSON guard; its
	// fixed plaintext denial must not be advertised as a JSON conversion.
	originContent := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = originContent
	responses["408"] = map[string]any{"description": "Cancellation during shared origin admission; no issuance or cookie delivery.", "content": map[string]any{"text/plain": originContent}}
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Original reveal-once __Host-identity_flow credential: Secure, HttpOnly, host-only, Path=/, Lax or Strict. Fresh error-free commitment only, never replay or recovery.", "schema": text(4096)}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Whole seconds; no automatic issuance retry.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	definition := map[string]any{"operationId": "identity.session.preauth-issue", "description": "Explicit original browser-flow initiation, not a user session. Exact HTTPS host-mapped tenant and configured Origin; no query, trailers, Authorization or Idempotency-Key. Ambient cookies confer no authority. Shared IP rate.auth admission precedes preparation. Fixed trusted action/callback/policy; five-minute original timeline. Each deliberate start is independent; unknown delivery never retries or renews. Native recovery is outcome-only.",
		"security": []any{}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "description": "Exact configured HTTPS Origin; no Referer fallback. Runtime trust values are not exported.", "schema": text(2048)}},
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{}, map[string]any{"remember": map[string]any{"type": "boolean", "description": "Absent selects configured default; resolve once for eventual session. Null is invalid. Flow TTL remains five minutes."}})}}}, "responses": responses}
	if device {
		definition["description"] = definition["description"].(string) + " Selected non-authenticating browser-device profile: validate existing __Host-identity_device custody before preparation; absent custody is issued after IP admission and delivered only with successful original flow. Existing device expiry is never renewed. Malformed, duplicate, expired or scope-mismatched device cookies deny."
		responses["200"].(map[string]any)["headers"].(map[string]any)["Set-Cookie"].(map[string]any)["description"] = "Separate Set-Cookie fields: original __Host-identity_flow, plus __Host-identity_device only when absent. Both Secure, HttpOnly, host-only, Path=/, Lax or Strict; device is bounded non-authenticating correlation, never session/MFA authority. Fresh error-free flow commitment only; no replay, error or recovery delivery. Existing device is not redelivered or renewed."
	}
	if len(methods) != 0 {
		names := make([]string, len(methods))
		for i, method := range methods {
			names[i] = method.Name
		}
		schema := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
		schema["properties"].(map[string]any)["method"] = map[string]any{"type": "string", "enum": names, "description": "Exact selected login-method name. Absent retains the default deployment profile. Selects a fixed issuer; cannot override action, callback, origin or policy."}
		definition["description"] = definition["description"].(string) + " Optional method selects only an explicitly configured fixed profile; unknown, null or empty method denies before preparation."
	}
	data, _ := json.Marshal(definition)
	return &identityhttp.WireOperation{Definition: data}
}
