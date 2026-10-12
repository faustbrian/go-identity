package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func uriWire(c URIConfig) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	success := object([]string{"disclosed", "commitOutcome", "commandID", "enrollmentID", "uri"}, map[string]any{"disclosed": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "enrollmentID": id, "uri": map[string]any{"type": "string", "minLength": 1, "maxLength": 8192, "description": "First committed otpauth provisioning only. Never log, cache, retry disclosure or place in redirects."}})
	failure := object([]string{"disclosed", "commitOutcome", "error"}, map[string]any{"disclosed": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_or_csrf_denied", "denied", "rate_limited", "conflict", "in_progress", "replay", "unavailable"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store original reveal outcome; no cookie, session, redirect or successor.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	definition, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.totp-uri", "description": "Cookie-only pending-enrollment disclosure using its original session/synchronizer and stable random reveal command. Exact HTTPS Origin required. Native original-custody source supplies immutable challenge quota and earliest delivery deadline; neither session reads nor retries renew it. Native mutation atomically consumes reveal. Idempotency-Key, Authorization, body-selected subject/lifetime, queries and trailers are forbidden. Matching replay returns committed metadata with 409 and no URI.", "security": []any{map[string]any{"MFAProvisioningSession": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "enum": c.TrustedOrigins}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"commandID", "enrollmentID"}, map[string]any{"commandID": id, "enrollmentID": id})}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original primary session that created the pending enrollment."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAProvisioningSession", Definition: scheme}}}
}
