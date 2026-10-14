package otphttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func signinWire() *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	positive := map[string]any{"type": "integer", "minimum": 1}
	keyVersion := map[string]any{"type": "integer", "minimum": 1, "maximum": 4294967295}
	attempt := object([]string{"commandID", "tenantID", "attemptID", "fingerprint", "fingerprintKeyVersion"}, map[string]any{
		"commandID": id, "tenantID": text(256), "attemptID": text(128), "fingerprint": text(128), "fingerprintKeyVersion": keyVersion,
	})
	recovery := object([]string{"sendCommandID", "attempt", "expectedVersion", "digestKeyVersion", "scopeDigest"}, map[string]any{
		"sendCommandID": id, "attempt": attempt, "expectedVersion": positive, "digestKeyVersion": keyVersion,
		"scopeDigest": map[string]any{"type": "array", "minItems": 32, "maxItems": 32, "items": map[string]any{"type": "integer", "minimum": 0, "maximum": 255}},
	})
	errorCode := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}
	success := object([]string{"signedIn", "commandID", "sessionID", "commitOutcome", "recovery"}, map[string]any{
		"signedIn": map[string]any{"const": true}, "commandID": id, "sessionID": text(128), "commitOutcome": map[string]any{"const": "committed"}, "recovery": recovery,
	})
	failure := map[string]any{"oneOf": []any{
		object([]string{"error"}, map[string]any{"error": errorCode}),
		object([]string{"signedIn", "commitOutcome", "error"}, map[string]any{
			"signedIn": map[string]any{"const": false}, "commandID": id, "sessionID": text(128), "recovery": recovery, "error": errorCode,
			"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}},
		}),
	}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free original outcome; no-store and nosniff. No response trailers. Correlation is not authority or permission to retry.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	// Shared router origin admission owns a fixed plaintext denial before this
	// feature's JSON response guard; advertise its real media, not a conversion.
	originContent := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = originContent
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native signin or credential delivery.", "content": map[string]any{"text/plain": originContent}}
	responses["200"].(map[string]any)["headers"] = map[string]any{
		"Set-Cookie":   map[string]any{"description": "Fresh native session only: configured Secure/HttpOnly host-only cookie, Path=/, Lax or Strict. Never replay, error or recovery.", "schema": text(4096)},
		"X-CSRF-Token": map[string]any{"description": "Fresh session-bound synchronizer; never log or place in response JSON.", "schema": text(256)},
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded whole seconds; does not authorize retrying consumed signin.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	definition := map[string]any{
		"operationId": "identity.otp.signin",
		"description": "Original-flow OTP signin. Exact initiating HTTPS tenant host and Origin plus original __Host-identity_flow cookie. No query, trailers, Authorization or Idempotency-Key. Original Send command selects canonical destination and retained remember policy; clients cannot replace either. Shared IP admission precedes source discovery, then identifier admission and one atomic consuming call. Unknown outcome never retries; retain code-free native recovery correlation. Only fresh committed success delivers session and synchronizer headers.",
		"security":    []any{map[string]any{"IdentityOTPOriginalFlow": []any{}}},
		"parameters":  []any{map[string]any{"name": "Origin", "in": "header", "required": true, "description": "Exact configured initiating HTTPS Origin; no Referer fallback.", "schema": text(2048)}},
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"flowID", "sendCommandID", "code"}, map[string]any{
			"flowID": id, "sendCommandID": id, "code": map[string]any{"type": "string", "pattern": "^[!-~]{4,128}$", "writeOnly": true},
		})}}}, "responses": responses,
	}
	data, _ := json.Marshal(definition)
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_flow", "description": "Original bounded browser-flow custody, not an authenticated user session; never accepted from query or headers."})
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "IdentityOTPOriginalFlow", Definition: scheme}}}
}
