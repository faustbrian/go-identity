package sessionhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func adminSessionListWire(cookie string) *identityhttp.WireOperation {
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	identifier := map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[!-~]{1,128}$"}
	cursor := map[string]any{"type": "string", "maxLength": 216, "pattern": "^([A-Za-z0-9_-]{46,215})?$", "description": "Empty at completion; otherwise the native canonical unpadded base64url v1 scope-bound keyset locator. It is not authentication or authorization."}
	instant := map[string]any{"type": "string", "format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$", "description": "Nonzero UTC instant in years 1..9999, preserving original recorded activity and expiry."}
	device := object([]string{"sessionID", "label", "lastSeenAt", "expiresAt", "current", "inactive"}, map[string]any{
		"sessionID":  identifier,
		"label":      map[string]any{"type": "string", "maxLength": 128, "pattern": "^[^\\u0000-\\u001f\\u007f-\\u009f]*$", "description": "Untrusted display text, at most 128 UTF-8 bytes, without control runes; not device trust."},
		"lastSeenAt": instant, "expiresAt": instant,
		"current": map[string]any{"type": "boolean"}, "inactive": map[string]any{"type": "boolean"},
	})
	success := object([]string{"sessions", "nextCursor"}, map[string]any{
		"sessions": map[string]any{"type": "array", "maxItems": 100, "items": device}, "nextCursor": cursor,
	})
	failure := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "misdirected_request", "rate_limited", "unavailable", "not_found", "method_not_allowed"}}})
	content := func(schema any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	responses := map[string]any{"200": map[string]any{"description": "Authorized bounded safe session page, including inactive records. This metadata confers no authority and never issues or clears cookies.", "content": content(success)}}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = map[string]any{"description": "Redacted failure without partial sessions, cursor, credentials or cookie mutation.", "content": content(failure)}
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"type": "string", "const": "GET"}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^([1-9]|[1-5][0-9]|60)$"}, "description": "Audited shared administrative quota delay, 1..60 whole seconds."}}
	requestCursor := map[string]any{"type": "string", "minLength": 46, "maxLength": 216, "pattern": "^[A-Za-z0-9_-]{46,215}$", "description": "Optional nonempty native canonical v1 locator from the preceding page; fresh authentication and target policy still apply."}
	definition, _ := json.Marshal(map[string]any{
		"operationId": adminSessionListOperation,
		"description": "Explicit selected GET on the mapped HTTPS tenant with only the original ordinary session cookie. Native authentication derives the actor and exact target permission before one synchronous shared rate.admin admission and page read. Exactly targetSubjectID and canonical decimal limit 1..100 are required; cursor is optional. No body, trailer, CSRF input, Idempotency-Key, Authorization or actor/tenant override. Responses are no-store, nosniff and credential-free; no implicit retry or cookie mutation.",
		"security":    []any{map[string]any{"AdminSessionListCookie": []string{}}},
		"parameters": []any{
			map[string]any{"in": "query", "name": "targetSubjectID", "required": true, "schema": identifier},
			map[string]any{"in": "query", "name": "limit", "required": true, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}, "description": "Canonical decimal spelling, without sign, leading zero or fractional notation."},
			map[string]any{"in": "query", "name": "cursor", "required": false, "schema": requestCursor},
		},
		"responses": responses,
	})
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie, "description": "Singleton original ordinary administrator session cookie; no alternate bearer or impersonation child fallback."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "AdminSessionListCookie", Definition: scheme}}}
}
