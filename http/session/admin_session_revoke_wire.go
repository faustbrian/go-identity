package sessionhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func adminSessionRevokeWire(cookie string) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	identifier := map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[!-~]{1,128}$"}
	success := map[string]any{"oneOf": []any{
		object([]string{"revoked", "version"}, map[string]any{
			"revoked": map[string]any{"const": true},
			"version": map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(18446744073709551615), "description": "Confirmed native successor version for this single session."},
		}),
		object([]string{"revoked"}, map[string]any{"revoked": map[string]any{"const": false}}),
	}, "description": "revoked discriminates confirmed mutation from a non-disclosing no-op. Only true carries a positive version; false omits version entirely, never zero or null."}
	failure := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "misdirected_request", "rate_limited", "unavailable", "not_found", "method_not_allowed"}}})
	content := func(schema any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	responses := map[string]any{"200": map[string]any{
		"description": "Authorized confirmed single-session mutation or non-disclosing repeat no-op. No cookies, credentials or target metadata are returned.", "content": content(success),
	}}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = map[string]any{"description": "Redacted non-success, including unknown native outcome, without revoked, version, credentials or cookie mutation. No automatic replay is authorized.", "content": content(failure)}
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"type": "string", "const": "POST"}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{
		"schema": map[string]any{"type": "string", "pattern": "^([1-9]|[1-5][0-9]|60)$"}, "description": "Audited shared administrative quota delay in 1..60 whole seconds; not permission for automatic replay.",
	}}
	definition, _ := json.Marshal(map[string]any{
		"operationId": adminSessionRevokeOperation,
		"description": "Explicit opt-in repeat POST on the mapped HTTPS tenant. Exactly one trusted Origin must equal the mapped request origin with no Referer fallback. Only the original ordinary administrator cookie and its stored-session X-CSRF-Token supply custody. Native current authentication and exact target authorization derive the actor before one synchronous shared rate.admin admission. Strict bounded JSON has exactly userID and sessionID; query, trailers, Idempotency-Key, Authorization, actor/tenant overrides and alternate credential inputs deny. No independent synchronizer age, transport key or automatic retry is introduced. Responses are no-store and nosniff and never alter cookies.",
		"security":    []any{map[string]any{"AdminSessionRevokeCookie": []string{}}},
		"parameters": []any{
			map[string]any{"in": "header", "name": "Origin", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 2048}, "description": "Singleton exact trusted HTTPS Origin matching the mapped request origin; no Referer fallback."},
			map[string]any{"in": "header", "name": "X-CSRF-Token", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}, "description": "Singleton canonical original stored-session synchronizer; no cookie, form or JSON fallback."},
		},
		"requestBody": map[string]any{"required": true, "content": content(object([]string{"userID", "sessionID"}, map[string]any{"userID": identifier, "sessionID": identifier}))},
		"responses":   responses,
	})
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie, "description": "Required singleton original ordinary administrator session cookie. No Authorization or impersonation child substitute."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "AdminSessionRevokeCookie", Definition: scheme}}}
}
