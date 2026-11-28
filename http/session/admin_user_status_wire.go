package sessionhttp

import (
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func adminUserStatusWire(operation, cookie string, target identity.Status) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	text := func(maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"}
	version := map[string]any{"type": "integer", "minimum": 2, "maximum": uint64(18446744073709551615)}
	requestFields := map[string]any{"userID": text(128)}
	required := []string{"userID", "expectedVersion"}
	schemeName := "AdminUserUnbanCookie"
	if target == identity.StatusBanned {
		schemeName = "AdminUserBanCookie"
		required = []string{"userID", "reason"}
		requestFields["reason"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "writeOnly": true, "description": "Registered redacted UTF-8 reason code, at most 512 bytes, without whitespace or controls. Never returned."}
		requestFields["expiresAt"] = map[string]any{"type": "string", "format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$", "description": "Optional explicit non-null UTC instant in years 1..9999, with at most six fractional digits and nonzero. Omission means indefinite. Native policy owns its permitted future duration."}
	} else {
		requestFields["expectedVersion"] = map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(18446744073709551614), "description": "Exact positive native version with room for the required single successor increment."}
	}
	consumers := (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: operation}}).RequiredConsumers()
	owner := object([]string{"owner", "status"}, map[string]any{
		"owner": map[string]any{"type": "string", "enum": consumers}, "status": map[string]any{"const": "pending"},
	})
	user := object([]string{"id", "tenantID", "status", "version"}, map[string]any{
		"id": text(128), "tenantID": text(128), "status": map[string]any{"const": string(target)}, "version": version,
	})
	revocation := object([]string{"cascadeID", "generation", "authorityVersion", "status", "owners", "externalLimitations"}, map[string]any{
		"cascadeID": id, "generation": map[string]any{"const": 1}, "authorityVersion": map[string]any{"type": "integer", "minimum": 2, "maximum": uint64(18446744073709551615)},
		"status": map[string]any{"const": "pending"}, "owners": map[string]any{"type": "array", "minItems": len(consumers), "maxItems": len(consumers), "items": owner},
		"externalLimitations": map[string]any{"type": "array", "maxItems": 0, "items": map[string]any{"type": "string"}},
	})
	success := object([]string{"commandID", "commitOutcome", "user", "revocation"}, map[string]any{
		"commandID": id, "commitOutcome": map[string]any{"const": "committed"}, "user": user, "revocation": revocation,
	})
	failure := object([]string{"commitOutcome", "error"}, map[string]any{
		"commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}},
		"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "conflict", "unavailable", "rate_limited", "misdirected_request", "not_found", "method_not_allowed"}},
	})
	content := func(schema any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	responses := map[string]any{"200": map[string]any{
		"description": "Authorized safe User and exact native pending revocation admission. This does not assert cleanup completion or revive old credentials. No cookie or CSRF token is issued.", "content": content(success),
	}}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = map[string]any{"description": "Redacted non-success without User or revocation metadata. Original observed command and commit outcome are retained when available; no automatic replay or cookie mutation.", "content": content(failure)}
	}
	// The shared CORS boundary may reject a foreign origin before this leaf.
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{
		"description": "Audited shared administrative quota delay in 1..60 whole seconds. Never authorizes an automatic replay.",
		"schema":      map[string]any{"type": "string", "pattern": "^([1-9]|[1-5][0-9]|60)$"},
	}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"type": "string", "const": "POST"}}}
	header := func(name string, schema any, description string) map[string]any {
		return map[string]any{"in": "header", "name": name, "required": true, "description": description, "schema": schema}
	}
	definition, _ := json.Marshal(map[string]any{
		"operationId": operation,
		"description": "Explicit opt-in exact POST on the mapped HTTPS tenant. Only the original ordinary administrator cookie and its current stored synchronizer confer custody; Authorization, query, trailers and body credential alternatives deny. An explicit exact trusted Origin is required with no Referer fallback. Native authentication and exact permission derive the actor before the shared administrative quota callback, request-key resolution or mutation. Strict JSON has no caller actor, tenant or command overrides. No independent synchronizer-age claim or automatic retry is made. Responses are no-store and nosniff.",
		"security":    []any{map[string]any{schemeName: []string{}}},
		"parameters": []any{
			header("Origin", text(2048), "Exactly one explicit trusted HTTPS Origin matching the mapped request origin; no Referer fallback."),
			header("X-CSRF-Token", map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}, "Exactly one canonical original stored-session synchronizer token; cookies and JSON never supply CSRF authority."),
			header("Idempotency-Key", map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}, "Exactly one opaque case-sensitive key; no trimming, body/query alternatives or response disclosure."),
		},
		"requestBody": map[string]any{"required": true, "content": content(object(required, requestFields))}, "responses": responses,
	})
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie, "description": "Required singleton original ordinary administrator session cookie; no child credential or Authorization substitution."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: schemeName, Definition: scheme}}}
}
