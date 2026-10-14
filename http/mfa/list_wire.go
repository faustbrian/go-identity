package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func listWire(c ListConfig) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	stamp := map[string]any{"type": "string", "format": "date-time"}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(18446744073709551615)}
	label := map[string]any{"type": "string", "maxLength": 128, "description": "Untrusted presentation metadata; never factor/device authority."}
	factor := object([]string{"id", "method", "state", "createdAt", "version"}, map[string]any{"id": id, "method": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}, "state": map[string]any{"type": "integer", "enum": []int{1, 2, 3}, "description": "1 pending, 2 active, 3 revoked. Display state is not authorization."}, "label": label, "createdAt": stamp, "lastUsedAt": stamp, "version": version})
	device := object([]string{"id", "expiresAt", "version"}, map[string]any{"id": id, "label": label, "expiresAt": stamp, "lastUsedAt": stamp, "version": version})
	success := object([]string{"factors", "trustedDevices", "recoveryCodeCount"}, map[string]any{"factors": map[string]any{"type": "array", "minItems": 0, "maxItems": 100, "items": factor}, "trustedDevices": map[string]any{"type": "array", "minItems": 0, "maxItems": 100, "items": device}, "recoveryCodeCount": map[string]any{"type": "integer", "minimum": 0, "maximum": 100, "description": "Unused active-set code count only, never plaintext or verifier."}})
	failure := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store credential-free metadata or redacted denial.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	definition, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.list", "description": "Explicit cookie-only authenticated self-listing. Exact HTTPS tenant host, current native session and action policy required. Safe metadata/counts only; no credential, verifier, proof, authority vector, command or commit outcome. Empty inventories and exhausted codes are valid. No query, body, Authorization, Idempotency-Key, mutation CSRF or automatic refresh. Original session expiry wins through rate/middleware/native-read and final delivery.", "security": []any{map[string]any{"MFAListSession": []string{}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Actual native current session; never issued, refreshed or extended by listing."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAListSession", Definition: scheme}}}
}
