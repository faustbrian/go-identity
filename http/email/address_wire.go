package emailhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func addressQueryWire(c AddressQueryConfig, get bool) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(18446744073709551615)}
	address := object([]string{"identifierID", "userID", "primary", "verified", "identifierVersion", "verificationVersion"}, map[string]any{"identifierID": id, "userID": id, "primary": map[string]any{"type": "boolean"}, "verified": map[string]any{"type": "boolean"}, "identifierVersion": version, "verificationVersion": version, "canonical": map[string]any{"type": "string", "maxLength": 512}, "display": map[string]any{"type": "string", "maxLength": 512}})
	parameter := func(name string, required bool, schema any) any {
		return map[string]any{"name": name, "in": "query", "required": required, "schema": schema}
	}
	action := "identity.email.address-list"
	schemeName := "EmailAddressListSession"
	parameters := []any{parameter("limit", false, map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25}), parameter("cursor", false, map[string]any{"type": "string", "minLength": 1, "maxLength": 512})}
	success := object([]string{"addresses"}, map[string]any{"addresses": map[string]any{"type": "array", "minItems": 0, "maxItems": 100, "items": address}, "nextCursor": map[string]any{"type": "string", "minLength": 1, "maxLength": 512}})
	if get {
		action = "identity.email.address-get"
		schemeName = "EmailAddressGetSession"
		parameters = []any{parameter("addressID", true, id)}
		success = object([]string{"address"}, map[string]any{"address": address})
	}
	failure := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}})
	response := func(schema any) any {
		return map[string]any{"description": "Authorized no-store snapshot or redacted denial; no credentials, command or mutation.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	definition, _ := json.Marshal(map[string]any{"operationId": action, "description": "Cookie-authenticated human self read. Exact HTTPS tenant and current native session/policy; no target-user override, Authorization, body, idempotency key, CSRF mutation, refresh or session issuance. Values remain subject to native disclosure policy; original session validity governs final delivery.", "parameters": parameters, "security": []any{map[string]any{schemeName: []string{}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Actual current native session; never issued, refreshed or extended by address reads."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: schemeName, Definition: scheme}}}
}
