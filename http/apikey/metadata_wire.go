package apikeyhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func metadataWire(action string, first, organizations bool) *identityhttp.WireOperation {
	text := func(maximum int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum} }
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := text(128)
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}
	owner := map[string]any{"oneOf": []any{
		object([]string{"kind", "version", "userID"}, map[string]any{"kind": map[string]any{"const": "user"}, "version": version, "userID": id}),
		object([]string{"kind", "version", "organizationID"}, map[string]any{"kind": map[string]any{"const": "organization"}, "version": version, "organizationID": id}),
	}}
	properties := map[string]any{
		"id": id, "version": version, "authorityVersion": version, "owner": owner,
		"configurationID": id, "configurationRevision": version,
		"name":        map[string]any{"type": "string", "maxLength": 128},
		"status":      map[string]any{"type": "string", "enum": []string{"active", "revoked"}},
		"permissions": map[string]any{"type": "array", "maxItems": 64, "uniqueItems": true, "items": text(128), "description": "Stored sorted immutable ceiling only, not current effective permissions or an authorization proof."},
		"createdAt":   map[string]any{"type": "string", "format": "date-time"},
		"expiresAt":   map[string]any{"type": []string{"string", "null"}, "format": "date-time", "description": "Null preserves an explicitly selected legacy key's absent expiry. Expired/revoked records remain metadata, not usable credentials."},
		"rootID":      id, "rootVersion": version, "previousID": id,
		"issuer": text(512), "environment": text(128), "audience": text(128),
	}
	required := []string{"id", "version", "authorityVersion", "owner", "configurationID", "configurationRevision", "name", "status", "permissions", "createdAt", "expiresAt", "rootID", "rootVersion", "issuer", "environment", "audience"}
	key := object(required, properties)
	cursor := map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[A-Za-z0-9_-]+$"}
	response := object([]string{"key"}, map[string]any{"key": key})
	parameters := []any{}
	parameter := func(name string, required bool, schema any) any {
		return map[string]any{"name": name, "in": "query", "required": required, "schema": schema}
	}
	if action == "get" {
		parameters = append(parameters, parameter("keyID", true, id))
	} else {
		response = object([]string{"keys"}, map[string]any{"keys": map[string]any{"type": "array", "maxItems": 200, "items": key}, "nextCursor": cursor})
		parameters = append(parameters,
			parameter("limit", true, map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "Canonical unsigned decimal only; no sign, leading zeroes, fractions or exponent notation."}),
			parameter("cursor", false, cursor),
			map[string]any{"name": "configurationIDs", "in": "query", "required": false, "description": "One JSON array encoded as a single query value within configured URI/decoded-byte limits. Exact sorted distinct IDs; punctuation is not a separator. Absent/empty selects configured profiles.", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "array", "maxItems": 16, "uniqueItems": true, "items": id}}}},
		)
	}
	if organizations {
		parameters = append(parameters, parameter("organizationID", false, id))
	}
	errorSchema := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "forbidden", "https_required", "unavailable", "rate_limited", "not_found", "method_not_allowed", "misdirected_request"}}})
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "404", "405", "421", "429", "503"} {
		schema := errorSchema
		if status == "200" {
			schema = response
		}
		responses[status] = map[string]any{"description": "Bounded no-store metadata JSON; never key material, digests, a session or mutation receipt.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"const": "GET"}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	wire, _ := json.Marshal(map[string]any{"operationId": "identity.apikey." + action,
		"description": "Opt-in strict password-bearer metadata read. No body, Idempotency-Key, cookie fallback or request-selected user/tenant/actor. Missing and unauthorized targets both deny. Native current session/tenant/user/configuration/policy and selected organization membership authorize every call. A cursor is only a live-view position, never authority or a held snapshot. Shared rate.safe admission performs no API-key verification or quota debit. Returned permissions are historical stored ceilings; reads require no sensitive-change proof and grant none. Query/header/URI and result sizes are bounded; the original authority deadline never renews.",
		"security":    []any{map[string]any{"APIKeyManagementBearer": []string{}}}, "parameters": parameters, "responses": responses,
	})
	out := &identityhttp.WireOperation{Definition: wire}
	if first {
		out.SecuritySchemes = []identityhttp.WireComponent{{Name: "APIKeyManagementBearer", Definition: []byte(`{"type":"http","scheme":"bearer","bearerFormat":"opaque native password session","description":"Exactly one Authorization Bearer credential; ambient cookies never supply authority."}`)}}
	}
	return out
}
