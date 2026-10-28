package apikeyhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func operationWire(action string, first bool) *identityhttp.WireOperation {
	text := func(maximum int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum} }
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := text(128)
	permissions := map[string]any{"type": "array", "maxItems": 64, "uniqueItems": true, "items": text(128), "description": "Bytewise sorted, duplicate-free native permission ceiling; each string is at most128 UTF-8 bytes and contains no whitespace/control characters. Empty is an explicit zero-permission ceiling."}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}
	expected := map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 1, "description": "Exact advanceable unsigned decimal version; fractions, exponent notation and overflow deny."}
	request := object([]string{"keyID", "expectedVersion"}, map[string]any{"keyID": id, "expectedVersion": expected})
	if action == "create" {
		request = object([]string{"name", "permissions", "expiresAt"}, map[string]any{"name": text(128), "permissions": permissions, "expiresAt": map[string]any{"type": "string", "format": "date-time", "description": "Explicit absolute expiry at microsecond precision; native configuration and current authority enforce its lifetime."}})
	}
	errorCode := map[string]any{"type": "string", "enum": []string{"invalid_request", "forbidden", "conflict", "in_progress", "unavailable", "rate_limited", "not_found", "method_not_allowed", "misdirected_request"}}
	errorSchema := object([]string{"error"}, map[string]any{"error": errorCode})
	command := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	scope := object([]string{"commandID", "tenantID", "userID", "actorID", "actorKind", "operationID", "recordID"}, map[string]any{"commandID": command, "tenantID": id, "userID": id, "actorID": id, "actorKind": map[string]any{"const": "user"}, "operationID": map[string]any{"const": "identity.apikey." + action}, "recordID": id})
	fields := map[string]any{"committed": map[string]any{"type": "boolean"}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": command, "recovery": scope, "error": errorCode}
	if action != "delete" {
		fields["key"] = object([]string{"id", "version", "name", "permissions", "expiresAt"}, map[string]any{"id": id, "version": version, "name": text(128), "permissions": permissions, "expiresAt": map[string]any{"type": "string", "format": "date-time"}})
		fields["secret"] = map[string]any{"type": "string", "pattern": "^idk_[A-Za-z0-9_-]{43}$", "readOnly": true, "description": "Only original invocation-local proven-committed reveal-once material. Absent on replay/recovery/unknown/failure; never reconstructed."}
	}
	response := object([]string{"committed", "commitOutcome"}, fields)
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "404", "405", "409", "421", "429", "503"} {
		var schema any = map[string]any{"oneOf": []any{errorSchema, response}}
		if status == "200" {
			schema = map[string]any{"allOf": []any{response, map[string]any{
				"required":   []string{"commandID", "recovery"},
				"properties": map[string]any{"committed": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}},
				"not":        map[string]any{"required": []string{"error"}},
			}}}
		}
		responses[status] = map[string]any{"description": "Bounded no-store JSON. Retain original request input/key and safe native recovery scope; outcome is not current authority or delivery confirmation.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}, "description": "Known shared rate denial; bounded ceiling seconds, no automatic retry."}}
	definition := map[string]any{"operationId": "identity.apikey." + action, "description": "Opt-in modern self-owned unlimited uncached Narrow API-key management. Exactly one native password session Authorization Bearer and original Idempotency-Key; ambient cookies never provide authority. Exact HTTPS tenant host and transport-derived full client IP; closed JSON, no owner/actor/tenant/configuration/network override. Native current policy and original exclusive15m authentication freshness remain mandatory. Shared IP10/10m and tenant/subject10/10m secret-rate admission is separate from native protected-risk admission. Native owner retains atomic mutation/audit/outbox, zero-overlap rotation, immutable grants/expiry and terminal revocation. Same-key retries disclose original outcome only and cannot reveal a new secret. Unknown or lost response does not authorize replacement issuance; use retained original input/key or direct current-authorized native status recovery. No recovery route or API-key-as-session, organization, legacy, quota or cache profile is selected.", "security": []any{map[string]any{"APIKeyManagementBearer": []string{}}}, "parameters": []any{map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9!#$%&'*+.^_`|~-]+$"}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}}, "responses": responses}
	wire, _ := json.Marshal(definition)
	out := &identityhttp.WireOperation{Definition: wire}
	if first {
		out.SecuritySchemes = []identityhttp.WireComponent{{Name: "APIKeyManagementBearer", Definition: []byte(`{"type":"http","scheme":"bearer","bearerFormat":"opaque native password session","description":"Exactly one Authorization Bearer credential; ambient cookies never supply authority."}`)}}
	}
	return out
}
