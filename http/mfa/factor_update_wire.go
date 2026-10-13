package mfahttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func factorUpdateWire(c FactorUpdateConfig) *identityhttp.WireOperation {
	object := func(required []string, fields map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	label := map[string]any{"type": "string", "maxLength": 128, "description": "Untrusted presentation text, at most128 UTF-8 bytes; empty string explicitly clears the label. No control characters."}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(^uint64(0) - 1)}
	factor := object([]string{"id", "method", "label", "state", "createdAt", "version"}, map[string]any{"id": id, "method": map[string]any{"const": "totp"}, "label": label, "state": map[string]any{"const": 2}, "createdAt": map[string]any{"type": "string", "format": "date-time"}, "lastUsedAt": map[string]any{"type": "string", "format": "date-time"}, "version": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}})
	success := object([]string{"commitOutcome", "commandID", "factor"}, map[string]any{"commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "factor": factor})
	failure := object([]string{"commitOutcome", "error"}, map[string]any{"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_or_csrf_denied", "denied", "rate_limited", "unavailable", "conflict", "in_progress"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store metadata/observation. A known commitment is conserved even when metadata is withheld; absence is not rollback.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	body := object([]string{"factorID", "proofID", "action", "name", "expectedVersion"}, map[string]any{"factorID": id, "proofID": id, "action": map[string]any{"const": "rename"}, "name": label, "expectedVersion": version})
	d, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.factor-update", "description": "Explicit cookie-only TOTP rename with original action/session-bound factor proof, native recent-primary policy, keyed shared quotas, optimistic version and protected atomic proof/session/audit effects. Removal/replacement are unselected. Command identity is derived by the native keyed owner, never supplied in the body. No Authorization, query, target-user, method/purpose override, trailer, secret or session issuance. Original evidence expiry is never renewed; retry/recovery disclose no fresh factor metadata.", "security": []any{map[string]any{"MFAFactorUpdateSession": []string{}}}, "parameters": []any{map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}}, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "enum": c.TrustedOrigins}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	return &identityhttp.WireOperation{Definition: d, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAFactorUpdateSession", Definition: scheme}}}
}
