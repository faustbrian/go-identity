package mfahttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func regenerationWire(c RecoveryRegenerateConfig) *identityhttp.WireOperation {
	object := func(required []string, p map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	success := object([]string{"regenerated", "commitOutcome", "commandID", "recoveryCodes"}, map[string]any{"regenerated": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "recoveryCodes": map[string]any{"type": "array", "minItems": c.CodeCount, "maxItems": c.CodeCount, "items": map[string]any{"type": "string", "minLength": 22, "maxLength": 22, "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"}, "description": "Fresh known-commit plaintext only. Retain securely; never log, cache or retry disclosure."}})
	failure := object([]string{"regenerated", "commitOutcome", "error"}, map[string]any{"regenerated": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "origin_or_csrf_denied", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "conflict", "in_progress", "replay", "unavailable"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store original replacement outcome. No new session, redirect or successor command.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	d, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.recovery-regenerate", "description": "Explicit cookie-only whole-set replacement with a separately issued fresh active-factor proof. Exact HTTPS Origin and native synchronizer required. Original signed proof/session bindings and unchanged proof timestamps precede original-command shared quotas. Native protected replacement consumes proof, retires predecessor codes and revokes sessions atomically. Revocation does not renew or revive original delivery authority. Only fresh known commitment reveals codes; replay, cancellation and ambiguity do not. No user/set/count/purpose override, Authorization, Idempotency-Key, query, trailer or automatic retry.", "security": []any{map[string]any{"MFARegenerationSession": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "enum": c.TrustedOrigins}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"commandID", "proofID"}, map[string]any{"commandID": id, "proofID": id})}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Actual original session bound to the factor proof; successful replacement revokes it."})
	return &identityhttp.WireOperation{Definition: d, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFARegenerationSession", Definition: scheme}}}
}
