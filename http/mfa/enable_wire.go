package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func enableWire(c EnableConfig) *identityhttp.WireOperation {
	text := func(lo, hi int) any { return map[string]any{"type": "string", "minLength": lo, "maxLength": hi} }
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	outcome := map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}
	success := object([]string{"enabled", "active", "commitOutcome", "commandID", "enrollmentID", "factorMethod", "expiresAt", "version"}, map[string]any{"enabled": map[string]any{"const": true}, "active": map[string]any{"const": false}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": text(1, 128), "enrollmentID": text(1, 128), "factorMethod": map[string]any{"const": "totp"}, "expiresAt": map[string]any{"type": "string", "format": "date-time"}, "version": map[string]any{"type": "integer", "minimum": 1}, "recoveryCodes": map[string]any{"type": "array", "minItems": c.FactorPolicy.RecoveryCodes, "maxItems": c.FactorPolicy.RecoveryCodes, "items": text(1, 256), "description": "First-known-commit plaintext only; absent on retry. Retain securely, never log."}})
	failure := object([]string{"enabled", "active", "commitOutcome", "error"}, map[string]any{"enabled": map[string]any{"const": false}, "active": map[string]any{"const": false}, "commitOutcome": outcome, "commandID": text(1, 128), "error": map[string]any{"type": "string", "enum": []string{"unavailable", "invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_or_csrf_denied", "denied", "rate_limited", "conflict", "in_progress"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store original outcome. No session or provisioning URI is issued.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	parameters := []any{}
	for _, p := range []struct {
		name   string
		schema any
	}{{"Origin", map[string]any{"type": "string", "enum": c.TrustedOrigins}}, {"X-CSRF-Token", text(43, 43)}, {"Idempotency-Key", text(1, 256)}} {
		parameters = append(parameters, map[string]any{"name": p.name, "in": "header", "required": true, "schema": p.schema})
	}
	definition, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.enable", "description": "Explicit cookie-only pending TOTP enrollment using original primary session and committed action-specific password verification. Exact HTTPS Origin and native stored-session synchronizer required. Request key is unchanged on retry; ambiguous command observations are not rollback. Recovery material is never redelivered. Separate URI revelation and code confirmation are required before factor use. No Authorization fallback, subject selection, redirect, query or trailers.", "security": []any{map[string]any{"MFAEnrollmentSession": []string{}}}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"proofID"}, map[string]any{"proofID": text(22, 128)})}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original authenticated primary session; never an enrollment-generated session."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAEnrollmentSession", Definition: scheme}}}
}
