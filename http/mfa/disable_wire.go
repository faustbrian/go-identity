package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func disableWire(c DisableConfig) *identityhttp.WireOperation {
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	body := object([]string{"target", "proofID"}, map[string]any{"target": map[string]any{"type": "string", "enum": []string{"one", "all"}}, "factorID": id, "proofID": id})
	body["oneOf"] = []any{map[string]any{"properties": map[string]any{"target": map[string]any{"const": "one"}}, "required": []string{"factorID"}}, map[string]any{"properties": map[string]any{"target": map[string]any{"const": "all"}}, "not": map[string]any{"required": []string{"factorID"}}}}
	factor := object([]string{"id", "method", "state", "createdAt", "version"}, map[string]any{"id": id, "method": map[string]any{"const": "totp"}, "label": map[string]any{"type": "string", "maxLength": 128}, "state": map[string]any{"const": 1}, "createdAt": map[string]any{"type": "string", "format": "date-time"}, "version": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}})
	success := object([]string{"commitOutcome", "commandID", "factors"}, map[string]any{"commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "factors": map[string]any{"type": "array", "maxItems": 100, "items": factor, "description": "Remaining unexpired pending factors from the protected successor. One-target leaves siblings intact; all-target returns an empty set."}})
	failure := object([]string{"commitOutcome", "error"}, map[string]any{"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_or_csrf_denied", "denied", "rate_limited", "unavailable", "conflict", "in_progress"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store safe disposition; no factor secrets or new session. A known commitment is retained even when metadata is withheld.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	d, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.disable", "description": "Explicit cookie-only disable-purpose TOTP proof and recent primary custody. Native sole-TOTP/email-reset recovery profile only; additional unsupported factor authority denies. One/all remain distinct immutable keyed scopes. Command identity is owner-derived; no body/query/credential overrides. Factor/code erasure, subject-session revocation and audit are atomic. Historical recovery discloses no fresh factor projections.", "security": []any{map[string]any{"MFADisableSession": []string{}}}, "parameters": []any{map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}}, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "enum": c.TrustedOrigins}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	return &identityhttp.WireOperation{Definition: d, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFADisableSession", Definition: scheme}}}
}
