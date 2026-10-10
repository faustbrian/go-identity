package passwordhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// Explicit wire projections, not reflected domain/proof/configuration types.
func changeWire(c ChangeConfig) *identityhttp.WireOperation {
	text := func(minimum, maximum int) any {
		return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
	}
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	command := map[string]any{"type": "string", "pattern": "^[!-~]{1,128}$"}
	recovery := object([]string{"commandID", "tenantID", "userID", "actorID", "actorKind", "operationID", "recordID"}, map[string]any{"commandID": command, "tenantID": text(1, 256), "userID": text(1, 256), "actorID": text(1, 256), "actorKind": map[string]any{"const": "user"}, "operationID": map[string]any{"const": "identity.password.change"}, "recordID": text(1, 256)})
	success := object([]string{"changed", "commandID", "commitOutcome", "credentialVersion", "authorityInvalidated", "recovery"}, map[string]any{"changed": map[string]any{"const": true}, "commandID": command, "commitOutcome": map[string]any{"const": "committed"}, "credentialVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}, "authorityInvalidated": map[string]any{"const": true}, "recovery": recovery})
	errorCode := map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_or_csrf_denied", "origin_denied", "https_required", "denied", "rate_limited", "unavailable", "conflict", "in_progress"}}
	attempt := object([]string{"changed", "commitOutcome", "error"}, map[string]any{"changed": map[string]any{"const": false}, "commandID": command, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "recovery": recovery, "error": errorCode})
	attempt["dependentRequired"] = map[string]any{"commandID": []string{"recovery"}, "recovery": []string{"commandID"}}
	attempt["allOf"] = []any{map[string]any{"if": map[string]any{"properties": map[string]any{"commitOutcome": map[string]any{"enum": []string{"not_committed", "committed", "unknown", "in_progress"}}}}, "then": map[string]any{"required": []string{"commandID", "recovery"}}}}
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": errorCode}), attempt}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free original command observation; no-store/nosniff. Recovery is scoped metadata, not authorization or an automatic retry. No cookies, bearer, CSRF or trailers.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	retry := map[string]any{"description": "Bounded whole seconds when known. Preserve original key and input; ambiguous outcomes never authorize a replacement command.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": retry}
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native password change.", "content": map[string]any{"text/plain": plain}}
	parameters := []any{map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "description": "Exactly one header supplies the sole original byte-preserved key; no body/query/form/cookie/trailer or hook alternative.", "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}}}
	schemeName := "PasswordChangeBearer"
	scheme := map[string]any{"type": "http", "scheme": "bearer", "description": "Exactly one strict Authorization: Bearer session credential. Ambient cookies ignored; no credential or CSRF fallback."}
	if c.Transport == session.CredentialCookie {
		cookie, _ := c.Cookie.DeletionAttributes()
		schemeName = "PasswordChangeCookie"
		scheme = map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Exactly the selected secure host cookie; Authorization forbidden. Current primary synchronizer state and exact trusted Origin are required."}
		parameters = append(parameters, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(1, 2048), "description": "Exact trusted HTTPS origin; Referer fallback denied. Deployment origin values are not exported."}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"}, "description": "Canonical 32-byte current session synchronizer; verified under native primary fences with protected effects. No independent token-age promise."})
	}
	definition := map[string]any{"operationId": "identity.password.change", "description": "Selected authenticated password-change profile only. Exactly proofID and newPassword in closed bounded JSON; no user/tenant, password-current/revoke policy, return target, command identity or retry-key body fields. The proof ID names the original completed credential-specific verification for this action; native workflow validates its signature/current primary and consumes it with password/session effects. Trusted startup policy selects session disposition. Preliminary authority never renews through hooks/rate/proof IO. All applicable rate.secret buckets use the original key atomically. Only error-free known commit sets changed=true; committed errors and unknown remain historical observations, never automatic retry or credential delivery. Raw/decoded byte budgets and owning password policy remain additionally enforced; passwords are not normalized.", "security": []any{map[string]any{schemeName: []string{}}}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"proofID", "newPassword"}, map[string]any{"proofID": map[string]any{"type": "string", "pattern": "^[!-~]{22,128}$"}, "newPassword": map[string]any{"type": "string", "minLength": 1, "maxLength": min(c.Network.Limits.MaximumDecodedBytes, uint64(1<<20)), "writeOnly": true}})}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	security, _ := json.Marshal(scheme)
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: schemeName, Definition: security}}}
}
