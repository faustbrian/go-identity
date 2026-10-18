package passwordhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func usernameRenameOperation(c UsernameRenameConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewUsernameRenameHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/username", OperationID: "identity.username.update", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	text := func(min, max int) any { return map[string]any{"type": "string", "minLength": min, "maxLength": max} }
	object := func(required []string, p map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 1}
	recovery := object([]string{"commandID", "tenantID", "userID", "actorID", "actorKind", "operationID", "recordID"}, map[string]any{"commandID": text(22, 22), "tenantID": text(1, 256), "userID": text(1, 256), "actorID": text(1, 256), "actorKind": map[string]any{"const": "user"}, "operationID": map[string]any{"const": "identity.username.update"}, "recordID": text(1, 256)})
	success := object([]string{"changed", "commandID", "commitOutcome", "identifierVersion", "recovery"}, map[string]any{"changed": map[string]any{"const": true}, "commandID": text(22, 22), "commitOutcome": map[string]any{"const": "committed"}, "identifierVersion": map[string]any{"type": "integer", "minimum": 2, "maximum": ^uint64(0)}, "recovery": recovery})
	failure := object([]string{"changed", "commitOutcome", "error"}, map[string]any{"changed": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": text(22, 22), "recovery": recovery, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "https_required", "origin_or_csrf_denied", "origin_denied", "denied", "rate_limited", "unavailable", "conflict", "in_progress"}}})
	failure["dependentRequired"] = map[string]any{"commandID": []string{"recovery"}, "recovery": []string{"commandID"}}
	response := func(s any) any {
		return map[string]any{"description": "No-store credential-free original command metadata; never automatic retry permission or renewed authentication.", "content": map[string]any{"application/json": map[string]any{"schema": s}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during exact-origin admission; no mutation.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	definition, err := json.Marshal(map[string]any{"operationId": "identity.username.update", "description": "Explicit cookie/password-proof self rename. Original native signed proof and keyed request possession precede shared rate admission, without a current-session read that would break exact terminal retries. Native work rechecks current factor/policy/CSRF, consumes proof and commits name/cooldown/identifier-session invalidation atomically. Closed bounded input; tenant, user, proof, normalization and session disposition cannot be chosen by the caller. Original metadata only on replay; no proof renewal or reenrollment.", "security": []any{map[string]any{"UsernameRenameCookie": []string{}}}, "parameters": []any{map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}}, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(1, 2048)}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"proofID", "identifierID", "expectedIdentifierVersion", "expectedVerificationVersion", "username"}, map[string]any{"proofID": text(22, 128), "identifierID": text(1, 256), "expectedIdentifierVersion": version, "expectedVerificationVersion": version, "username": text(1, 128)})}}}, "responses": responses})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, err := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original native session cookie; Authorization forbidden. Exact trusted Origin and original issued synchronizer are mandatory, including historical retry."})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "UsernameRenameCookie", Definition: scheme}}}
	return op, nil
}
