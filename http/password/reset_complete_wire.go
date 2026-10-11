package passwordhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func resetCompleteOperation(c ResetCompleteConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewResetCompleteHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.reset-complete", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = resetCompleteWire(c)
	return op, nil
}
func resetCompleteWire(c ResetCompleteConfig) *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, p map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	recovery := object([]string{"tenantID", "userID", "credentialID", "actorID", "actorKind"}, map[string]any{"tenantID": text(256), "userID": text(128), "credentialID": text(256), "actorID": text(256), "actorKind": map[string]any{"const": "service-account"}})
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "rate_limiter_unavailable", "denied", "unavailable", "conflict", "in_progress"}}
	success := object([]string{"completed", "commitOutcome", "commandID", "credentialVersion", "sessionsRevoked", "recovery"}, map[string]any{"completed": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "credentialVersion": map[string]any{"type": "integer", "minimum": 2}, "sessionsRevoked": map[string]any{"const": true}, "recovery": recovery})
	attempt := object([]string{"completed", "commitOutcome", "sessionsRevoked", "error"}, map[string]any{"completed": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "sessionsRevoked": map[string]any{"const": false}, "recovery": recovery, "error": codes})
	attempt["dependentRequired"] = map[string]any{"commandID": []string{"recovery"}, "recovery": []string{"commandID"}}
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), attempt}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store original completion/recovery metadata. No token, password, session or automatic signin.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no mutation.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}, "description": "Bounded whole seconds, not authority to replace an uncertain original command."}}
	}
	body := object([]string{"commandID", "token", "newPassword"}, map[string]any{"commandID": id, "token": map[string]any{"type": "string", "minLength": 32, "maxLength": 4096, "writeOnly": true}, "newPassword": map[string]any{"type": "string", "minLength": 1, "maxLength": min(c.Network.Limits.MaximumDecodedBytes, uint64(1<<20)), "writeOnly": true}})
	definition := map[string]any{"operationId": "identity.password.reset-complete", "description": "Explicit-confirmation reset with exact mapped HTTPS tenant/Origin and signed device correlation. One original purpose-bound proof, one replacement password and original commandID in closed JSON; no Idempotency-Key, Authorization, query token or identity override. IP admission precedes durable original-proof lookup, then shared original subject/challenge admission. Native authority, HIBP/policy, atomic use, credential replacement and all-session revocation remain required. Metadata supports proof/password-free recovery; never retry automatically or issue a session.", "security": []any{map[string]any{"PasswordResetBrowserDevice": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Original signed browser correlation, not account or execution authority."})
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "PasswordResetBrowserDevice", Definition: device}}}
}
