package passwordhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func resetRequestOperation(c ResetRequestConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, e := NewResetRequestHandlerWithMiddleware(c, m)
	if e != nil {
		return identityhttp.OperationDescriptor{}, e
	}
	op, e := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.reset-request", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if e != nil {
		return identityhttp.OperationDescriptor{}, e
	}
	op.Wire = resetRequestWire(c)
	return op, nil
}

func resetRequestWire(c ResetRequestConfig) *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, p map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	recovery := object([]string{"attemptID", "tenantID", "actorID", "actorKind"}, map[string]any{"attemptID": id, "tenantID": text(256), "actorID": text(256), "actorKind": map[string]any{"const": "service-account"}})
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "rate_limiter_unavailable", "denied", "unavailable", "conflict", "in_progress"}}
	success := object([]string{"accepted", "commitOutcome", "commandID", "recovery"}, map[string]any{"accepted": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "recovery": recovery})
	attempt := object([]string{"accepted", "commitOutcome", "error"}, map[string]any{"accepted": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "recovery": recovery, "error": codes})
	attempt["dependentRequired"] = map[string]any{"commandID": []string{"recovery"}, "recovery": []string{"commandID"}}
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), attempt}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store enumeration-safe acknowledgement or original recovery locator; no address, token, password, session or retry key.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission, without native execution.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}, "description": "Bounded whole seconds, not permission to replace an uncertain attempt."}}
	}
	body := object([]string{"commandID", "identifier", "callbackURL"}, map[string]any{"commandID": id, "identifier": text(4096), "callbackURL": map[string]any{"const": c.CallbackURL}})
	definition := map[string]any{"operationId": "identity.password.reset-request", "description": "Opt-in original reset request. Exact mapped HTTPS tenant and Origin, signed device cookie and one Idempotency-Key header. Preserve commandID and key across explicit retries. IP admission precedes native normalization and shared destination admission. Native selection, factor authority, risk, issuance and encrypted delivery remain authoritative. Eligible and suppressed recipients receive identical acknowledgement; no automatic retry, recovery, redirect or credential delivery.", "security": []any{map[string]any{"PasswordResetBrowserDevice": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Original signed browser correlation, not account or execution authority."})
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "PasswordResetBrowserDevice", Definition: device}}}
}
