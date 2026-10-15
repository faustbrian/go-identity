package emailhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func requestWire(c RequestConfig, change bool) *identityhttp.WireOperation {
	text := func(min, max int) map[string]any {
		return map[string]any{"type": "string", "minLength": min, "maxLength": max}
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "required": required, "additionalProperties": false, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	action, scheme := "identity.email.verification-send", "EmailVerificationRequestSession"
	fields := map[string]any{"proofID": id, "callback": text(1, 2048), "address": text(1, 4096)}
	add := object([]string{"proofID", "callback", "address"}, fields)
	resend := object([]string{"proofID", "callback", "addressID"}, map[string]any{"proofID": id, "callback": text(1, 2048), "address": text(1, 4096), "addressID": text(1, 128)})
	var input any = map[string]any{"oneOf": []any{add, resend}}
	if change {
		action, scheme = "identity.email.change-request", "EmailChangeRequestSession"
		input = object([]string{"proofID", "newAddress", "callback"}, map[string]any{"proofID": id, "newAddress": text(1, 4096), "callback": text(1, 2048)})
	}
	success := object([]string{"queued", "commandID", "commitOutcome", "deliveryState"}, map[string]any{"queued": map[string]any{"const": true}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}, "deliveryState": map[string]any{"const": "queued"}})
	failed := object([]string{"queued", "commitOutcome", "error"}, map[string]any{"queued": map[string]any{"const": false}, "commandID": id, "commitOutcome": map[string]any{"enum": []string{"none", "not_committed", "committed", "unknown", "in_progress", "conflict"}}, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "conflict", "in_progress", "not_found", "method_not_allowed", "misdirected_request", "https_required", "origin_or_csrf_denied", "rate_limited", "unavailable"}}})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store original request metadata; queued never means sent, verified, primary-changed or authenticated.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"202": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failed)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded ceiling seconds when supplied; no automatic retry.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; native work did not begin.", "content": map[string]any{"text/plain": plain}}
	parameter := func(name string, schema any) any {
		return map[string]any{"name": name, "in": "header", "required": true, "schema": schema}
	}
	key := text(1, 256)
	key["writeOnly"] = true
	key["pattern"] = "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"
	csrf := text(43, 43)
	csrf["writeOnly"] = true
	csrf["pattern"] = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
	definition, _ := json.Marshal(map[string]any{"operationId": action, "description": "Selected cookie-authenticated self-service delivered-link request. Exactly one original action-bound password proof ID, session cookie, Origin, stored X-CSRF-Token and Idempotency-Key. Original native custody is authenticated before mutable session lookup; no renewed authority or expiry. Required canonical rate admission precedes one native transaction. No actor, tenant, command, proof-policy or session-policy overrides, bearer fallback, response credentials, redirects or auto-login. Change uses new-address possession and old-address notification only. Exact retry retains the original result; unknown is not rollback. No HTTP recovery endpoint is selected.", "security": []any{map[string]any{scheme: []string{}}}, "parameters": []any{parameter("Origin", text(1, 2048)), parameter("X-CSRF-Token", csrf), parameter("Idempotency-Key", key)}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": input}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	cookieDefinition, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original native cookie possession; fresh work additionally requires current same-transaction authority. Never issued or refreshed by this route."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: scheme, Definition: cookieDefinition}}}
}
