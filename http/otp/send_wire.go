package otphttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func emailSigninSendWire() *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	errorCode := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable", "conflict", "in_progress"}}
	success := object([]string{"accepted", "commandID", "commitOutcome"}, map[string]any{"accepted": map[string]any{"const": true}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}})
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": errorCode}), object([]string{"accepted", "commitOutcome", "error"}, map[string]any{"accepted": map[string]any{"const": false}, "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "error": errorCode})}}
	response := func(schema any) any {
		return map[string]any{"description": "Enumeration-safe original command status, no-store/nosniff. Acceptance is not recipient existence, challenge state or delivery. No cookies, credentials or response trailers.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"202": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded whole seconds when available; preserve original key and input for native replay resolution, never replace ambiguous commands.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native Send.", "content": map[string]any{"text/plain": plain}}
	definition := map[string]any{"operationId": "identity.otp.send", "description": "Selected email/signin profile only. Exact HTTPS mapped tenant and initiating Origin, original flowID/cookie and existing scoped browser-device cookie are mandatory; no fallback issuance. Email-owned bounded normalization precedes shared delivery admission and one native Send. Trusted actor/policy/target, IP and device are never body choices; purpose/channel are fixed. Header-only exact idempotency; no query, trailers, Authorization or automatic retry. Native service owns primary custody, counted risk and durable issuance or indistinguishable suppression.", "security": []any{map[string]any{"IdentityOTPOriginalFlow": []any{}, "IdentityOTPBrowserDevice": []any{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"flowID", "email"}, map[string]any{"flowID": id, "email": map[string]any{"type": "string", "minLength": 3, "maxLength": 4096, "writeOnly": true, "description": "Bounded UTF-8 exact mailbox under configured owning email policy; raw and canonical byte bounds are enforced at runtime."}})}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Original scoped non-authenticating browser correlation; never session authority or MFA trust. Missing/invalid/expired custody denies, never mints a replacement."})
	flow := signinWire().SecuritySchemes[0]
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{flow, {Name: "IdentityOTPBrowserDevice", Definition: device}}}
}
