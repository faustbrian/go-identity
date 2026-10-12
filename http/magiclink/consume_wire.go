package magiclinkhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func consumeWire(c ConsumeConfig) *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, fields map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "denied", "unavailable", "conflict", "in_progress", "replay", "superseded"}}
	success := object([]string{"signedIn", "commitOutcome", "commandID", "sessionID"}, map[string]any{"signedIn": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "sessionID": text(128)})
	failed := object([]string{"signedIn", "commitOutcome", "error"}, map[string]any{"signedIn": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": codes})
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), failed}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store original outcome. Only fresh exact commitment delivers the native cookie/synchronizer; JSON contains neither secret nor subject.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Native reveal-once bearer under selected secure cookie policy; never on replay.", "schema": text(4096)}, "X-CSRF-Token": map[string]any{"description": "Original session/version-bound synchronizer, delivered only with the fresh bearer.", "schema": text(256)}}
	if c.MFAContinuation {
		challenge := object([]string{"signedIn", "commitOutcome", "commandID", "challengeRequired", "challengeID", "challengeMethod", "challengeExpiresAt"}, map[string]any{"signedIn": map[string]any{"const": false}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "challengeRequired": map[string]any{"const": true}, "challengeID": id, "challengeMethod": map[string]any{"const": "totp"}, "challengeExpiresAt": map[string]any{"type": "string", "format": "date-time"}})
		responses["200"] = response(map[string]any{"oneOf": []any{success, challenge}})
		responses["200"].(map[string]any)["description"] = "A fresh exact commit delivers either a session cookie/synchronizer OR a challenge-only X-MFA-Token. Challenge metadata is not authentication; JSON contains no credential or subject."
		responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"schema": text(4096)}, "X-CSRF-Token": map[string]any{"schema": text(256)}, "X-MFA-Token": map[string]any{"description": "Reveal-once original MFA continuation proof. No session cookie/synchronizer accompanies it; never exposed on retry, recovery, error or expired response commitment.", "schema": text(4096)}}
	}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled before consuming native work during shared origin admission.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded whole seconds when available; not permission to replace an uncertain command.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	body := object([]string{"commandID", "preAuthID", "token", "callbackURL"}, map[string]any{"commandID": id, "preAuthID": id, "token": map[string]any{"type": "string", "minLength": 32, "maxLength": 4096, "writeOnly": true}, "callbackURL": map[string]any{"const": c.CallbackURL}})
	definition := map[string]any{"operationId": "identity.magic-link.consume", "description": "Explicit POST consumption, never scanner GET. Original command, grant and browser flow/cookie plus exact mapped HTTPS tenant/Origin/callback are mandatory. No Idempotency-Key, Authorization, query, redirects or automatic retry/recovery. Trusted IP precedes purpose-bound native original-source lookup; subject/challenge budgets retain original signed lifetime. Native current recipient/factor/risk and atomic one-use/session authority remain decisive. Unknown/replay/error/cancellation withhold credentials; known commit remains visible without implying successful delivery.", "security": []any{map[string]any{"MagicLinkOriginalFlow": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"const": string(c.Origin)}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses}
	definition["security"] = []any{map[string]any{"MagicLinkOriginalFlow": []string{}, "MagicLinkBrowserDevice": []string{}}}
	data, _ := json.Marshal(definition)
	flow, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_flow", "description": "Original server-issued browser flow; possession is authenticated by the native workflow, not by transport metadata."})
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Signed original browser correlation under selected tenant/origin policy; not a session or MFA factor."})
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "MagicLinkOriginalFlow", Definition: flow}, {Name: "MagicLinkBrowserDevice", Definition: device}}}
}
