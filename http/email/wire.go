package emailhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func confirmationWire() *identityhttp.WireOperation {
	text := func(min, max int) any { return map[string]any{"type": "string", "minLength": min, "maxLength": max} }
	object := func(required []string, fields map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	version := map[string]any{"type": "integer", "minimum": 1}
	address := object([]string{"identifierID", "userID", "primary", "identifierVersion", "verificationVersion"}, map[string]any{"identifierID": text(1, 128), "userID": text(1, 128), "email": text(1, 4096), "primary": map[string]any{"type": "boolean"}, "identifierVersion": version, "verificationVersion": version})
	recovery := object([]string{"tenantID", "userID", "recordID", "actorID", "actorKind"}, map[string]any{"tenantID": text(1, 128), "userID": text(1, 128), "recordID": text(1, 128), "actorID": text(1, 128), "actorKind": map[string]any{"const": "service-account"}})
	errorCode := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable", "invalid_verification", "conflict", "in_progress"}}
	fields := map[string]any{"confirmed": map[string]any{"type": "boolean"}, "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "replayed": map[string]any{"type": "boolean"}, "address": address, "recovery": recovery, "error": errorCode}
	copyFields := func() map[string]any {
		out := map[string]any{}
		for k, v := range fields {
			out[k] = v
		}
		return out
	}
	fresh := copyFields()
	delete(fresh, "error")
	fresh["confirmed"] = map[string]any{"const": true}
	fresh["commitOutcome"] = map[string]any{"const": "committed"}
	fresh["replayed"] = map[string]any{"const": false}
	replay := copyFields()
	delete(replay, "error")
	delete(replay, "address")
	replay["confirmed"] = map[string]any{"const": true}
	replay["commitOutcome"] = map[string]any{"const": "committed"}
	replay["replayed"] = map[string]any{"const": true}
	successSchema := map[string]any{"oneOf": []any{object([]string{"confirmed", "commandID", "commitOutcome", "replayed", "recovery", "address"}, fresh), object([]string{"confirmed", "commandID", "commitOutcome", "replayed", "recovery"}, replay)}}
	failed := copyFields()
	delete(failed, "address")
	failed["confirmed"] = map[string]any{"const": false}
	responseSchema := map[string]any{"oneOf": []any{object([]string{"confirmed", "commitOutcome", "replayed", "error"}, failed), object([]string{"error"}, map[string]any{"error": errorCode})}}
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = map[string]any{"description": "No-store original confirmation outcome. Only fresh successful commit may disclose an address; replay/failure never issues credentials or implies current account eligibility.", "content": map[string]any{"application/json": map[string]any{"schema": responseSchema}}}
	}
	responses["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"] = successSchema
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded ceiling seconds when supplied. No automatic retry or replacement command.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native confirmation.", "content": map[string]any{"text/plain": plain}}
	token := text(32, 4096).(map[string]any)
	token["writeOnly"] = true
	token["description"] = "Original signed one-use email capability; body only, never a URL, cookie or reusable session."
	definition := map[string]any{"operationId": "identity.email.verification-confirm", "description": "Original-signup require-before-signin no-session profile. Exact HTTPS mapped tenant and Origin; closed body capability, original callback and stable confirmation command. Reject Authorization, Idempotency-Key, query/trailers and replacement identity. Ambient cookies grant no authority. Trusted IP budget precedes proof/source work, followed by original subject/grant budgets and one native confirmation. Unknown remains unknown; original command replay returns metadata only. Recovery correlation grants no authority and no recovery route is selected.", "security": []any{}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(1, 2048)}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"token", "callback", "commandID"}, map[string]any{"token": token, "callback": text(1, 2048), "commandID": id})}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	return &identityhttp.WireOperation{Definition: data}
}
