package emailhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func removalWire(c RemovalConfig) *identityhttp.WireOperation {
	text := func(min, max int) map[string]any {
		return map[string]any{"type": "string", "minLength": min, "maxLength": max}
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "required": required, "additionalProperties": false, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	version := map[string]any{"type": "string", "minLength": 1, "maxLength": 20, "pattern": "^[1-9][0-9]{0,19}$", "description": "Canonical uint64 decimal, excluding overflow and max uint64; no JSON floating-point coercion."}
	input := object([]string{"proofID", "addressID", "expectedIdentifierVersion", "expectedVerificationVersion", "reason", "primaryDisposition", "recoveryDisposition"}, map[string]any{"proofID": id, "addressID": text(1, 128), "expectedIdentifierVersion": version, "expectedVerificationVersion": version, "reason": map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_.-]{0,63}$"}, "primaryDisposition": map[string]any{"enum": []string{"preserve-primary", "leave-unassigned", "replace-primary"}}, "recoveryDisposition": map[string]any{"const": "preserve-verified-email"}, "replacementAddressID": text(1, 128), "expectedReplacementIdentifierVersion": version, "expectedReplacementVerificationVersion": version})
	replacement := []string{"replacementAddressID", "expectedReplacementIdentifierVersion", "expectedReplacementVerificationVersion"}
	absent := []any{}
	for _, field := range replacement {
		absent = append(absent, map[string]any{"required": []string{field}})
	}
	input["allOf"] = []any{map[string]any{"if": map[string]any{"properties": map[string]any{"primaryDisposition": map[string]any{"const": "replace-primary"}}}, "then": map[string]any{"required": replacement}, "else": map[string]any{"not": map[string]any{"anyOf": absent}}}}
	if c.AdministrativeTargets {
		input["properties"].(map[string]any)["targetSubjectID"] = text(1, 128)
	}
	success := object([]string{"removed", "commandID", "commitOutcome", "cascadeID", "cascadeGeneration", "cascadeStatus"}, map[string]any{"removed": map[string]any{"const": true}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}, "cascadeID": id, "cascadeGeneration": map[string]any{"const": 1}, "cascadeStatus": map[string]any{"const": "pending"}})
	failed := object([]string{"removed", "commitOutcome", "error"}, map[string]any{"removed": map[string]any{"const": false}, "commandID": id, "commitOutcome": map[string]any{"enum": []string{"none", "not_committed", "committed", "unknown", "in_progress", "conflict"}}, "error": map[string]any{"enum": []string{"invalid_request", "denied", "conflict", "in_progress", "not_found", "method_not_allowed", "misdirected_request", "https_required", "origin_or_csrf_denied", "rate_limited", "unavailable"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store original removal outcome; pending cascade is not asynchronous cleanup completion. No response credentials or redirects.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failed)
	}
	parameter := func(name string, schema any) any {
		return map[string]any{"name": name, "in": "header", "required": true, "schema": schema}
	}
	key := text(1, 256)
	key["writeOnly"] = true
	key["pattern"] = "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"
	csrf := text(43, 43)
	csrf["writeOnly"] = true
	csrf["pattern"] = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
	description := "Selected cookie-only fresh-password self-removal with known-empty MFA."
	if c.AdministrativeTargets {
		description = "Selected cookie-only self or explicitly authorized administrative removal with independent actor password proof and known-empty actor/target MFA. Optional targetSubjectID selects the target, never the authenticated actor or permission."
	}
	description += " Original proof/cookie/CSRF and keyed request custody precede shared secret admission; current authority and actual remaining target signin/reset eligibility are rechecked atomically. Removes only the exact versioned address, retires unused target grants, invalidates prior target identifier-bound sessions and durably admits the complete pending lifecycle manifest. No implicit primary selection, actor/tenant override, weaker-factor fallback, authentication issuance or recovery endpoint. Retry exact original input; unknown is not rollback."
	definition, _ := json.Marshal(map[string]any{"operationId": "identity.email.address-remove", "description": description, "security": []any{map[string]any{"EmailRemovalSession": []string{}}}, "parameters": []any{parameter("Origin", text(1, 2048)), parameter("X-CSRF-Token", csrf), parameter("Idempotency-Key", key)}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": input}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original native cookie possession; unfinished work additionally requires current protected transaction authority. Never refreshed or issued here."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "EmailRemovalSession", Definition: scheme}}}
}
