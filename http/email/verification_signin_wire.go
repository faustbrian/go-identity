package emailhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// The selected wire is a registration-confirmation profile, not another route
// or an implicit change to default/managed confirmation schemas.
func verificationSigninWire(mfa bool) *identityhttp.WireOperation {
	base := confirmationWireFor("identity.email.verification-confirm", "Explicit original-browser registration verification followed by separately committed email-possession signin.")
	var definition map[string]any
	if json.Unmarshal(base.Definition, &definition) != nil {
		return nil
	}
	text := map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	child := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"signedIn", "commandID", "commitOutcome", "replayed", "recovery"}, "properties": map[string]any{
		"signedIn": map[string]any{"type": "boolean"}, "commandID": text, "sessionID": text, "replayed": map[string]any{"type": "boolean"},
		"commitOutcome": map[string]any{"type": "string", "enum": []string{"committed", "not_committed", "unknown", "conflict", "in_progress"}},
		"recovery":      map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenantID", "userID", "recordID", "actorID", "actorKind"}, "properties": map[string]any{"tenantID": text, "userID": text, "recordID": text, "actorID": text, "actorKind": map[string]any{"const": "service-account"}}},
	}}
	if mfa {
		p := child["properties"].(map[string]any)
		p["challengeRequired"] = map[string]any{"type": "boolean"}
		p["challengeID"] = text
		p["challengeMethod"] = map[string]any{"const": "totp"}
		p["challengeExpiresAt"] = map[string]any{"type": "string", "format": "date-time"}
	}
	responses := definition["responses"].(map[string]any)
	for status, value := range responses {
		response := value.(map[string]any)
		content := response["content"].(map[string]any)
		application, ok := content["application/json"].(map[string]any)
		if !ok {
			continue
		}
		for _, variant := range application["schema"].(map[string]any)["oneOf"].([]any) {
			variant.(map[string]any)["properties"].(map[string]any)["signin"] = child
		}
		response["description"] = "No-store verification outcome and optional independent signin outcome. Committed verification survives later failed/unknown signin. Only fresh error-free committed signin delivers a cookie and X-CSRF-Token; replay/recovery never does."
		if status == "200" {
			response["headers"] = map[string]any{"Set-Cookie": map[string]any{"schema": map[string]any{"type": "string"}, "description": "Fresh secure HttpOnly session cookie, preserving original signup remember policy; absent on replay."}, "X-CSRF-Token": map[string]any{"schema": map[string]any{"type": "string"}, "description": "Fresh session synchronizer; absent on replay."}}
			if mfa {
				response["headers"].(map[string]any)["X-MFA-Token"] = map[string]any{"schema": map[string]any{"type": "string", "maxLength": 4096}, "description": "Reveal-once original TOTP continuation only for fresh pending commitment; never with session cookie/CSRF or on replay/recovery."}
			}
		}
	}
	definition["description"] = "Explicit original-browser registration confirmation then independently committed email-possession signin. Requires the original signup flow cookie, signed browser-device cookie, exact HTTPS mapped tenant/Origin and delivered original grant. Closed body has token, callback and stable confirmation commandID only; no identity or remember override. Original remember choice is recovered from signup custody. Current account, risk, authorization and known-empty MFA must admit signin; enrolled/unknown MFA denies without fallback. Verification and signin have separate outcomes. Scanner inspection/default or managed-address confirmation cannot issue sessions; retry/recovery never regenerate credentials."
	if mfa {
		definition["description"] = "Explicit registration confirmation and separately committed email-possession signin using the original signup browser and signed device. Current known-empty MFA may issue a session; a genuinely enrolled TOTP factor instead yields only pending challenge metadata and reveal-once X-MFA-Token. Actual factor completion is independently selected. Preserve original remember, parent deadlines and separately committed verification. Unknown outcomes, errors, replay and recovery never redeliver credentials; no identity/remember override or primary fallback."
	}
	definition["parameters"] = append(definition["parameters"].([]any), map[string]any{"name": "Cookie", "in": "header", "required": true, "schema": map[string]any{"type": "string"}, "description": "Original signup flow and signed browser-device cookies; no session authentication fallback."})
	wire, err := json.Marshal(definition)
	if err != nil {
		return nil
	}
	return &identityhttp.WireOperation{Definition: wire}
}
