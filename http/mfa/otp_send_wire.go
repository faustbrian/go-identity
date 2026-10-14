package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func otpSendWire(c OTPSendConfig) *identityhttp.WireOperation {
	wire := totpWire(TOTPVerifyConfig{CallbackURL: c.CallbackURL, Origin: c.Origin})
	var d map[string]any
	_ = json.Unmarshal(wire.Definition, &d)
	d["operationId"] = "identity.mfa.otp-send"
	d["description"] = "Keyed password-origin secondary OTP login sending. Requires original child/flow/device, exact HTTPS Origin and callback, enrolled factor/channel and one unchanged Idempotency-Key. Native custody resolves canonical destination internally; no caller command, recipient, generation, subject or remember override. IP admission precedes read-only native destination authentication and shared destination quota. Native protected sending remains decisive. Queued metadata is historical, never provider delivery, factor verification or session issuance. Enrollment is not selected by this profile."
	body := d["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	props := body["properties"].(map[string]any)
	props["continuationID"] = props["challengeID"]
	delete(props, "challengeID")
	delete(props, "commandID")
	delete(props, "code")
	delete(props, "trustDevice")
	props["channel"] = map[string]any{"type": "string", "enum": []string{"email", "sms"}}
	body["required"] = []string{"preAuthID", "continuationID", "factorID", "channel", "token", "callbackURL"}
	d["parameters"] = append(d["parameters"].([]any), map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}, "description": "Exactly one original initiating key, mapped unchanged; no body/query/cookie/trailer alternative."})
	id := props["factorID"]
	commit := map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}
	errorCodes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "denied", "unavailable", "conflict", "in_progress"}}
	response := func(success bool) any {
		p := map[string]any{"accepted": map[string]any{"const": success}, "commandID": id, "commitOutcome": commit}
		required := []string{"accepted", "commitOutcome"}
		if success {
			p["commitOutcome"] = map[string]any{"const": "committed"}
			p["challengeID"] = id
			p["deliveryState"] = map[string]any{"const": "queued"}
			required = append(required, "commandID", "challengeID", "deliveryState")
		} else {
			p["error"] = errorCodes
			required = append(required, "error")
		}
		return map[string]any{"description": "No-store original queue/outcome metadata, never code, recipient, credential or actual provider delivery.", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}}}}
	}
	responses := map[string]any{"202": response(true)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(false)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	d["responses"] = responses
	wire.Definition, _ = json.Marshal(d)
	return wire
}
