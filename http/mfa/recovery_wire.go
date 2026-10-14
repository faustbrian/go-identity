package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// The closed recovery profile shares response and browser custody with TOTP,
// but not its input, factor selection or native authentication owner.
func recoveryWire(c RecoveryUseConfig) *identityhttp.WireOperation {
	wire := totpWire(TOTPVerifyConfig{CallbackURL: c.CallbackURL, Origin: c.Origin})
	var definition map[string]any
	_ = json.Unmarshal(wire.Definition, &definition)
	definition["operationId"] = "identity.mfa.recovery-use"
	definition["description"] = "Original-primary recovery-code completion. Requires exact original continuation, flow/device cookies, Origin and callback. Native shared attempts, current authority, protected risk, code burn and session issuance remain atomic. No caller user/factor/set/remember override or TOTP fallback. Credentials are delivered only on a fresh committed result."
	body := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties := body["properties"].(map[string]any)
	properties["continuationID"] = properties["challengeID"]
	delete(properties, "challengeID")
	delete(properties, "factorID")
	delete(properties, "trustDevice")
	delete(properties, "code")
	properties["recoveryCode"] = map[string]any{"type": "string", "minLength": 8, "maxLength": 256, "writeOnly": true, "description": "Distinct bounded opaque recovery credential; never an OTP."}
	body["required"] = []string{"commandID", "preAuthID", "continuationID", "token", "recoveryCode", "callbackURL"}
	success := definition["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	success["required"] = append(success["required"].([]any), "recoveryRequired")
	success["properties"].(map[string]any)["recoveryRequired"] = map[string]any{"type": "boolean", "description": "Committed policy remediation, not proof of future factor authority."}
	wire.Definition, _ = json.Marshal(definition)
	return wire
}
