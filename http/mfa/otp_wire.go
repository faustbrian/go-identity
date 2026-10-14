package mfahttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// OTP shares the guarded session response and original browser credentials,
// but selects a distinct native method and original-send factor provenance.
func otpWire(c OTPVerifyConfig) *identityhttp.WireOperation {
	wire := totpWire(TOTPVerifyConfig{CallbackURL: c.CallbackURL, Origin: c.Origin})
	var definition map[string]any
	_ = json.Unmarshal(wire.Definition, &definition)
	definition["operationId"] = "identity.mfa.otp-verify"
	definition["description"] = "Password-origin secondary OTP login completion. Exact original continuation, flow/device cookies, HTTPS, Origin and callback are required. Native original committed send selects the enrolled factor and recipient; no caller factor, challenge generation, user or remember-policy override. IP admission precedes authenticated original-source and subject/child admission. Protected OTP, capability, shared attempts and session effects remain atomic. Only a fresh reconciled committed password/OTP session delivers credentials; replay, cancellation and ambiguous outcomes never do. Enrollment and active step-up are not selected by this profile."
	body := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties := body["properties"].(map[string]any)
	properties["continuationID"] = properties["challengeID"]
	delete(properties, "challengeID")
	delete(properties, "factorID")
	properties["code"].(map[string]any)["description"] = "Opaque bounded code; native purpose-bound secondary OTP owns comparison and shared attempts."
	body["required"] = []string{"commandID", "preAuthID", "continuationID", "token", "code", "callbackURL", "trustDevice"}
	wire.Definition, _ = json.Marshal(definition)
	return wire
}
