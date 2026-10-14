package otphttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// Recovery shares original-flow custody and common transport denials, not the
// consuming operation's success or credential delivery. Derive detached wire
// data so neither contribution can mutate the other's immutable schema.
func signinRecoveryWire() *identityhttp.WireOperation {
	wire := signinWire()
	var definition map[string]any
	json.Unmarshal(wire.Definition, &definition)
	responses := definition["responses"].(map[string]any)
	oldSuccess := responses["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties := oldSuccess["properties"].(map[string]any)
	recovery := properties["recovery"].(map[string]any)
	rp := recovery["properties"].(map[string]any)
	rp["expectedVersion"].(map[string]any)["maximum"] = uint64(^uint64(0))
	attempt := rp["attempt"].(map[string]any)["properties"].(map[string]any)
	attempt["tenantID"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "Exact original tenant, at most 128 UTF-8 bytes; native scope agreement remains mandatory."}
	attempt["attemptID"] = map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	attempt["fingerprint"] = map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	rp["scopeDigest"].(map[string]any)["not"] = map[string]any{"const": [32]byte{}}
	id := properties["commandID"]
	history := func(committed bool) any {
		required := []string{"signedIn", "commandID", "commitOutcome", "recovery"}
		fields := map[string]any{"signedIn": map[string]any{"const": false}, "commandID": id, "recovery": recovery, "commitOutcome": map[string]any{"const": "not_committed"}}
		if committed {
			required = append(required, "sessionID")
			fields["sessionID"] = map[string]any{"type": "string", "pattern": "^[!-~]{1,128}$"}
			fields["commitOutcome"] = map[string]any{"const": "committed"}
		}
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	responses["200"] = map[string]any{"description": "Authorized original history only; signedIn is false. Historical session identity does not establish current login. Never cookie/CSRF delivery or execution retry.", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"oneOf": []any{history(true), history(false)}}}}}
	definition["operationId"] = "identity.otp.signin.recover"
	definition["description"] = "Code-free historical recovery with the exact original flow cookie, initiating Origin and retained consuming correlation. Fixed POST keeps custody out of URLs; no query, trailers, Authorization, Idempotency-Key, code or replacement identity/remember policy. Shared signin IP admission precedes one native historical read. Original flow need not remain executable; native current disclosure policy still applies. No code comparison, challenge debit, consumption retry, custody renewal or credential delivery. Unknown remains unknown."
	definition["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"flowID", "recovery"}, "properties": map[string]any{"flowID": id, "recovery": recovery}}}}}
	data, _ := json.Marshal(definition)
	wire.Definition = data
	return wire
}
