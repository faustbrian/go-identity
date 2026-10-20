package phonehttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewChangeFeature independently selects authenticated new-number sending,
// replacement and original code-free history. It enables no enrollment, signin,
// reset, signup, removal or administrative operation. Its send route and the
// enrollment send route are mutually exclusive selections, never fallbacks.
func NewChangeFeature(c ChangeConfig) (identityhttp.Feature, error) {
	return NewChangeFeatureWithMiddleware(c, nil)
}

// NewChangeFeatureWithMiddleware binds hooks to the actual frozen owner phases.
// Construction validates the complete selected profile without IO or callbacks.
func NewChangeFeatureWithMiddleware(c ChangeConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	operations := make([]identityhttp.OperationDescriptor, 0, 3)
	for mode, id := range []string{"identity.phone.send-verification", "identity.phone.update", "identity.phone.update.recover"} {
		h, err := newChangeHandler(c, mode, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: id, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = changeWire(c, mode, id)
		if mode != 0 {
			op.Wire.SecuritySchemes = nil
		}
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: operations})
}

func changeWire(c ChangeConfig, mode int, operation string) *identityhttp.WireOperation {
	text := func(maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	version := map[string]any{"type": "string", "pattern": "^[1-9][0-9]{0,19}$", "not": map[string]any{"const": "18446744073709551615"}, "description": "Canonical decimal uint64 in 1..18446744073709551614; out-of-range input denies."}
	keyVersion := map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(^uint32(0))}
	recovery := object([]string{"sendCommandID", "attempt", "expectedVersion", "digestKeyVersion", "scopeDigest"}, map[string]any{
		"sendCommandID": id, "attempt": object([]string{"tenantID", "commandID", "attemptID", "fingerprint", "fingerprintKeyVersion"}, map[string]any{
			"tenantID": text(128), "commandID": id, "attemptID": id, "fingerprint": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "fingerprintKeyVersion": keyVersion,
		}), "expectedVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}, "digestKeyVersion": keyVersion,
		"scopeDigest": map[string]any{"type": "array", "minItems": 32, "maxItems": 32, "items": map[string]any{"type": "integer", "minimum": 0, "maximum": 255}, "not": map[string]any{"const": [32]byte{}}},
	})
	fields := map[string]any{"flowID": map[string]any{"type": "string", "pattern": "^[!-~]{1,128}$"}}
	required := []string{"flowID"}
	parameters := []any{
		map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)},
		map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "writeOnly": true}},
	}
	if mode != 2 {
		fields["proofID"] = id
		required = append(required, "proofID")
		parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}})
	}
	switch mode {
	case 0:
		fields["number"], fields["previousNumber"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 64, "writeOnly": true}, map[string]any{"type": "string", "minLength": 1, "maxLength": 64, "writeOnly": true}
		fields["identifierID"], fields["expectedIdentifierVersion"], fields["expectedVerificationVersion"] = id, version, version
		required = append(required, "number", "previousNumber", "identifierID", "expectedIdentifierVersion", "expectedVerificationVersion")
	case 1:
		fields["sendCommandID"], fields["code"] = id, map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": true}
		fields["reason"] = map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_.-]{0,63}$", "description": "Original registered replacement reason, never arbitrary audit text."}
		required = append(required, "sendCommandID", "code", "reason")
	case 2:
		fields["recovery"] = recovery
		required = append(required, "recovery")
	}
	base := map[string]any{"accepted": map[string]any{"const": mode == 0}, "updated": map[string]any{"const": false}, "replayed": map[string]any{"type": "boolean"}, "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"committed", "not_committed"}}}
	successRequired := []string{"accepted", "updated", "replayed", "commandID", "commitOutcome"}
	if mode == 0 {
		base["replayed"], base["commitOutcome"] = map[string]any{"const": false}, map[string]any{"const": "committed"}
	} else {
		base["recovery"] = recovery
		base["cascadeID"], base["cascadeGeneration"], base["cascadeStatus"] = id, map[string]any{"type": "integer", "minimum": 1}, map[string]any{"const": "pending"}
		base["replayed"] = map[string]any{"const": true}
		successRequired = append(successRequired, "recovery")
	}
	var success any = object(successRequired, base)
	if mode == 1 {
		fresh := make(map[string]any, len(base))
		for k, v := range base {
			fresh[k] = v
		}
		fresh["updated"], fresh["replayed"], fresh["commitOutcome"] = map[string]any{"const": true}, map[string]any{"const": false}, map[string]any{"const": "committed"}
		success = map[string]any{"oneOf": []any{success, object(append(append([]string{}, successRequired...), "cascadeID", "cascadeGeneration", "cascadeStatus"), fresh)}}
	}
	failureFields := map[string]any{"accepted": map[string]any{"const": false}, "updated": map[string]any{"const": false}, "replayed": map[string]any{"type": "boolean"}, "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "error": text(64)}
	if mode != 0 {
		failureFields["recovery"], failureFields["cascadeID"], failureFields["cascadeGeneration"], failureFields["cascadeStatus"] = recovery, id, map[string]any{"type": "integer", "minimum": 1}, map[string]any{"const": "pending"}
	}
	failed := object([]string{"accepted", "updated", "replayed", "commitOutcome", "error"}, failureFields)
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free original status; no-store/nosniff. Pending cascade is not completed cleanup; unknown is not rollback. No session or credential response headers.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	status := "200"
	if mode == 0 {
		status = "202"
	}
	responses := map[string]any{status: response(success)}
	for _, code := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[code] = response(map[string]any{"oneOf": []any{failed, object([]string{"error"}, map[string]any{"error": text(64)})}})
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	security := map[string]any{"IdentityPhoneChangeSession": []any{}}
	if mode == 0 {
		security["IdentityPhoneChangeDevice"] = []any{}
	}
	definition, _ := json.Marshal(map[string]any{"operationId": operation, "description": "Explicit cookie-only verified-phone replacement. Exact tenant HTTPS/Origin and original stored-session synchronizer are mandatory. Sending additionally requires a signed browser device and sending proof; completion requires a distinct update proof and original new-number code. Send/update retry keys occur only in the header. Recovery forbids keys/codes/fresh proofs, returns only current-authorized original metadata and never renews validity. No signup, enrollment, reset, signin or factor fallback.", "security": []any{security}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object(required, fields)}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	sessionScheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	deviceScheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device"})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "IdentityPhoneChangeSession", Definition: sessionScheme}, {Name: "IdentityPhoneChangeDevice", Definition: deviceScheme}}}
}
