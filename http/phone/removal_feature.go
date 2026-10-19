package phonehttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewRemovalFeature independently selects POST /v1/phone/remove. It enables no
// enrollment, OTP, signin, reset, replacement or administrative operation.
func NewRemovalFeature(c RemovalConfig) (identityhttp.Feature, error) {
	return NewRemovalFeatureWithMiddleware(c, nil)
}

// NewRemovalFeatureWithMiddleware preserves the frozen protected phases and
// explicit wire contract. Construction performs no request IO or registration.
func NewRemovalFeatureWithMiddleware(c RemovalConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	h, err := newRemovalHandler(c, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: "identity.phone.remove", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = removalWire(c)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: []identityhttp.OperationDescriptor{op}})
}

func removalWire(c RemovalConfig) *identityhttp.WireOperation {
	text := func(max int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": max}
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	version := map[string]any{"type": "string", "pattern": "^[1-9][0-9]{0,19}$", "not": map[string]any{"const": "18446744073709551615"}, "description": "Canonical decimal uint64 in 1..18446744073709551614; out-of-range input is rejected."}
	fields := map[string]any{"number": map[string]any{"type": "string", "minLength": 1, "maxLength": 64, "writeOnly": true}, "identifierID": id, "expectedIdentifierVersion": version, "expectedVerificationVersion": version, "proofID": id, "reason": map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_.-]{0,63}$", "description": "Registered removal reason under native policy."}}
	success := object([]string{"removed", "commandID", "commitOutcome", "cascadeID", "cascadeGeneration", "cascadeStatus"}, map[string]any{"removed": map[string]any{"const": true}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}, "cascadeID": id, "cascadeGeneration": map[string]any{"type": "integer", "minimum": 1}, "cascadeStatus": map[string]any{"const": "pending"}})
	failure := object([]string{"removed", "commitOutcome", "error"}, map[string]any{"removed": map[string]any{"const": false}, "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "error": text(64)})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free original status; no-store/nosniff. Pending cascade is not completed cleanup. Unknown is not rollback.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(map[string]any{"oneOf": []any{failure, object([]string{"error"}, map[string]any{"error": text(64)})}})
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	definition, _ := json.Marshal(map[string]any{"operationId": "identity.phone.remove", "description": "Explicit authenticated phone self-removal with original action-bound password proof, cookie/CSRF and header retry key. Requires an actual independent recovery path; no OTP is consumed or session issued. Native authority, atomic old-number notice and pending lifecycle cascade remain mandatory.", "security": []any{map[string]any{"IdentityPhoneRemovalSession": []any{}}}, "parameters": []any{
		map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)},
		map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "writeOnly": true}},
		map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}},
	}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"number", "identifierID", "expectedIdentifierVersion", "expectedVerificationVersion", "proofID", "reason"}, fields)}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "IdentityPhoneRemovalSession", Definition: scheme}}}
}
