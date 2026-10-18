package phonehttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewVerificationFeature explicitly selects existing-account cookie enrollment,
// verification and original code-free recovery. Omission exposes no phone route
// or capability. Signup, signin, reset, replacement and removal are not enabled.
func NewVerificationFeature(c VerificationConfig) (identityhttp.Feature, error) {
	return NewVerificationFeatureWithMiddleware(c, nil)
}

// NewVerificationFeatureWithMiddleware preserves the real frozen owner phases.
// Construction validates all three operations without IO or partial selection.
func NewVerificationFeatureWithMiddleware(c VerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	ops := make([]identityhttp.OperationDescriptor, 0, 3)
	for mode, id := range []string{"identity.phone.send-verification", "identity.phone.verify", "identity.phone.verify.recover"} {
		h, err := newHandler(c, mode, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: id, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = verificationWire(c, mode, id)
		if mode != 0 {
			op.Wire.SecuritySchemes = nil
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: ops})
}

func verificationWire(c VerificationConfig, mode int, operation string) *identityhttp.WireOperation {
	text := func(max int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": max}
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}
	keyVersion := map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(^uint32(0))}
	recovery := object([]string{"sendCommandID", "attempt", "expectedVersion", "digestKeyVersion", "scopeDigest"}, map[string]any{
		"sendCommandID": id, "attempt": object([]string{"tenantID", "commandID", "attemptID", "fingerprint", "fingerprintKeyVersion"}, map[string]any{
			"tenantID": text(128), "commandID": id, "attemptID": id, "fingerprint": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "fingerprintKeyVersion": keyVersion,
		}), "expectedVersion": version, "digestKeyVersion": keyVersion,
		"scopeDigest": map[string]any{"type": "array", "minItems": 32, "maxItems": 32, "items": map[string]any{"type": "integer", "minimum": 0, "maximum": 255}, "not": map[string]any{"const": [32]byte{}}},
	})
	fields := map[string]any{"flowID": map[string]any{"type": "string", "pattern": "^[!-~]{1,128}$"}}
	required := []string{"flowID"}
	parameters := []any{
		map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)},
		map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "writeOnly": true}},
	}
	if mode == 0 {
		required = append(required, "number", "proofID")
		fields["number"], fields["proofID"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 64, "writeOnly": true, "description": "Phone input canonicalized by the selected versioned native E.164 policy."}, id
		parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}})
	} else if mode == 1 {
		required = append(required, "sendCommandID", "code")
		fields["sendCommandID"], fields["code"] = id, map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": true}
	} else {
		required = append(required, "recovery")
		fields["recovery"] = recovery
	}
	successRequired := []string{"accepted", "verified", "commandID", "commitOutcome"}
	successFields := map[string]any{"accepted": map[string]any{"const": mode == 0}, "verified": map[string]any{"const": false}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}}
	if mode != 0 {
		successRequired = append(successRequired, "recovery")
		successFields["recovery"] = recovery
	}
	if mode == 2 {
		successFields["commitOutcome"] = map[string]any{"type": "string", "enum": []string{"committed", "not_committed"}}
	}
	var success any = object(successRequired, successFields)
	if mode == 1 {
		fresh := map[string]any{}
		for key, value := range successFields {
			fresh[key] = value
		}
		fresh["verified"], fresh["identifierID"], fresh["identifierVersion"] = map[string]any{"const": true}, text(128), version
		success = map[string]any{"oneOf": []any{success, object(append(append([]string{}, successRequired...), "identifierID", "identifierVersion"), fresh)}}
	}
	errors := map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "origin_or_csrf_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "conflict", "in_progress", "unavailable"}}
	failure := object([]string{"accepted", "verified", "commitOutcome", "error"}, map[string]any{"accepted": map[string]any{"const": false}, "verified": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "recovery": recovery, "error": errors})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free original status; no-store/nosniff. No session, code, number or credential headers. Unknown does not prove rollback.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	status := "200"
	if mode == 0 {
		status = "202"
		delete(failure["properties"].(map[string]any), "recovery")
	}
	responses := map[string]any{status: response(success)}
	for _, code := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[code] = response(map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": errors}), failure}})
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	security := map[string]any{"IdentityPhoneSession": []any{}}
	if mode == 0 {
		security["IdentityPhoneDevice"] = []any{}
	}
	definition, _ := json.Marshal(map[string]any{"operationId": operation,
		"description": "Explicit existing-account password-session phone enrollment only. Exact HTTPS tenant host, Origin and current original-session synchronizer required. Send also requires the existing signed browser device, fresh action-bound proof and header retry key. Verification/recovery forbid idempotency keys. Native authority, original issued lifetime, canonical shared budgets and atomic effects remain mandatory. No signup, signin, replacement, reset, removal, factor fallback or session issuance.",
		"security":    []any{security}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object(required, fields)}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	sessionScheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	deviceScheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device"})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "IdentityPhoneSession", Definition: sessionScheme}, {Name: "IdentityPhoneDevice", Definition: deviceScheme}}}
}
