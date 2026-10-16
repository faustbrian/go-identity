package otphttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewEmailVerificationFeature explicitly selects authenticated-session email
// verification Send, completion and original metadata recovery under one OTP
// owner. Omit it to expose no routes or metadata. It does not select signin,
// pre-auth, primary replacement or automatic session issuance. Another OTP Send
// profile cannot be composed at the same route; conflicting selections deny.
func NewEmailVerificationFeature(c EmailVerificationConfig) (identityhttp.Feature, error) {
	return NewEmailVerificationFeatureWithMiddleware(c, nil)
}

// NewEmailVerificationFeatureWithMiddleware preserves the frozen real typed
// owner phases and credential-free responses through router middleware binding.
// All dependencies are validated without native IO; no partial feature escapes.
func NewEmailVerificationFeatureWithMiddleware(c EmailVerificationConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	ops := make([]identityhttp.OperationDescriptor, 0, 3)
	for mode, id := range []string{"identity.otp.send", "identity.otp.email-verify", "identity.otp.email-verify.recover"} {
		h, err := newEmailVerificationHandler(c, mode, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/otp", OperationID: id, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = emailVerificationWire(c, mode)
		if mode != 0 {
			op.Wire.SecuritySchemes = nil
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: ops})
}

func emailVerificationWire(c EmailVerificationConfig, mode int) *identityhttp.WireOperation {
	text := func(max int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": max}
	}
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	recovery := object([]string{"sendCommandID", "attempt", "expectedVersion", "digestKeyVersion", "scopeDigest"}, map[string]any{
		"sendCommandID":    id,
		"attempt":          object([]string{"commandID", "tenantID", "attemptID", "fingerprint", "fingerprintKeyVersion"}, map[string]any{"commandID": id, "tenantID": text(128), "attemptID": id, "fingerprint": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "fingerprintKeyVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(^uint32(0))}}),
		"expectedVersion":  map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)},
		"digestKeyVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(^uint32(0))},
		"scopeDigest":      map[string]any{"type": "array", "minItems": 32, "maxItems": 32, "items": map[string]any{"type": "integer", "minimum": 0, "maximum": 255}, "not": map[string]any{"const": [32]byte{}}},
	})
	required := []string{"flowID"}
	fields := map[string]any{"flowID": map[string]any{"type": "string", "pattern": "^[!-~]{1,128}$"}}
	parameters := []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "writeOnly": true}}}
	idName := "identity.otp.email-verify"
	success := "200"
	if mode == 0 {
		idName, success = "identity.otp.send", "202"
		required = append(required, "addressID", "addressVersion")
		fields["addressID"], fields["addressVersion"] = text(128), map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 1}
		parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}})
	} else if mode == 1 {
		required = append(required, "sendCommandID", "code")
		fields["sendCommandID"], fields["code"] = id, map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": true, "description": "Opaque submitted code under the selected native code profile; never returned or logged."}
	} else {
		idName = "identity.otp.email-verify.recover"
		required = append(required, "recovery")
		fields["recovery"] = recovery
	}
	result := object([]string{"accepted", "verified", "commitOutcome"}, map[string]any{"accepted": map[string]any{"type": "boolean"}, "verified": map[string]any{"type": "boolean"}, "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "addressID": text(128), "addressVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}, "recovery": recovery, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "origin_or_csrf_denied", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "conflict", "in_progress", "unavailable"}}})
	// These assertions bind the shared response shape to each selected arm;
	// history cannot masquerade as a new verification or address disclosure.
	props := result["properties"].(map[string]any)
	if mode == 0 {
		props["verified"] = map[string]any{"const": false}
		delete(props, "addressID")
		delete(props, "addressVersion")
		delete(props, "recovery")
	} else {
		props["accepted"] = map[string]any{"const": false}
	}
	if mode == 2 {
		props["verified"] = map[string]any{"const": false}
		delete(props, "addressID")
		delete(props, "addressVersion")
	}
	successFields := map[string]any{"accepted": map[string]any{"const": mode == 0}, "verified": map[string]any{"const": mode == 1}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}}
	successRequired := []string{"accepted", "verified", "commandID", "commitOutcome"}
	if mode != 0 {
		successFields["recovery"] = recovery
		successRequired = append(successRequired, "recovery")
	}
	if mode == 1 {
		successFields["addressID"], successFields["addressVersion"] = props["addressID"], props["addressVersion"]
		successRequired = append(successRequired, "addressID", "addressVersion")
	}
	if mode == 2 {
		successFields["commitOutcome"] = map[string]any{"type": "string", "enum": []string{"committed", "not_committed"}}
	}
	props["accepted"], props["verified"] = map[string]any{"const": false}, map[string]any{"const": false}
	delete(props, "addressID")
	delete(props, "addressVersion")
	result["required"] = []string{"accepted", "verified", "commitOutcome", "error"}
	failureSchema := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": props["error"]}), result}}
	response := func(schema any) any {
		return map[string]any{"description": "Credential-free original status. No-store/nosniff; no Set-Cookie, CSRF response token, session or code. Unknown does not prove rollback.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{success: response(object(successRequired, successFields))}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failureSchema)
	}
	// The shared router's earlier CORS owner may reject before feature JSON.
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	security := map[string]any{"IdentityEmailOTPSession": []any{}}
	if mode == 0 {
		security["IdentityEmailOTPDevice"] = []any{}
	}
	definition, _ := json.Marshal(map[string]any{"operationId": idName, "description": "Selected authenticated self-user email_verification_otp profile only. Exact HTTPS tenant host, Origin, original password-session cookie and stored synchronizer are mandatory. No body identity/purpose/factor overrides, Authorization, query, trailers, primary replacement or automatic signin. Send alone requires header idempotency and a scoped device cookie; completion/recovery forbid idempotency. Native owners retain current authority, attempt accounting, atomic identifier effects and original metadata recovery.", "security": []any{security}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object(required, fields)}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	sessionScheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	deviceScheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device"})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "IdentityEmailOTPSession", Definition: sessionScheme}, {Name: "IdentityEmailOTPDevice", Definition: deviceScheme}}}
}
