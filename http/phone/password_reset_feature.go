package phonehttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewPasswordResetFeature explicitly selects the two no-session phone recovery
// operations. It enables no enrollment, signin, phone change, removal, fallback
// or additional recovery route. Native code-free history remains a separate Go
// API. No operation or metadata exists unless the feature is composed.
func NewPasswordResetFeature(c PasswordResetConfig) (identityhttp.Feature, error) {
	return NewPasswordResetFeatureWithMiddleware(c, nil)
}

// NewPasswordResetFeatureWithMiddleware binds hooks to the existing immutable
// decode/authenticate/admit/handle phases, without replacement authority or a
// second execution. Construction validates all selected owners without IO.
func NewPasswordResetFeatureWithMiddleware(c PasswordResetConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	operations := make([]identityhttp.OperationDescriptor, 0, 2)
	for _, complete := range []bool{false, true} {
		h, err := newPasswordResetHandler(c, complete, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		id := "identity.phone.password-reset-request"
		if complete {
			id = "identity.phone.password-reset-complete"
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: id, Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 4096})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = passwordResetWire(complete, id)
		if complete {
			op.Wire.SecuritySchemes = nil
		}
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: operations})
}

func passwordResetWire(complete bool, operation string) *identityhttp.WireOperation {
	text := func(maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
	}
	secret := func(maximum int) map[string]any { v := text(maximum); v["writeOnly"] = true; return v }
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	fields := map[string]any{"commandID": id, "riskIssuanceCommandID": id, "flowID": id}
	required := []string{"commandID", "riskIssuanceCommandID", "flowID"}
	parameters := []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}}
	status := "202"
	description := "Explicit no-session phone recovery. Exact HTTPS tenant host/Origin and original flow plus signed browser-device cookies are mandatory. Authorization and X-CSRF-Token are forbidden. Retain commandID, riskIssuanceCommandID and original cookies across retries; risk issuance and consuming command IDs must differ. Request acknowledgment is enumeration-safe and does not prove account existence, commitment or delivery. No session/remember/fallback option."
	success := object([]string{"accepted", "commandID"}, map[string]any{"accepted": map[string]any{"const": true}, "commandID": id})
	if complete {
		status = "200"
		fields["token"], fields["phoneCode"], fields["totpCode"], fields["newPassword"] = secret(4096), secret(128), secret(128), secret(1<<20)
		fields["token"].(map[string]any)["minLength"] = 32
		required = append(required, "token", "phoneCode", "totpCode", "newPassword")
		success = object([]string{"completed", "commandID", "commitOutcome", "credentialVersion", "sessionsRevoked"}, map[string]any{"completed": map[string]any{"const": true}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}, "credentialVersion": map[string]any{"type": "integer", "minimum": 2, "maximum": ^uint64(0)}, "sessionsRevoked": map[string]any{"const": true}})
		description += " Completion forbids Idempotency-Key. Both codes and the capability are submitted only by explicit POST; native authority owns comparison, current freshness, atomic password/session effects and original replay. No link-scanner GET or automatic retry."
	} else {
		fields["number"] = secret(64)
		required = append(required, "number")
		parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}})
	}
	failure := object([]string{"error"}, map[string]any{"error": text(64), "commandID": id, "commitOutcome": map[string]any{"type": "string", "enum": []string{"committed", "not_committed", "unknown", "conflict", "in_progress"}}})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free no-store/nosniff response; unknown is not rollback. No credential/session response headers.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{status: response(success)}
	for _, code := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[code] = response(failure)
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	definition, _ := json.Marshal(map[string]any{"operationId": operation, "description": description, "security": []any{map[string]any{"IdentityPhoneRecoveryFlow": []any{}, "IdentityPhoneRecoveryDevice": []any{}}}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object(required, fields)}}}, "responses": responses})
	flow, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_flow"})
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device"})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "IdentityPhoneRecoveryFlow", Definition: flow}, {Name: "IdentityPhoneRecoveryDevice", Definition: device}}}
}
