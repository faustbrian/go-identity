package passwordhttp

import (
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewSignupFeature selects only required-email-verification browser signup.
// Omission exposes no route or metadata; use NewFeature for sibling operations.
func NewSignupFeature(c SignupConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{Signup: &c}, nil)
}

// NewSignupFeatureWithMiddleware binds frozen typed owner phases. Router
// rebinding cannot replace original retry-key, flow or password custody.
func NewSignupFeatureWithMiddleware(c SignupConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{Signup: &c}, m)
}
func signupOperation(c SignupConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewSignupHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.signup", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = signupWire(c)
	return op, nil
}
func signupWire(c SignupConfig) *identityhttp.WireOperation {
	text := func(max any) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, p map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	recovery := object([]string{"commandID", "tenantID", "flowID", "actorID", "actorKind"}, map[string]any{"commandID": id, "tenantID": text(256), "flowID": id, "actorID": text(256), "actorKind": map[string]any{"const": "service-account"}})
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "rate_limiter_unavailable", "denied", "unavailable", "conflict", "in_progress"}}
	success := object([]string{"verificationRequired", "commitOutcome", "commandID", "recovery", "replayed"}, map[string]any{"verificationRequired": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "recovery": recovery, "replayed": map[string]any{"type": "boolean"}})
	attempt := object([]string{"verificationRequired", "commitOutcome", "replayed", "error"}, map[string]any{"verificationRequired": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "recovery": recovery, "replayed": map[string]any{"type": "boolean"}, "error": codes})
	attempt["dependentRequired"] = map[string]any{"commandID": []string{"recovery"}, "recovery": []string{"commandID"}}
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), attempt}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store/nosniff original metadata only; no account, address, key, password or credentials. Recovery is not permission or retry.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native work.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known bounded whole seconds; never authorization to resubmit secrets after ambiguity.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	var variants []any
	for _, f := range c.FieldSchema.Fields {
		if f.InputPermission != identity.FieldWrite && f.InputPermission != identity.FieldReadWrite {
			continue
		}
		var value any
		switch f.Kind {
		case identity.AttributeString:
			value = map[string]any{"type": "string", "maxLength": 4096}
		case identity.AttributeBool:
			value = map[string]any{"type": "boolean"}
		case identity.AttributeInt64:
			value = map[string]any{"type": "integer", "minimum": int64(-9223372036854775808), "maximum": int64(9223372036854775807)}
		case identity.AttributeTime:
			value = map[string]any{"type": "string", "format": "date-time", "maxLength": 64}
		case identity.AttributeStringList:
			value = map[string]any{"type": "array", "maxItems": 64, "items": map[string]any{"type": "string", "maxLength": 4096}}
		}
		v := object([]string{"name", "kind", "value"}, map[string]any{"name": map[string]any{"const": f.Name}, "kind": map[string]any{"const": string(f.Kind)}, "value": value})
		v["writeOnly"] = true
		variants = append(variants, v)
	}
	var item any = false
	if len(variants) > 0 {
		item = map[string]any{"oneOf": variants}
	}
	request := object([]string{"flowID", "email", "password", "callbackURL"}, map[string]any{"flowID": id, "email": text(4096), "password": map[string]any{"type": "string", "minLength": 1, "maxLength": min(c.Network.Limits.MaximumDecodedBytes, uint64(1<<20)), "writeOnly": true}, "callbackURL": map[string]any{"type": "string", "maxLength": 2048}, "remember": map[string]any{"type": "boolean"}, "allowedFields": map[string]any{"type": "array", "maxItems": min(len(c.FieldSchema.Fields), 64), "items": item}})
	definition := map[string]any{"operationId": "identity.password.signup", "description": "Selected required-email-verification signup; no session or existing-account identity. Original flow and signed device, exact mapped HTTPS tenant/Origin, callback and remember choice. Exactly one byte-exact Idempotency-Key header, no alternate channel. IP admission precedes native normalization then shared identifier admission and one native keyed signup. Native field policy and original custody remain authoritative. Keyed replay retains original history even after live-flow deletion; no automatic retry, credential delivery or renewal. Immediate-session/MFA signup profiles remain unavailable, not downgraded.", "security": []any{map[string]any{"PasswordSignupOriginalFlow": []string{}, "PasswordSignupBrowserDevice": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"}, "description": "Original tenant/actor/operation/intent-bound key; never log, return or replace after ambiguity."}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	wire := &identityhttp.WireOperation{Definition: data}
	for _, s := range []struct{ name, cookie string }{{"PasswordSignupOriginalFlow", "__Host-identity_flow"}, {"PasswordSignupBrowserDevice", "__Host-identity_device"}} {
		data, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": s.cookie, "description": "Original browser custody, not account identity, session or execution permission."})
		wire.SecuritySchemes = append(wire.SecuritySchemes, identityhttp.WireComponent{Name: s.name, Definition: data})
	}
	return wire
}
