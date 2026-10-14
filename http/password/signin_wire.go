package passwordhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewSigninFeature selects only browser password signin and its concrete wire
// contract. Omission exposes no route or metadata. Use NewFeature when composing
// sibling password operations under the same owner; no global registration.
func NewSigninFeature(c SigninConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{Signin: &c}, nil)
}

// NewSigninFeatureWithMiddleware selects the real frozen native phases.
// Router rebinding preserves original credential and response custody.
func NewSigninFeatureWithMiddleware(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(FeatureConfig{Signin: &c}, m)
}

func signinOperation(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.OperationDescriptor, error) {
	h, err := NewSigninHandlerWithMiddleware(c, m)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.signin", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = signinWire(c)
	return op, nil
}

func signinWire(c SigninConfig) *identityhttp.WireOperation {
	text := func(max any) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, fields map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	recovery := object([]string{"commandID", "tenantID", "flowID", "actorID", "actorKind"}, map[string]any{"commandID": id, "tenantID": text(256), "flowID": id, "actorID": text(256), "actorKind": map[string]any{"const": "service-account"}})
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "rate_limiter_unavailable", "denied", "unavailable", "conflict", "in_progress"}}
	success := object([]string{"signedIn", "commandID", "sessionID", "commitOutcome", "recovery"}, map[string]any{"signedIn": map[string]any{"const": true}, "commandID": id, "sessionID": text(128), "commitOutcome": map[string]any{"const": "committed"}, "recovery": recovery})
	attempt := object([]string{"signedIn", "commitOutcome", "error"}, map[string]any{"signedIn": map[string]any{"const": false}, "commandID": id, "sessionID": text(128), "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "recovery": recovery, "error": codes})
	attempt["dependentRequired"] = map[string]any{"commandID": []string{"recovery"}, "recovery": []string{"commandID"}}
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), attempt}}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store/nosniff original command metadata. Recovery is not permission or retry. No credentials in JSON or response trailers.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	if c.MFAContinuation {
		challenge := object([]string{"signedIn", "commandID", "commitOutcome", "recovery", "challengeRequired", "challengeID", "challengeMethod", "challengeExpiresAt"}, map[string]any{"signedIn": map[string]any{"const": false}, "commandID": id, "commitOutcome": map[string]any{"const": "committed"}, "recovery": recovery, "challengeRequired": map[string]any{"const": true}, "challengeID": id, "challengeMethod": map[string]any{"const": "totp"}, "challengeExpiresAt": map[string]any{"type": "string", "format": "date-time"}})
		responses["200"] = response(map[string]any{"oneOf": []any{success, challenge}})
		responses["200"].(map[string]any)["headers"] = map[string]any{"X-MFA-Token": map[string]any{"description": "Reveal-once original continuation proof, delivered only for fresh challenge-only commitment; never with session cookie/CSRF, on retry or failed delivery.", "schema": text(4096)}}
	}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native work.", "content": map[string]any{"text/plain": plain}}
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Original fresh session, Secure/HttpOnly/host-only/Path=/ and explicit Lax or Strict; never replay or error.", "schema": text(4096)}, "X-CSRF-Token": map[string]any{"description": "Original session-bound synchronizer; never log or place in JSON.", "schema": text(256)}}
	if c.MFAContinuation {
		responses["200"].(map[string]any)["headers"].(map[string]any)["X-MFA-Token"] = map[string]any{"description": "Reveal-once original continuation proof only for fresh challenge-only commitment; never with session cookie/CSRF.", "schema": text(4096)}
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known bounded whole seconds; does not authorize resubmitting secrets after ambiguity.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	request := object([]string{"flowID", "identifier", "password", "callbackURL"}, map[string]any{"flowID": id, "identifier": text(1024), "password": map[string]any{"type": "string", "minLength": 1, "maxLength": min(c.Network.Limits.MaximumDecodedBytes, uint64(1<<20)), "writeOnly": true}, "callbackURL": map[string]any{"type": "string", "maxLength": 2048}, "remember": map[string]any{"type": "boolean"}})
	definition := map[string]any{"operationId": "identity.password.signin", "description": "Selected verified-email single-factor browser password profile; MFA continuation remains unavailable and native factor policy must deny rather than downgrade. Original pre-auth cookie/flowID, exact HTTPS tenant/Origin, callback and remember choice; signed device supplies correlation only. IP admission precedes native normalization/custody, then shared identifier budget and one non-keyed native signin. No Authorization, retry key, query, trailers, client identity or credential alternative. Only fresh error-free known commit delivers original session and synchronizer; ambiguity retains password-free recovery without retry or renewal.", "security": []any{map[string]any{"PasswordSigninOriginalFlow": []string{}, "PasswordSigninBrowserDevice": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}}, "responses": responses}
	if c.MFAContinuation {
		definition["description"] = "Explicit password-first MFA selection. Original flow/cookie, mapped HTTPS tenant/Origin, callback, remember and signed device remain mandatory. Correct password commits either the selected single-factor session or a challenge-only X-MFA-Token; partial authentication cannot issue a session. Native current factor/risk/credential authority is decisive. Replay, ambiguity, errors, cancellation and expired response commitment withhold credentials. Recovery preserves original metadata without proof redelivery."
	}
	data, _ := json.Marshal(definition)
	wire := &identityhttp.WireOperation{Definition: data}
	for _, item := range []struct{ name, cookie, description string }{{"PasswordSigninOriginalFlow", "__Host-identity_flow", "Original pre-auth browser possession, not a user session."}, {"PasswordSigninBrowserDevice", "__Host-identity_device", "Original signed correlation, never account/MFA/hardware authority or replacement issuance."}} {
		scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": item.cookie, "description": item.description})
		wire.SecuritySchemes = append(wire.SecuritySchemes, identityhttp.WireComponent{Name: item.name, Definition: scheme})
	}
	return wire
}
