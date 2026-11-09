package oauthhttp

import (
	"encoding/json"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func wireOperation(c Config, callback bool) *identityhttp.WireOperation {
	text := func(min, max int) map[string]any {
		return map[string]any{"type": "string", "minLength": min, "maxLength": max}
	}
	parameter := func(name, location string, required bool, schema any) any {
		return map[string]any{"name": name, "in": location, "required": required, "schema": schema}
	}
	failed := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{"error": map[string]any{"enum": []string{"invalid_request", "denied", "conflict", "rate_limited", "unavailable"}}}}
	response := func(schema any) any {
		return map[string]any{"description": "No-store result without credential or provider diagnostics.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{}
	for _, code := range []string{"400", "403", "409", "429", "503"} {
		responses[code] = response(failed)
	}
	action := "identity.account.link-start"
	schemeName := "SocialLinkStartBrowser"
	if callback {
		schemeName = "SocialLinkCallbackBrowser"
	}
	definition := map[string]any{"operationId": action, "security": []any{map[string]any{schemeName: []string{}}}, "responses": responses}
	if callback {
		action = "identity.oauth.callback"
		definition["operationId"] = action
		definition["description"] = "Selected query/S256 OIDC explicit-self linking callback. Exactly one code or provider error, immutable issuer and original state/browser are required. No actor, tenant, provider endpoint, idempotency header or fresh session lookup may replace native state authority. Native state is reserved before PKCE release/exchange; unknown outcomes never retry the code. Linking never issues a session."
		state := text(43, 43)
		state["writeOnly"] = true
		code := text(1, c.Provider.MaxCodeBytes)
		code["writeOnly"] = true
		definition["parameters"] = []any{parameter("state", "query", true, state), parameter("iss", "query", true, map[string]any{"const": c.Provider.Issuer}), parameter("code", "query", false, code), parameter("error", "query", false, text(1, 256)), parameter("error_description", "query", false, text(0, 1024)), parameter("error_uri", "query", false, text(1, 2048))}
		responses["303"] = map[string]any{"description": "Committed linking redirects to the original allowlisted success callback; terminal provider refusal redirects to the original allowlisted error callback without an identity. No session cookie is issued.", "headers": map[string]any{"Location": map[string]any{"required": true, "schema": text(1, 2048)}}}
	} else {
		definition["description"] = "Selected cookie/fresh-self linking initiation. Requires exact Origin, X-CSRF-Token, Idempotency-Key and configured provider/scopes. Native admission rechecks original session/credential/factor/policy in its protected transaction. No implicit linking, signup or signin is selected."
		definition["parameters"] = []any{parameter("Origin", "header", true, map[string]any{"const": string(c.Origin)}), parameter("X-CSRF-Token", "header", true, text(43, 43)), parameter("Idempotency-Key", "header", true, text(1, 256))}
		definition["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"provider", "callback", "errorCallback", "scopes", "signupDisabled"}, "properties": map[string]any{"provider": map[string]any{"const": c.Provider.ID}, "callback": map[string]any{"type": "string", "enum": c.CallbackAllowlist}, "errorCallback": map[string]any{"type": "string", "enum": c.CallbackAllowlist}, "scopes": map[string]any{"const": c.Provider.Scopes}, "signupDisabled": map[string]any{"const": true}}}}}}
		responses["200"] = response(map[string]any{"type": "object", "additionalProperties": false, "required": []string{"redirectURI", "transactionID", "expiresAt"}, "properties": map[string]any{"redirectURI": text(1, 16384), "transactionID": text(1, 128), "expiresAt": map[string]any{"type": "string", "format": "date-time"}}})
	}
	wire, _ := json.Marshal(definition)
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original native browser possession; initiation additionally requires current fresh authority. Callback does not issue or refresh this cookie."})
	return &identityhttp.WireOperation{Definition: wire, SecuritySchemes: []identityhttp.WireComponent{{Name: schemeName, Definition: scheme}}}
}
