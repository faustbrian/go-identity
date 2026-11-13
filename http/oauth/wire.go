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
	var signinSchemes []identityhttp.WireComponent
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
		if c.Signin != nil {
			responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known provider/IP or original-transaction denial: bounded ceiling seconds, not permission to re-exchange a code.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
			definition["description"] = "Selected query/S256 OIDC callback. Native keyed original state selects explicit-self linking or existing-account signin, never ambient cookies or a request mode. Issuer and original browser/device must match. Shared provider/IP admission precedes native attribution and transaction admission. No fresh session lookup, implicit signup or enrolled-MFA fallback. Only a new exact signin commit delivers its HttpOnly session cookie and separate browser-readable synchronizer cookie; replay and provider denial emit neither. All redirects retain the original allowlisted same-origin callback."
			security := []any{}
			if !missing(c.Callback) {
				security = append(security, map[string]any{schemeName: []string{}})
			}
			security = append(security, map[string]any{"SocialSigninCallbackFlow": []string{}, "SocialSigninCallbackDevice": []string{}})
			definition["security"] = security
			for _, selected := range []struct{ component, name, description string }{
				{"SocialSigninCallbackFlow", "__Host-identity_flow", "Exact original native preauth possession, not an active session."},
				{"SocialSigninCallbackDevice", "__Host-identity_device", "Original signed browser correlation; not authentication or MFA authority."},
			} {
				encoded, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": selected.name, "description": selected.description})
				signinSchemes = append(signinSchemes, identityhttp.WireComponent{Name: selected.component, Definition: encoded})
			}
			responses["303"] = map[string]any{"description": "Original allowlisted redirect. Linking, denial and historical replay deliver no new credentials. Fresh signin alone emits separate secure host-only session and readable CSRF cookies with original Remember semantics.", "headers": map[string]any{
				"Location":   map[string]any{"required": true, "schema": text(1, 2048)},
				"Set-Cookie": map[string]any{"description": "Two separate fields only for new exact committed signin: HttpOnly session and browser-readable synchronizer token. Both Secure, host-only, Path=/, explicit SameSite and original expiry; never combine fields or expose tokens in URLs.", "schema": text(1, 8192)},
			}}
		}
	} else {
		definition["description"] = "Selected cookie/fresh-self linking initiation. Requires exact Origin, X-CSRF-Token, Idempotency-Key and configured provider/scopes. Native admission rechecks original session/credential/factor/policy in its protected transaction. No implicit linking, signup or signin is selected."
		definition["parameters"] = []any{parameter("Origin", "header", true, map[string]any{"const": string(c.Origin)}), parameter("X-CSRF-Token", "header", true, text(43, 43)), parameter("Idempotency-Key", "header", true, text(1, 256))}
		definition["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"provider", "callback", "errorCallback", "scopes", "signupDisabled"}, "properties": map[string]any{"provider": map[string]any{"const": c.Provider.ID}, "callback": map[string]any{"type": "string", "enum": c.CallbackAllowlist}, "errorCallback": map[string]any{"type": "string", "enum": c.CallbackAllowlist}, "scopes": map[string]any{"const": c.Provider.Scopes}, "signupDisabled": map[string]any{"const": true}}}}}}
		responses["200"] = response(map[string]any{"type": "object", "additionalProperties": false, "required": []string{"redirectURI", "transactionID", "expiresAt"}, "properties": map[string]any{"redirectURI": text(1, 16384), "transactionID": text(1, 128), "expiresAt": map[string]any{"type": "string", "format": "date-time"}}})
	}
	wire, _ := json.Marshal(definition)
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original native browser possession; initiation additionally requires current fresh authority. Callback does not issue or refresh this cookie."})
	schemes := []identityhttp.WireComponent{}
	if !callback || c.Signin == nil || !missing(c.Callback) {
		schemes = append(schemes, identityhttp.WireComponent{Name: schemeName, Definition: scheme})
	}
	return &identityhttp.WireOperation{Definition: wire, SecuritySchemes: append(schemes, signinSchemes...)}
}

func wireSigninStart(c SigninStartConfig) *identityhttp.WireOperation {
	base := wireOperation(Config{Provider: c.Provider, Origin: c.Origin, Cookie: c.FlowCookie, CallbackAllowlist: c.CallbackAllowlist}, false)
	var definition map[string]any
	_ = json.Unmarshal(base.Definition, &definition)
	definition["operationId"] = "identity.oauth.signin-start"
	definition["responses"].(map[string]any)["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known provider/IP denial: bounded ceiling seconds. Retry the original flow and request key.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	definition["description"] = "Explicit existing-account query/S256 OIDC initiation. Reuse the original OAuth preauth flow ID, flow/device cookies and resolved Remember policy for keyed retries. Exact Origin and Idempotency-Key; no current user/session lookup, CSRF alternate, implicit signup or factor fallback. Native state authority authenticates the original browser and configuration before issuing one durable authorization transaction. This response creates no session."
	definition["security"] = []any{map[string]any{"SocialSigninStartFlow": []string{}, "SocialSigninStartDevice": []string{}}}
	definition["parameters"] = []any{
		map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"const": string(c.Origin)}},
		map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}},
	}
	schema := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	schema["required"] = []string{"flowID", "provider", "callback", "errorCallback", "scopes", "signupDisabled"}
	properties := schema["properties"].(map[string]any)
	properties["flowID"] = map[string]any{"type": "string", "minLength": 22, "maxLength": 22, "description": "Safe original OAuth preauth locator, not browser possession or a user."}
	properties["remember"] = map[string]any{"type": "boolean", "description": "Omission resolves the configured default. Must match the original flow; retries must not change it. Null denies."}
	encoded, _ := json.Marshal(definition)
	var schemes []identityhttp.WireComponent
	for _, selected := range []struct{ component, name string }{{"SocialSigninStartFlow", "__Host-identity_flow"}, {"SocialSigninStartDevice", "__Host-identity_device"}} {
		wire, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": selected.name, "description": "Original preauth browser custody. Device is non-authenticating correlation; native initiation still verifies current admission."})
		schemes = append(schemes, identityhttp.WireComponent{Name: selected.component, Definition: wire})
	}
	return &identityhttp.WireOperation{Definition: encoded, SecuritySchemes: schemes}
}
