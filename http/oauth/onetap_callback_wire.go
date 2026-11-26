package oauthhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func oneTapCallbackWire(c OneTapCallbackConfig) *identityhttp.WireOperation {
	text := func(minimum, maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
	}
	secret := func(minimum, maximum int) map[string]any {
		schema := text(minimum, maximum)
		schema["writeOnly"] = true
		return schema
	}
	failure := func(codes ...string) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{"error": map[string]any{"type": "string", "enum": codes}}}
	}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store redacted result; credentials are never serialized into JSON.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{}
	for _, outcome := range []struct {
		status string
		codes  []string
	}{
		{"400", []string{"invalid_request"}},
		{"403", []string{"denied", "https_required"}},
		{"404", []string{"not_found"}},
		{"405", []string{"method_not_allowed"}},
		{"409", []string{"conflict"}},
		{"421", []string{"misdirected_request"}},
		{"429", []string{"rate_limited"}},
		{"503", []string{"unavailable"}},
	} {
		responses[outcome.status] = response(failure(outcome.codes...))
	}
	// NewRouter preserves its own CORS denial rather than invoking this leaf.
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"const": "POST"}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known shared provider/IP denial, rounded up to bounded seconds. No permission to replay completion.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	responses["200"] = response(map[string]any{"type": "object", "additionalProperties": false, "required": []string{"status"}, "properties": map[string]any{"status": map[string]any{"const": "signed_in"}}})
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Exactly two separate fields only for a fresh accepted native commit: secure host-only HttpOnly session and readable synchronizer cookies. Original Remember choice, session expiry and DeliveryValidUntil are preserved. Historical, failed and nondeliverable results issue neither.", "schema": text(1, 8192)}}
	definition := map[string]any{
		"operationId": "identity.oauth.onetap-callback",
		"description": "Selected existing-account Google popup callback only. Exact configured HTTPS tenant/Origin and original flow/signed-device cookies, one matching opaque Google double-submit cookie/body value, and closed bounded JSON precede native completion. An optional client_id only confirms the configured client. No Idempotency-Key, Authorization, header CSRF, query, redirect, signup, linking, MFA or JWT-claim alternatives. Shared provider/IP admission is transport-owned; native completion owns provider verification, counted risk and the one-use transaction. Only a fresh exact accepted session and CSRF cookie emission returns signed_in. Replay, unknown, cancellation and expired original delivery authority fail closed without credentials or redirects.",
		"security":    []any{map[string]any{"OneTapCallbackFlow": []string{}, "OneTapCallbackDevice": []string{}, "OneTapCallbackGoogleCSRF": []string{}}},
		"parameters":  []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"const": string(c.Origin)}}},
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"flowId", "credential", "g_csrf_token"},
			"properties": map[string]any{"flowId": text(22, 22), "credential": secret(1, c.Provider.MaxTokenBytes), "g_csrf_token": secret(1, 1024), "client_id": map[string]any{"const": c.Provider.ClientID}},
		}}}},
		"responses": responses,
	}
	wire, _ := json.Marshal(definition)
	device, _ := c.Device.Cookie.DeletionAttributes()
	var schemes []identityhttp.WireComponent
	for _, item := range []struct{ component, name, description string }{
		{"OneTapCallbackFlow", "__Host-identity_flow", "One exact original native preauth flow cookie. A flow locator or current session cannot replace it."},
		{"OneTapCallbackDevice", device.Name, "One exact original signed browser device correlation, not independent authentication authority."},
		{"OneTapCallbackGoogleCSRF", "g_csrf_token", "One unquoted opaque cookie value exactly matching the bounded g_csrf_token JSON string; duplicates deny before native/provider work."},
	} {
		encoded, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": item.name, "description": item.description})
		schemes = append(schemes, identityhttp.WireComponent{Name: item.component, Definition: encoded})
	}
	return &identityhttp.WireOperation{Definition: wire, SecuritySchemes: schemes}
}
