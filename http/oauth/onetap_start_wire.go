package oauthhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func wireOneTapStart(c OneTapStartConfig) *identityhttp.WireOperation {
	text := func(minimum, maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
	}
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	enum := func(values ...string) map[string]any { return map[string]any{"type": "string", "enum": values} }
	boolean := map[string]any{"type": "boolean"}
	context := enum("signin", "signup", "use")
	buttonType := enum("standard", "icon")
	theme := enum("outline", "filled_blue", "filled_black", "outline_dark")
	size := enum("small", "medium", "large")
	width := map[string]any{"type": "integer", "minimum": 0, "maximum": 400}
	prompt := object([]string{"context", "cancelOnTapOutside"}, map[string]any{"context": context, "cancelOnTapOutside": boolean})
	button := object([]string{"type", "theme", "size"}, map[string]any{"type": buttonType, "theme": theme, "size": size, "width": width})
	remember := map[string]any{"type": "boolean", "description": "Omission resolves the trusted session default once. Null denies; retries must preserve the original choice. The preauth expiry remains five minutes."}
	request := map[string]any{"oneOf": []any{
		object([]string{"prompt"}, map[string]any{"prompt": prompt, "remember": remember}),
		object([]string{"button"}, map[string]any{"button": button, "remember": remember}),
	}}
	// Native options are detached GIS subsets, not a complete initialization or
	// render call: their established projection uses GIS snake_case spellings.
	promptOutput := object([]string{"context", "cancel_on_tap_outside"}, map[string]any{"context": context, "cancel_on_tap_outside": boolean})
	buttonOutput := object([]string{"ux_mode", "type", "theme", "size"}, map[string]any{"ux_mode": map[string]any{"type": "string", "const": "popup"}, "type": buttonType, "theme": theme, "size": size, "width": width})
	options := map[string]any{"oneOf": []any{
		object([]string{"experience", "prompt"}, map[string]any{"experience": map[string]any{"type": "string", "const": "prompt"}, "prompt": promptOutput}),
		object([]string{"experience", "button"}, map[string]any{"experience": map[string]any{"type": "string", "const": "popup_button"}, "button": buttonOutput}),
	}}
	nonce := text(43, 43)
	nonce["pattern"] = "^[A-Za-z0-9_-]{43}$"
	flowID := text(22, 22)
	flowID["pattern"] = "^[A-Za-z0-9_-]{22}$"
	success := object([]string{"clientId", "nonce", "flowId", "expiresAt", "options"}, map[string]any{"clientId": text(1, 1024), "nonce": nonce, "flowId": flowID, "expiresAt": map[string]any{"type": "string", "format": "date-time"}, "options": options})
	failure := object([]string{"error"}, map[string]any{"error": enum("invalid_request", "denied", "https_required", "conflict", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable")})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store/nosniff JSON with Referrer-Policy: no-referrer. No raw native result or credential in JSON.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{
		"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"},
	}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"type": "string", "const": "POST"}}}
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Exactly the original reveal-once __Host-identity_flow credential after a fresh exact committed Start. Secure, HttpOnly, host-only, Path=/, SameSite=Lax, original expiry and bounded remaining Max-Age. Never replay, unknown outcome, error, device renewal or session issuance.", "schema": text(1, 4096)}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known shared provider/IP denial, rounded up to bounded whole seconds. Absent on unavailable authority; not permission to restart an unknown command.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	definition, _ := json.Marshal(map[string]any{
		"operationId": "identity.oauth.onetap-start",
		"description": "Explicit anonymous Google One Tap prompt OR popup-button start. Exact HTTPS host-mapped tenant and configured Origin; one Idempotency-Key and existing signed browser Device. A valid singleton ambient flow cookie does not select or authorize Start; only a fresh accepted result may replace it. No provider/client/callback override, hints, user information, redirect or UI. Shared provider/IP admission precedes one synchronous native Start. Only this invocation's fresh committed result delivers its detached options and original flow cookie. Replay and unknown commitment reveal nothing; lost acknowledgement never triggers transport retry, reissue or restart. GIS script/CSP/COOP integration remains the consumer's responsibility; this route supplies neither UI nor callback handling.",
		"security":    []any{map[string]any{"OneTapStartDevice": []string{}}},
		"parameters": []any{
			map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "const": string(c.Origin)}},
			map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": text(1, 256)},
		},
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}},
		"responses":   responses,
	})
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Original signed same-tenant, same-origin non-authenticating browser correlation. This route requires it and never issues or renews it."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "OneTapStartDevice", Definition: scheme}}}
}
