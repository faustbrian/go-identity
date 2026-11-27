package oauthhttp

import (
	"encoding/json"
	"fmt"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewOneTapRedirectCallbackFeature selects only exact POST
// /v1/oauth/onetap-callback under identity/oauth/onetap, with the Google HTML
// form contract and original frontchannel-cookie authority. It is an alternative
// to NewOneTapCallbackFeature, not an additional route: selecting both collides.
// The router requires explicit CORSOneTapRedirectNavigation policy for this
// bound-origin operation; sender Origin/Referer cannot replace original proof.
// Configuration validation and handler ownership match
// NewOneTapRedirectCallbackHandler. Construction performs no I/O.
func NewOneTapRedirectCallbackFeature(c OneTapRedirectCallbackConfig) (identityhttp.Feature, error) {
	h, err := NewOneTapRedirectCallbackHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", Handler: h,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFBoundOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 16384,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = oneTapRedirectCallbackWire(c)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth/onetap", Operations: []identityhttp.OperationDescriptor{op}})
}

func oneTapRedirectCallbackWire(c OneTapRedirectCallbackConfig) *identityhttp.WireOperation {
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
	response := func(description string, schema any) map[string]any {
		return map[string]any{"description": description, "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
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
		responses[outcome.status] = response("No cookies, redirects or serialized credentials. No-store stable redacted failure.", failure(outcome.codes...))
	}
	responses["503"].(map[string]any)["description"] = "No cookies, redirects or serialized credentials. No-store unavailable result includes replay, unknown commit, cancellation and expired original delivery authority; completion is never retried here."
	// NewRouter retains its fixed CORS-envelope denial before entering the leaf.
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"const": "POST"}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known shared provider/IP denial, rounded up to bounded seconds. This does not authorize replaying completion.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	responses["200"] = response("No-store signed_in only after a fresh accepted native commit and successful cookie delivery. Credentials are never serialized into JSON.", map[string]any{"type": "object", "additionalProperties": false, "required": []string{"status"}, "properties": map[string]any{"status": map[string]any{"const": "signed_in"}}})
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Exactly two separate fields: the native secure host-only HttpOnly session cookie and readable synchronizer cookie. Original Remember choice, expiry and DeliveryValidUntil are preserved. No frontchannel, device or Google cookie is issued, rotated or cleared.", "schema": text(1, 8192)}}
	state := text(22, 22)
	state["pattern"] = "^[A-Za-z0-9_-]{21}[AQgw]$"
	state["description"] = "Canonical unpadded base64url 16-byte native preauth transaction ID, used only as a locator."
	googleCSRF := secret(1, 1024)
	googleCSRF["description"] = "One opaque RFC6265 cookie-octet value exactly matching the original unquoted g_csrf_token cookie."
	definition := map[string]any{
		"operationId": "identity.oauth.onetap-callback",
		"description": "Selected existing-account Google HTML redirect callback only, not popup JSON. Exact trusted HTTPS tenant endpoint, original path-bound frontchannel cookie, canonical form state and Google double-submit cookie/body pair precede native completion. Sender Origin/Referer and unknown form values confer no authority. No caller device, Authorization, Idempotency-Key, header CSRF, query, signup, linking, MFA or JWT-claim alternatives. Shared provider/IP admission is transport-owned; native completion owns provider verification, counted risk and the one-use transaction. Only fresh exact accepted session and CSRF cookie delivery returns signed_in; replay and nondelivery fail closed without credentials or redirects.",
		"security":    []any{map[string]any{"OneTapRedirectCallbackFrontchannel": []string{}, "OneTapRedirectCallbackGoogleCSRF": []string{}}},
		"requestBody": map[string]any{
			"required":    true,
			"description": fmt.Sprintf("Form body only, at most %d raw bytes, %d aggregate decoded name/value bytes and %d fields. Duplicate/case-alias names, reserved idempotency-key alternatives and malformed encoding deny. Unknown fields are tolerated within these same bounds, then ignored; they cannot replace trusted client, endpoint or device context.", c.Network.Limits.MaximumBodyBytes, c.Network.Limits.MaximumDecodedBytes, c.Network.Limits.MaximumFields),
			"content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{
				"type": "object", "additionalProperties": text(0, int(c.Network.Limits.MaximumDecodedBytes)), "maxProperties": c.Network.Limits.MaximumFields,
				"required":   []string{"state", "credential", "g_csrf_token"},
				"properties": map[string]any{"state": state, "credential": secret(1, c.Provider.MaxTokenBytes), "g_csrf_token": googleCSRF},
			}}},
		},
		"responses": responses,
	}
	wire, _ := json.Marshal(definition)
	frontchannel, _ := c.FrontchannelCookie.DeletionAttributes()
	var schemes []identityhttp.WireComponent
	for _, item := range []struct{ component, name, description string }{
		{"OneTapRedirectCallbackFrontchannel", frontchannel.Name, "One exact original native path-bound Secure, HttpOnly, SameSite=None frontchannel cookie. Form state is only a locator; a Lax flow cookie, current device or current session cannot replace this proof."},
		{"OneTapRedirectCallbackGoogleCSRF", "g_csrf_token", "One original unquoted opaque cookie value exactly matching the bounded g_csrf_token form value. Missing, duplicate, case-alias or mismatched values deny before native/provider work."},
	} {
		encoded, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": item.name, "description": item.description})
		schemes = append(schemes, identityhttp.WireComponent{Name: item.component, Definition: encoded})
	}
	return &identityhttp.WireOperation{Definition: wire, SecuritySchemes: schemes}
}
