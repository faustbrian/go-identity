package oauthserverhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func operationWire(action string, first bool) *identityhttp.WireOperation {
	text := func(maximum int) any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
	}
	object := func(required []string, fields map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	request := object([]string{"token"}, map[string]any{"token": text(2048), "token_type_hint": text(128)})
	result := any(nil)
	switch action {
	case "token":
		request = object([]string{"grant_type"}, map[string]any{"grant_type": map[string]any{"const": "client_credentials"}, "scope": text(8192), "resource": text(2048)})
		result = object([]string{"access_token", "token_type", "expires_in", "scope"}, map[string]any{
			"access_token": map[string]any{"type": "string", "minLength": 43, "maxLength": 43, "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "readOnly": true},
			"token_type":   map[string]any{"const": "Bearer"}, "expires_in": map[string]any{"type": "integer", "minimum": 0, "maximum": 300}, "scope": text(8192),
		})
	case "introspect":
		inactive := object([]string{"active"}, map[string]any{"active": map[string]any{"const": false}})
		active := object([]string{"active"}, map[string]any{"active": map[string]any{"const": true}, "client_id": text(128), "sub": text(128), "aud": text(2048), "iss": text(2048), "scope": text(8192), "exp": map[string]any{"type": "integer"}})
		result = map[string]any{"oneOf": []any{inactive, active}}
	}
	// The shared router can deny before the OAuth pipeline. Its transport
	// vocabulary/media remain distinct; the feature must not rewrite them.
	errorSchema := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "invalid_client", "invalid_grant", "invalid_scope", "unsupported_grant_type", "temporarily_unavailable", "https_required", "not_found", "method_not_allowed", "misdirected_request", "unavailable"}}})
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "401", "403", "404", "405", "421", "429", "503"} {
		response := map[string]any{"description": "Bounded no-store OAuth response or shared transport denial; no input credentials, native command identifiers or internal diagnostics."}
		schema := errorSchema
		if status == "200" {
			schema = result
		}
		if schema != nil {
			response["content"] = map[string]any{"application/json": map[string]any{"schema": schema}}
		}
		responses[status] = response
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["401"].(map[string]any)["headers"] = map[string]any{"WWW-Authenticate": map[string]any{"schema": map[string]any{"const": `Basic realm="oauth2"`}}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"const": "POST"}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	wire, _ := json.Marshal(map[string]any{
		"operationId": "identity.oauth-server." + action,
		"description": "Explicit confidential-workload profile. Exactly one RFC6749 client_secret_basic header, bounded form-only input and trusted issuer HTTPS origin. Native current-client authentication precedes the shared client rate budget; the final native operation rechecks authority independently. No cookies, Idempotency-Key, body/query client credentials, private/standard exchange, code/refresh/device issuance, consumer-written stores or automatic recovery. Inactive introspection exposes only active=false; revocation of an unknown token is non-enumerating native success. Nonfresh/unknown token outcomes disclose no credentials.",
		"security":    []any{map[string]any{"OAuthWorkloadBasic": []string{}}},
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": request}}},
		"responses":   responses,
	})
	out := &identityhttp.WireOperation{Definition: wire}
	if first {
		out.SecuritySchemes = []identityhttp.WireComponent{{Name: "OAuthWorkloadBasic", Definition: []byte(`{"type":"http","scheme":"basic","description":"RFC6749 section2.3.1: form-encode client identifier and secret separately before Basic encoding. Exactly one Authorization header; no alternative credential channels."}`)}}
	}
	return out
}
