package oauthserverhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-oauth-server/device"
)

func deviceWireText(maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
}

func deviceWireObject(required []string, properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}

func deviceWireSecret() map[string]any {
	return map[string]any{"type": "string", "minLength": 43, "maxLength": 43, "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"}
}

func deviceWireUserCode(canonical bool) map[string]any {
	if canonical {
		return map[string]any{"type": "string", "minLength": 9, "maxLength": 9, "pattern": "^[BCDFGHJKLMNPQRSTVWXZ23456789]{4}-[BCDFGHJKLMNPQRSTVWXZ23456789]{4}$", "readOnly": true}
	}
	return map[string]any{"type": "string", "minLength": 8, "maxLength": 9, "pattern": "^[BCDFGHJKLMNPQRSTVWXZbcdfghjklmnpqrstvwxz23456789]{4}-?[BCDFGHJKLMNPQRSTVWXZbcdfghjklmnpqrstvwxz23456789]{4}$", "writeOnly": true}
}

// deviceOperationWire derives the selected browser cookie component from the
// same policy as the handler. The first browser operation owns that component;
// the first protocol operation owns the existing shared Basic component.
func deviceOperationWire(action string, browser *DeviceConsentConfig, first bool) (*identityhttp.WireOperation, error) {
	if action == "device-authorize" {
		if browser != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		return deviceAuthorizationWire(first), nil
	}
	if browser == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := browser.SessionCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	method := "POST"
	var success any
	definition := map[string]any{
		"operationId": "identity.oauth-server." + action,
		"security":    []any{map[string]any{"OAuthDeviceSessionCookie": []string{}}},
		"description": "Selected secure host-cookie profile only; Authorization and Proxy-Authorization are forbidden. The native device service authenticates the current recent human session and retains all subject, tenant, consent and transactional CSRF authority. No bearer fallback, caller-supplied subject/proof, Idempotency-Key, session issuance or automatic recovery. Responses are bounded no-store projections, never device/access/refresh credentials or internal diagnostics.",
	}
	switch action {
	case "device-inspect":
		method = "GET"
		definition["parameters"] = []any{map[string]any{"name": "user_code", "in": "query", "required": true, "schema": deviceWireUserCode(false), "description": "The sole query parameter; GET bodies, Content-Type and X-CSRF-Token are forbidden. The submitted code is never echoed in errors."}}
		success = deviceWireObject([]string{"canonical_user_code", "client_display_name", "scopes", "resources", "expires_at"}, map[string]any{
			"canonical_user_code": deviceWireUserCode(true), "client_display_name": deviceWireText(128),
			"scopes":     map[string]any{"type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": deviceWireText(128)},
			"resources":  map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": deviceWireText(2048)},
			"expires_at": map[string]any{"type": "string", "format": "date-time"},
		})
	case "device-approve", "device-deny":
		properties := map[string]any{"user_code": deviceWireUserCode(false)}
		required := []string{"user_code"}
		state := "denied"
		if action == "device-approve" {
			properties["confirmed_user_code"] = deviceWireUserCode(false)
			required = append(required, "confirmed_user_code")
			state = "approved"
		}
		jsonBody := deviceWireObject(required, properties)
		formProperties := map[string]any{}
		for name, schema := range properties {
			formProperties[name] = schema
		}
		csrf := deviceWireSecret()
		csrf["writeOnly"] = true
		formProperties["csrf_token"] = csrf
		definition["parameters"] = []any{
			map[string]any{"name": "Origin", "in": "header", "required": true, "schema": deviceWireText(2048), "description": "Exact selected HTTPS issuer origin; Referer fallback is denied."},
			map[string]any{"name": "X-CSRF-Token", "in": "header", "required": false, "schema": csrf, "description": "Required for JSON. Form requests require exactly one header OR csrf_token field, never both, including equal values. Native mutation validates the token against the same active session transactionally."},
		}
		definition["requestBody"] = map[string]any{"required": true, "description": "Closed bounded JSON or URL-encoded body; query parameters are forbidden. Approval requires a separate explicit confirmed_user_code matching the displayed canonical code; a complete verification URI supplies no confirmation. CSRF header/form exclusivity cannot be expressed by the body schema alone.", "content": map[string]any{
			"application/json":                  map[string]any{"schema": jsonBody},
			"application/x-www-form-urlencoded": map[string]any{"schema": deviceWireObject(required, formProperties)},
		}}
		command := map[string]any{"type": "string", "minLength": 22, "maxLength": 22, "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
		fresh := deviceWireObject([]string{"outcome", "command_id", "replayed"}, map[string]any{
			"outcome": map[string]any{"const": "committed"}, "command_id": command, "replayed": map[string]any{"const": false},
		})
		completion := fresh
		if action == "device-deny" {
			replay := deviceWireObject([]string{"outcome", "replayed"}, map[string]any{
				"outcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"const": true},
			})
			completion = map[string]any{"oneOf": []any{fresh, replay}}
		}
		success = deviceWireObject([]string{"state", "completion"}, map[string]any{"state": map[string]any{"const": state}, "completion": completion})
	default:
		return nil, identityhttp.ErrInvalidInput
	}
	definition["responses"] = deviceWireResponses(success, method, true)
	data, _ := json.Marshal(definition) // Only static JSON values and validated cookie text are composed here.
	wire := &identityhttp.WireOperation{Definition: data}
	if first {
		scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Exactly the selected secure HttpOnly host-only session cookie. Native current recent human-session authentication is required; no Authorization or bearer fallback."})
		wire.SecuritySchemes = []identityhttp.WireComponent{{Name: "OAuthDeviceSessionCookie", Definition: scheme}}
	}
	return wire, nil
}

func deviceAuthorizationWire(first bool) *identityhttp.WireOperation {
	success := deviceWireObject([]string{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"}, map[string]any{
		"device_code": deviceWireSecret(), "user_code": deviceWireUserCode(true), "verification_uri": deviceWireText(2048), "verification_uri_complete": deviceWireText(2048),
		"expires_in": map[string]any{"type": "integer", "minimum": 0, "maximum": 900}, "interval": map[string]any{"type": "integer", "minimum": 5, "maximum": 60},
	})
	definition := map[string]any{
		"operationId": "identity.oauth-server.device-authorize",
		"description": "RFC8628 device authorization on the exact selected HTTPS issuer. Bounded URL-encoded body only; query parameters and Idempotency-Key are forbidden. Public clients require body client_id and no Authorization; confidential clients require exactly one client_secret_basic header and forbid body client_id. Proxy-Authorization and alternative client secrets are forbidden. Native admission verifies explicit current device-client permission before generation and issuance. Unknown extension form parameters are ignored, never treated as network or subject authority. Only a fresh known-committed authorization reveals codes; no command identifiers or recovery secrets are emitted.",
		"security":    []any{map[string]any{}, map[string]any{"OAuthWorkloadBasic": []string{}}},
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{"oneOf": []any{deviceClientForm(false, true), deviceClientForm(false, false)}}}}},
		"responses":   deviceWireResponses(success, "POST", false),
	}
	data, _ := json.Marshal(definition)
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: operationWire("token", first).SecuritySchemes}
}

// deviceClientForm retains the native parser's public-none/Basic distinction
// and ignored extension parameters. Known credential/grant overrides remain
// forbidden rather than accidentally accepted as future protocol extensions.
func deviceClientForm(poll, public bool) map[string]any {
	properties := map[string]any{"client_id": deviceWireText(128)}
	required := []string{}
	forbidden := []string{"client_secret", "client_assertion", "client_assertion_type", "subject", "tenant_id", "user_id", "redirect_uri", "code", "code_verifier", "refresh_token"}
	if poll {
		properties["grant_type"] = map[string]any{"const": device.GrantType}
		properties["device_code"] = deviceWireSecret()
		required = append(required, "grant_type", "device_code")
		forbidden = append(forbidden, "scope", "resource")
	} else {
		// Native ParseDeviceRequest treats an empty scope/resource exactly as
		// omission, selecting the registered ceiling and sole resource.
		properties["scope"] = map[string]any{"type": "string", "maxLength": 4096}
		properties["resource"] = map[string]any{"type": "string", "maxLength": 2048}
		forbidden = append(forbidden, "grant_type", "device_code")
	}
	if public {
		required = append(required, "client_id")
	} else {
		forbidden = append(forbidden, "client_id")
	}
	denied := make([]any, 0, len(forbidden))
	for _, name := range forbidden {
		denied = append(denied, map[string]any{"required": []string{name}})
	}
	return map[string]any{"type": "object", "properties": properties, "required": required, "maxProperties": 32, "propertyNames": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[!-~]+$"}, "additionalProperties": map[string]any{"type": "string", "maxLength": 4096}, "not": map[string]any{"anyOf": denied}}
}

// tokenWireWithDevice extends the existing token definition only when device
// polling is selected. The ordinary workload-only definition remains untouched.
func tokenWireWithDevice(workload, first bool) *identityhttp.WireOperation {
	wire := operationWire("token", first)
	var definition map[string]any
	_ = json.Unmarshal(wire.Definition, &definition) // operationWire emits only the known static object above.
	requestMedia := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/x-www-form-urlencoded"].(map[string]any)
	requests := []any{deviceClientForm(true, true), deviceClientForm(true, false)}
	if workload {
		requests = append(requests, requestMedia["schema"])
	}
	requestMedia["schema"] = map[string]any{"oneOf": requests}
	definition["description"] = "One exact OAuth token endpoint with explicitly selected grant variants. The RFC8628 device grant permits public-none with body client_id OR exclusive client_secret_basic with no body client_id; the native device owner authenticates each current device client and atomically enforces polling/consumption policy. Scope/resource overrides are forbidden for device polling. If selected, client_credentials retains its existing Basic-only confidential-workload profile and access-only response. OpenAPI operation security cannot condition authentication on grant_type; the public alternative never permits unauthenticated workload issuance. Bounded form only; no query parameters, Proxy-Authorization, Idempotency-Key, cookie authority, code/refresh/exchange grants or automatic recovery. No command identifiers, ID tokens or issued_token_type are emitted. Pending/slow_down/denied/expired responses disclose no credentials."
	definition["security"] = []any{map[string]any{}, map[string]any{"OAuthWorkloadBasic": []string{}}}
	deviceResult := deviceWireObject([]string{"access_token", "token_type", "expires_in", "scope"}, map[string]any{
		"access_token": deviceWireSecret(), "refresh_token": deviceWireSecret(), "token_type": map[string]any{"const": "Bearer"},
		"expires_in": map[string]any{"type": "integer", "minimum": 0, "maximum": 300}, "scope": deviceWireText(2063),
	})
	var success any = deviceResult
	if workload {
		workloadResult := definition["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"]
		// Device responses without refresh tokens overlap workload responses.
		// anyOf preserves both real shapes without rejecting that intersection.
		success = map[string]any{"anyOf": []any{workloadResult, deviceResult}}
	}
	definition["responses"] = deviceWireResponses(success, "POST", false)
	wire.Definition, _ = json.Marshal(definition)
	return wire
}

func deviceWireResponses(success any, method string, browser bool) map[string]any {
	codes := map[string][]string{
		"400": {"invalid_request", "invalid_grant", "invalid_scope", "unsupported_grant_type", "authorization_pending", "slow_down", "access_denied", "expired_token"},
		"401": {"invalid_client"}, "403": {"https_required"}, "404": {"invalid_request", "not_found"},
		"405": {"invalid_request", "method_not_allowed"}, "421": {"invalid_request", "misdirected_request"},
		"429": {"temporarily_unavailable"}, "503": {"temporarily_unavailable", "unavailable"},
	}
	if browser {
		codes["403"] = append(codes["403"], "origin_or_csrf_denied")
	}
	responses := map[string]any{"200": map[string]any{"description": "Bounded no-store success projection from the selected native operation.", "content": map[string]any{"application/json": map[string]any{"schema": success}}}}
	for status, values := range codes {
		schema := deviceWireObject([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": values}})
		responses[status] = map[string]any{"description": "Redacted no-store operation failure or shared transport denial; no input credentials or internal diagnostics.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["401"].(map[string]any)["headers"] = map[string]any{"WWW-Authenticate": map[string]any{"schema": map[string]any{"const": `Basic realm="oauth2"`}}}
	responses["405"].(map[string]any)["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"const": method}}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Retry delay in whole seconds, bounded to1..3600.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	return responses
}
