package sessionhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// The integration owns these wire schemas beside the concrete projections.
// Domain opaque types and runtime configuration must never become JSON schemas
// through reflection. No origin, host, key or tenant configuration is exported.
func sessionWire(c SignOutConfig, logout bool) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	boolean := map[string]any{"type": "boolean"}
	date := map[string]any{"type": "string", "format": "date-time"}
	errorSchema := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable", "origin_denied", "denied", "conflict", "in_progress"}}})
	principal := object([]string{"tenantID", "userID"}, map[string]any{"tenantID": text(256), "userID": text(256)})
	state := object([]string{"id", "issuedAt", "lastActivityAt", "expiresAt", "absoluteExpiresAt"}, map[string]any{"id": text(256), "issuedAt": date, "lastActivityAt": date, "expiresAt": date, "absoluteExpiresAt": date})
	success := any(map[string]any{"oneOf": []any{
		object([]string{"authenticated", "needsRefresh"}, map[string]any{"authenticated": map[string]any{"const": false}, "needsRefresh": map[string]any{"const": false}}),
		object([]string{"authenticated", "needsRefresh", "principal", "session", "refreshEligibleAt"}, map[string]any{"authenticated": map[string]any{"const": true}, "needsRefresh": boolean, "principal": principal, "session": state, "refreshEligibleAt": date}),
	}})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "Credential-free JSON. Cache-Control: no-store; X-Content-Type-Options: nosniff.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	id := "identity.session.get"
	description := "Exact GET; no body, query, trailers or Idempotency-Key. Credentials are optional: absent/inactive returns unauthenticated metadata. No mutation, cookie emission or authority renewal."
	statuses := []string{"400", "404", "405", "421", "429", "503"}
	if logout {
		id = "identity.session.signout"
		description = "Exact POST; no query, trailers, client command identity or Idempotency-Key. Content-Type must select strict JSON {} or URL-encoded form, which may be empty. Present security headers/fields are singleton; duplicates and mixed CSRF sources deny. Only confirmed error-free success clears the selected transport. Unknown outcome never retries or clears credentials; original command/recovery remains visible."
		recovery := object([]string{"commandID", "tenantID", "actorID", "actorKind", "operationID"}, map[string]any{"commandID": text(22), "tenantID": text(256), "userID": text(256), "anonymousFlowID": text(256), "actorID": text(256), "actorKind": text(256), "operationID": text(128), "recordID": text(256), "linkMode": map[string]any{"type": "integer", "minimum": 1, "maximum": 3}})
		properties := map[string]any{"signedOut": boolean, "clearBearer": boolean, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "commandID": text(22), "recovery": recovery, "error": errorSchema["properties"].(map[string]any)["error"]}
		successProperties := map[string]any{}
		for k, v := range properties {
			if k != "error" {
				successProperties[k] = v
			}
		}
		successProperties["signedOut"] = map[string]any{"const": true}
		successProperties["clearBearer"] = map[string]any{"const": c.Transport == session.CredentialBearer}
		successProperties["commitOutcome"] = map[string]any{"type": "string", "enum": []string{"none", "committed"}}
		properties["signedOut"] = map[string]any{"const": false}
		properties["clearBearer"] = map[string]any{"const": false}
		success = object([]string{"signedOut", "clearBearer", "commitOutcome"}, successProperties)
		errorSchema = map[string]any{"oneOf": []any{errorSchema, object([]string{"signedOut", "clearBearer", "commitOutcome", "error"}, properties)}}
		statuses = append(statuses, "403", "409")
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range statuses {
		responses[status] = response(errorSchema)
	}
	retry := map[string]any{"description": "Whole seconds until retry admission; no automatic replay.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": retry}
	if logout {
		responses["409"].(map[string]any)["headers"] = map[string]any{"Retry-After": retry}
	}
	schemeName := "SessionBearer"
	scheme := map[string]any{"type": "http", "scheme": "bearer", "description": "Optional single strict Authorization: Bearer credential. Ambient cookies are ignored; no fallback."}
	if c.Transport == session.CredentialCookie {
		cookie, _ := c.Cookie.DeletionAttributes()
		schemeName = "SessionCookie"
		scheme = map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Optional selected secure host-only cookie. Authorization header is forbidden; no credential fallback."}
	}
	definition := map[string]any{"operationId": id, "description": description, "security": []any{map[string]any{}, map[string]any{schemeName: []string{}}}, "responses": responses}
	if logout {
		empty := object([]string{}, map[string]any{})
		form := object([]string{}, map[string]any{})
		if c.Transport == session.CredentialCookie {
			token := map[string]any{"type": "string", "minLength": 43, "maxLength": 43, "pattern": "^[A-Za-z0-9_-]{43}$"}
			form["properties"].(map[string]any)["csrf_token"] = token
			definition["parameters"] = []any{
				map[string]any{"name": "Origin", "in": "header", "required": true, "description": "Exact trusted HTTPS origin; Referer fallback denied. No origin values are exported.", "schema": text(2048)},
				map[string]any{"name": "X-CSRF-Token", "in": "header", "required": false, "description": "Current primary session-bound synchronizer token required when active; optional only for absent/inactive logout. Exactly one header OR form field, never both. No independent maximum-age claim.", "schema": token},
			}
			responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Exact configured Secure/HttpOnly host-cookie deletion tuple on confirmed success only; no credential disclosure.", "schema": text(4096)}}
		} else {
			definition["description"] = description + " Bearer mode rejects X-CSRF-Token and csrf_token; ambient cookies confer no authority and are never deleted."
		}
		definition["requestBody"] = map[string]any{"required": false, "description": "JSON object must be {}; form may be empty. Content-Type is mandatory even for an empty form. Only cookie mode permits csrf_token; schema cannot express header/form exclusivity or active-state conditional authority.", "content": map[string]any{"application/json": map[string]any{"schema": empty}, "application/x-www-form-urlencoded": map[string]any{"schema": form}}}
	}
	data, _ := json.Marshal(definition)
	wire := &identityhttp.WireOperation{Definition: data}
	// The shared scheme is declared once, by get. Signout uses its reference.
	if !logout {
		data, _ = json.Marshal(scheme)
		wire.SecuritySchemes = []identityhttp.WireComponent{{Name: schemeName, Definition: data}}
	}
	return wire
}
