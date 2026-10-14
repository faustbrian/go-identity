package passwordhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// The HTTP projection is intentionally separate from native proof authority and
// direct contract summaries. No reflected configuration or signing record enters
// the document. Character bounds supplement, not replace, transport byte budgets.
func verificationWire(c BearerVerificationConfig, device bool) *identityhttp.WireOperation {
	object := func(required []string, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	target := func(maximum int) any {
		return map[string]any{"type": "string", "pattern": "^[!-~]+$", "minLength": 1, "maxLength": maximum}
	}
	command := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"}
	timestamp := map[string]any{"type": "string", "format": "date-time"}
	proof := object([]string{"proofID", "purpose", "action", "audience", "issuedAt", "expiresAt"}, map[string]any{"proofID": command, "purpose": target(128), "action": target(128), "audience": target(256), "issuedAt": timestamp, "expiresAt": timestamp})
	success := object([]string{"verified", "proof", "commandID", "commitOutcome"}, map[string]any{"verified": map[string]any{"const": true}, "proof": proof, "commandID": command, "commitOutcome": map[string]any{"const": "committed"}})
	code := map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_denied", "https_required", "denied", "rate_limited", "unavailable"}}
	attempt := object([]string{"verified", "commitOutcome", "error"}, map[string]any{"verified": map[string]any{"const": false}, "commandID": command, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "error": code})
	attempt["allOf"] = []any{map[string]any{"if": map[string]any{"properties": map[string]any{"commitOutcome": map[string]any{"enum": []string{"not_committed", "committed", "unknown", "conflict", "in_progress"}}}}, "then": map[string]any{"required": []string{"commandID"}}}}
	failure := map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": code}), attempt}}
	response := func(schema any) any {
		return map[string]any{"description": "No-store/nosniff. Original command observations do not authorize retry or proof recovery. No cookies, CSRF, bearer or signing record.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Known bounded whole seconds; no automatic retry after ambiguous work.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission; no native verification.", "content": map[string]any{"text/plain": plain}}
	request := object([]string{"password", "purpose", "action", "audience"}, map[string]any{"password": map[string]any{"type": "string", "minLength": 1, "maxLength": min(c.Network.Limits.MaximumDecodedBytes, uint64(1<<20)), "writeOnly": true}, "purpose": target(128), "action": target(128), "audience": target(256)})
	definition := map[string]any{"operationId": "identity.password.verify", "description": "Explicit strict bearer profile only; ambient cookies ignored, CSRF alternatives and Idempotency-Key forbidden. Closed JSON contains exactly password and purpose/action/audience; native startup allowlisting is authoritative. No subject/tenant/proof/lifetime/assurance overrides. Password bytes are unchanged and raw/decoded transport byte budgets remain enforced. One original primary observation, atomic IP/subject admission and one native verification invocation; each attempt is a fresh command, not keyed or automatically retried. Only fresh error-free known commit delivers the original proof locator/target/timing projection. Protected operations load the original signed record; this projection grants no authority. Errors, including committed errors, never deliver proof or credentials.", "security": []any{map[string]any{"PasswordVerificationBearer": []string{}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}}, "responses": responses}
	scheme := map[string]any{"type": "http", "scheme": "bearer", "description": "Exactly one strict Authorization: Bearer session credential; no cookie or CSRF fallback."}
	data, _ := json.Marshal(definition)
	security, _ := json.Marshal(scheme)
	wire := &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "PasswordVerificationBearer", Definition: security}}}
	if device {
		definition["description"] = "Explicit device-bound bearer verification. Authorization is the sole session credential; the dedicated __Host-identity_device cookie supplies only signed server-random correlation, not account/MFA/hardware authority. Original namespace/tenant/effective HTTPS origin/expiry are checked before native work and before proof delivery, never renewed or issued here. All other ambient cookies are ignored. Closed unchanged password/purpose/action/audience input; no raw device, identity, expiry or key override. Native startup target policy, original primary validity, counted native Authentication risk and atomic proof/audit/outbox remain authoritative. Failures and ambiguous/committed errors never deliver proof or credentials; no automatic retry. Raw and decoded byte budgets remain enforced."
		definition["security"] = []any{map[string]any{"PasswordVerificationBearer": []string{}, "PasswordVerificationBrowserDevice": []string{}}}
		wire.Definition, _ = json.Marshal(definition)
		correlation, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Required original signed auxiliary correlation from configured initialization; never session authentication or MFA/hardware trust. No replacement issuance or expiry renewal."})
		wire.SecuritySchemes = append(wire.SecuritySchemes, identityhttp.WireComponent{Name: "PasswordVerificationBrowserDevice", Definition: correlation})
	}
	return wire
}

func cookieVerificationWire(c CookieVerificationConfig) *identityhttp.WireOperation {
	wire := verificationWire(BearerVerificationConfig{Network: c.Network}, false)
	var definition map[string]any
	_ = json.Unmarshal(wire.Definition, &definition)
	definition["description"] = "Exclusive protected cookie verification: original configured secure session cookie, exact trusted HTTPS Origin without Referer fallback, sole X-CSRF-Token header and original signed browser-device correlation are required. No bearer, body/query/trailer alternatives, retry key, issuance or renewal. Closed unchanged password/purpose/action/audience input, original primary validity and atomic IP/subject admission precede one native cookie transaction. Only fresh error-free known commit delivers the original proof projection; failures retain valid original command observations without proof or automatic retry. Raw/decoded transport byte budgets remain enforced."
	definition["security"] = []any{map[string]any{"PasswordVerificationSessionCookie": []string{}, "PasswordVerificationCSRF": []string{}, "PasswordVerificationBrowserDevice": []string{}}}
	wire.Definition, _ = json.Marshal(definition)
	cookie, _ := c.Cookie.DeletionAttributes()
	wire.SecuritySchemes = nil
	for _, item := range []struct{ name, location, wireName, description string }{
		{"PasswordVerificationSessionCookie", "cookie", cookie.Name, "Original configured secure session credential; Authorization alternatives are forbidden."},
		{"PasswordVerificationCSRF", "header", "X-CSRF-Token", "Exactly one original session synchronizer, protected by the native transaction owner; not body or query input."},
		{"PasswordVerificationBrowserDevice", "cookie", "__Host-identity_device", "Original signed tenant/origin-bound browser correlation; never session or MFA authority, issuance or renewal."},
	} {
		data, _ := json.Marshal(map[string]any{"type": "apiKey", "in": item.location, "name": item.wireName, "description": item.description})
		wire.SecuritySchemes = append(wire.SecuritySchemes, identityhttp.WireComponent{Name: item.name, Definition: data})
	}
	return wire
}
