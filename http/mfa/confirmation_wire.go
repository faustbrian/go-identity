package mfahttp

import (
	"encoding/json"
	"slices"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func confirmationWire(c EnrollmentConfirmationConfig) *identityhttp.WireOperation {
	object := func(required []string, p map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	success := object([]string{"activated", "commitOutcome", "commandID", "factorID", "version"}, map[string]any{"activated": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "factorID": id, "version": map[string]any{"type": "integer", "minimum": 1}})
	failure := object([]string{"activated", "commitOutcome", "error"}, map[string]any{"activated": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "unavailable", "origin_or_csrf_denied", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "conflict", "in_progress"}}})
	response := func(s any) any {
		return map[string]any{"description": "No-store original activation metadata. Never a session, provisioning URI or step-up grant.", "content": map[string]any{"application/json": map[string]any{"schema": s}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	variantError := object([]string{"error"}, map[string]any{"error": map[string]any{"const": "invalid_request"}})
	responses["400"] = response(map[string]any{"oneOf": []any{failure, variantError}})
	definition, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.totp-verify", "description": "Explicit enrollment confirmation variant requires singleton X-MFA-Variant: enrollment, original authenticated cookie, exact HTTPS Origin and native synchronizer. IP admission precedes native original enrollment custody; subject/challenge verification quotas precede atomic factor/code activation. Original deadlines cannot be renewed. No child login proof, trustDevice, subject/authority override, Authorization or Idempotency-Key. Activation does not silently promote the original session.", "security": []any{map[string]any{"MFAConfirmationSession": []string{}}}, "parameters": []any{map[string]any{"name": "X-MFA-Variant", "in": "header", "required": true, "schema": map[string]any{"const": "enrollment"}}, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "enum": c.TrustedOrigins}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object([]string{"commandID", "factorID", "code"}, map[string]any{"commandID": id, "factorID": id, "code": map[string]any{"type": "string", "minLength": 4, "maxLength": 128, "writeOnly": true}})}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Original enrollment primary session; never a newly issued MFA session."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAConfirmationSession", Definition: scheme}}}
}

func selectedBaseVerifyWire(c FeatureConfig) *identityhttp.WireOperation {
	selected := c
	if selected.TOTPVerify == nil {
		selected.TOTPVerify = selected.PasswordTOTPVerify
	}
	if selected.TOTPVerify == nil {
		selected.TOTPVerify = selected.VerificationTOTPVerify
	}
	if selected.TOTPVerify == nil {
		selected.TOTPVerify = selected.UsernameTOTPVerify
	}
	wire := combinedVerifyWire(selected)
	if c.PasswordTOTPVerify == nil && c.VerificationTOTPVerify == nil && c.UsernameTOTPVerify == nil {
		return wire
	}
	var definition map[string]any
	_ = json.Unmarshal(wire.Definition, &definition)
	if c.PasswordTOTPVerify != nil {
		definition["description"] = definition["description"].(string) + " Password-origin completion uses the selected native owner. Singleton X-MFA-Variant: password selects it; it is the default only when magic-link login is absent."
	}
	if c.VerificationTOTPVerify != nil {
		definition["description"] = definition["description"].(string) + " Registration-verification completion requires singleton X-MFA-Variant: verification and its separately selected native owner, original signup browser, confirmation and pending child. No primary fallback or new signup flow is permitted."
	}
	if c.UsernameTOTPVerify != nil {
		definition["description"] = definition["description"].(string) + " Username/password completion requires singleton X-MFA-Variant: username and its exact original native username challenge/browser. It is never a default or a fallback after another primary fails."
	}
	var variants []string
	if c.EnrollmentConfirmation != nil {
		variants = append(variants, "enrollment")
	}
	if c.PasswordTOTPVerify != nil {
		variants = append(variants, "password")
	}
	if c.VerificationTOTPVerify != nil {
		variants = append(variants, "verification")
	}
	if c.UsernameTOTPVerify != nil {
		variants = append(variants, "username")
	}
	parameters := definition["parameters"].([]any)
	found := false
	for _, parameter := range parameters {
		p := parameter.(map[string]any)
		if p["name"] == "X-MFA-Variant" {
			p["schema"] = map[string]any{"type": "string", "enum": variants}
			p["required"] = c.TOTPVerify == nil && c.PasswordTOTPVerify == nil
			found = true
		}
	}
	if !found {
		parameters = append(parameters, map[string]any{"name": "X-MFA-Variant", "in": "header", "required": c.TOTPVerify == nil && c.PasswordTOTPVerify == nil, "schema": map[string]any{"type": "string", "enum": variants}})
	}
	definition["parameters"] = parameters
	if c.VerificationTOTPVerify != nil || c.UsernameTOTPVerify != nil {
		var callbacks, origins []string
		for _, login := range []*TOTPVerifyConfig{c.TOTPVerify, c.PasswordTOTPVerify, c.VerificationTOTPVerify, c.UsernameTOTPVerify} {
			if login == nil {
				continue
			}
			if !slices.Contains(callbacks, login.CallbackURL) {
				callbacks = append(callbacks, login.CallbackURL)
			}
			if !slices.Contains(origins, string(login.Origin)) {
				origins = append(origins, string(login.Origin))
			}
		}
		if c.EnrollmentConfirmation != nil {
			for _, origin := range c.EnrollmentConfirmation.TrustedOrigins {
				if !slices.Contains(origins, string(origin)) {
					origins = append(origins, string(origin))
				}
			}
		}
		// The header selects one real owner; the shared body schema must still
		// describe every selected owner's callback, not only the default login.
		var projectCallbacks func(any)
		projectCallbacks = func(value any) {
			switch v := value.(type) {
			case map[string]any:
				if properties, ok := v["properties"].(map[string]any); ok {
					if _, exists := properties["callbackURL"]; exists {
						properties["callbackURL"] = map[string]any{"type": "string", "enum": callbacks}
					}
				}
				for _, child := range v {
					projectCallbacks(child)
				}
			case []any:
				for _, child := range v {
					projectCallbacks(child)
				}
			}
		}
		projectCallbacks(definition["requestBody"])
		for _, value := range parameters {
			p := value.(map[string]any)
			if p["name"] == "Origin" {
				p["schema"] = map[string]any{"type": "string", "enum": origins}
			}
		}
	}
	wire.Definition, _ = json.Marshal(definition)
	return wire
}

func combinedVerifyWire(c FeatureConfig) *identityhttp.WireOperation {
	if c.EnrollmentConfirmation == nil {
		return totpWire(*c.TOTPVerify)
	}
	confirmed := confirmationWire(*c.EnrollmentConfirmation)
	if c.TOTPVerify == nil {
		return confirmed
	}
	login := totpWire(*c.TOTPVerify)
	var a, b map[string]any
	_ = json.Unmarshal(login.Definition, &a)
	_ = json.Unmarshal(confirmed.Definition, &b)
	a["description"] = a["description"].(string) + " Enrollment is a distinct explicit header-selected profile: " + b["description"].(string)
	a["security"] = append(a["security"].([]any), b["security"].([]any)...)
	// Origin remains mandatory. Synchronizer is conditional on the explicit
	// enrollment header; body union never selects authentication by itself.
	a["parameters"] = append(a["parameters"].([]any), map[string]any{"name": "X-MFA-Variant", "in": "header", "required": false, "schema": map[string]any{"const": "enrollment"}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": false, "description": "Required only for enrollment; forbidden for login.", "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}})
	content := func(v any) map[string]any {
		return v.(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	}
	content(a["requestBody"])["schema"] = map[string]any{"oneOf": []any{content(a["requestBody"])["schema"], content(b["requestBody"])["schema"]}}
	responses := a["responses"].(map[string]any)
	for status, value := range b["responses"].(map[string]any) {
		if existing, ok := responses[status]; ok {
			content(existing)["schema"] = map[string]any{"anyOf": []any{content(existing)["schema"], content(value)["schema"]}}
		} else {
			responses[status] = value
		}
	}
	a["parameters"].([]any)[0].(map[string]any)["schema"] = map[string]any{"type": "string", "enum": append([]identityhttp.Origin{c.TOTPVerify.Origin}, c.EnrollmentConfirmation.TrustedOrigins...)}
	login.Definition, _ = json.Marshal(a)
	login.SecuritySchemes = append(login.SecuritySchemes, confirmed.SecuritySchemes...)
	return login
}
