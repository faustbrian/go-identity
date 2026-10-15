package mfahttp

import (
	"encoding/json"
	"slices"

	auth "github.com/faustbrian/go-authentication/v2"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func stepUpWire(c ActiveStepUpConfig) *identityhttp.WireOperation {
	wire := confirmationWire(EnrollmentConfirmationConfig{Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins})
	var d map[string]any
	_ = json.Unmarshal(wire.Definition, &d)
	d["description"] = "Explicit authenticated TOTP step-up requires singleton X-MFA-Variant: step-up and original cookie/Origin/CSRF. Fixed original native quota and observation deadlines precede atomic code/replay/proof verification. Only a fresh known commit reveals an exact action-bound proofID; replay, ambiguity and expiry never redeliver. Body purpose must be selected by startup policy; omission means regeneration only when selected. No login, enrollment, arbitrary purpose/subject override or session issuance."
	purposes := c.Purposes
	if len(purposes) == 0 {
		purposes = []auth.Purpose{"identity.mfa.recovery-regenerate"}
	}
	body := d["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	body["properties"].(map[string]any)["purpose"] = map[string]any{"type": "string", "enum": purposes}
	if !slices.Contains(purposes, auth.Purpose("identity.mfa.recovery-regenerate")) {
		body["required"] = append(body["required"].([]any), "purpose")
	}
	d["parameters"].([]any)[0].(map[string]any)["schema"] = map[string]any{"const": "step-up"}
	responses := d["responses"].(map[string]any)
	var rename func(any)
	rename = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if p, ok := v["properties"].(map[string]any); ok {
				if field, found := p["activated"]; found {
					delete(p, "activated")
					p["verified"] = field
				}
			}
			if required, ok := v["required"].([]any); ok {
				for i, x := range required {
					if x == "activated" {
						required[i] = "verified"
					}
				}
			}
			for _, child := range v {
				rename(child)
			}
		case []any:
			for _, child := range v {
				rename(child)
			}
		}
	}
	rename(responses)
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	responses["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"] = map[string]any{"type": "object", "additionalProperties": false, "required": []string{"verified", "commitOutcome", "commandID", "proofID"}, "properties": map[string]any{"verified": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "proofID": id}}
	wire.Definition, _ = json.Marshal(d)
	return wire
}

func selectedVerifyWire(c FeatureConfig) *identityhttp.WireOperation {
	if c.ActiveStepUp == nil {
		return selectedBaseVerifyWire(c)
	}
	active := stepUpWire(*c.ActiveStepUp)
	if c.TOTPVerify == nil && c.PasswordTOTPVerify == nil && c.EnrollmentConfirmation == nil {
		return active
	}
	base := selectedBaseVerifyWire(c)
	var a, b map[string]any
	_ = json.Unmarshal(base.Definition, &a)
	_ = json.Unmarshal(active.Definition, &b)
	a["description"] = a["description"].(string) + " " + b["description"].(string)
	a["security"] = append(a["security"].([]any), b["security"].([]any)...)
	content := func(v any) map[string]any {
		return v.(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	}
	// Enrollment and step-up have the same body shape: only the explicit header
	// selects authority. oneOf would incorrectly reject that shared shape.
	content(a["requestBody"])["schema"] = map[string]any{"anyOf": []any{content(a["requestBody"])["schema"], content(b["requestBody"])["schema"]}}
	responses := a["responses"].(map[string]any)
	for status, value := range b["responses"].(map[string]any) {
		if old, ok := responses[status]; ok {
			content(old)["schema"] = map[string]any{"anyOf": []any{content(old)["schema"], content(value)["schema"]}}
		} else {
			responses[status] = value
		}
	}
	parameters := a["parameters"].([]any)
	variantFound, csrfFound := false, false
	for _, value := range parameters {
		p := value.(map[string]any)
		switch p["name"] {
		case "X-MFA-Variant":
			variantFound = true
			values := []string{"step-up"}
			if c.EnrollmentConfirmation != nil {
				values = append(values, "enrollment")
			}
			if c.PasswordTOTPVerify != nil {
				values = append(values, "password")
			}
			p["schema"] = map[string]any{"type": "string", "enum": values}
			p["required"] = c.TOTPVerify == nil && c.PasswordTOTPVerify == nil
		case "X-CSRF-Token":
			csrfFound = true
		case "Origin":
			values := slices.Clone(c.ActiveStepUp.TrustedOrigins)
			if c.EnrollmentConfirmation != nil {
				for _, origin := range c.EnrollmentConfirmation.TrustedOrigins {
					if !slices.Contains(values, origin) {
						values = append(values, origin)
					}
				}
			}
			for _, login := range []*TOTPVerifyConfig{c.TOTPVerify, c.PasswordTOTPVerify} {
				if login != nil && !slices.Contains(values, login.Origin) {
					values = append(values, login.Origin)
				}
			}
			p["schema"] = map[string]any{"type": "string", "enum": values}
		}
	}
	if !variantFound {
		parameters = append(parameters, map[string]any{"name": "X-MFA-Variant", "in": "header", "required": false, "schema": map[string]any{"const": "step-up"}})
	}
	if !csrfFound {
		parameters = append(parameters, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": false, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}})
	}
	a["parameters"] = parameters
	base.Definition, _ = json.Marshal(a)
	// Both authenticated variants use the exact same named cookie scheme.
	for _, scheme := range active.SecuritySchemes {
		if !slices.ContainsFunc(base.SecuritySchemes, func(x identityhttp.WireComponent) bool { return x.Name == scheme.Name }) {
			base.SecuritySchemes = append(base.SecuritySchemes, scheme)
		}
	}
	return base
}
