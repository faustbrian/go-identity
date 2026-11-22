package ssohttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func signinCallbackWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.oidc-callback",
  "summary":"Complete an opted-in static enterprise OIDC login",
  "description":"Query-only callback for the exact configured provider and original browser flow. A fresh acknowledged commit issues secure session and CSRF cookies, then redirects to the original allowlisted URL. Refusal, replay and unresolved outcomes disclose no credentials.",
  "parameters":[{"name":"code","in":"query","required":false,"schema":{"type":"string","maxLength":4096}},{"name":"error","in":"query","required":false,"schema":{"type":"string","maxLength":256}},{"name":"state","in":"query","required":true,"schema":{"type":"string","minLength":43,"maxLength":43}},{"name":"iss","in":"query","required":true,"schema":{"type":"string","format":"uri","maxLength":2048}}],
  "responses":{"303":{"description":"Original success redirect with new credentials.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}}},"400":{"description":"Invalid query."},"403":{"description":"Callback denied."},"409":{"description":"Original callback conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no redirect or cookie."}}
}`)}
}

func signinStartWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{
		Definition: []byte(`{
  "operationId":"identity.sso.signin-start",
  "summary":"Start opted-in static enterprise OIDC sign-in",
  "description":"For the configured HTTPS tenant and provider only. Requires the original browser flow and signed device cookies and exact Origin. Keep the original command ID, request and idempotency key on retry. This operation issues no session.",
  "parameters":[{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}],
  "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["flowID","commandID","providerID","callback","errorCallback"],"properties":{"flowID":{"type":"string","minLength":22,"maxLength":22},"commandID":{"type":"string","minLength":22,"maxLength":22},"providerID":{"type":"string","minLength":1,"maxLength":128},"domain":{"type":"string","minLength":1,"maxLength":253},"callback":{"type":"string","format":"uri","maxLength":2048},"errorCallback":{"type":"string","format":"uri","maxLength":2048},"remember":{"type":"boolean"}}}}}},
  "responses":{
    "200":{"description":"Original durable authorization redirect, not a session.","content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["authorizationURL","transactionID","providerID","protocol"],"properties":{"authorizationURL":{"type":"string","format":"uri"},"transactionID":{"type":"string","minLength":22,"maxLength":22},"providerID":{"type":"string","minLength":1,"maxLength":128},"protocol":{"const":"oidc"}}}}}},
    "400":{"description":"Invalid request."},"403":{"description":"Start denied."},"409":{"description":"Original command conflict."},"429":{"description":"Provider IP quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no redirect."}
  }
}`),
	}
}

func memberSigninStartWire(cookieName string) *identityhttp.WireOperation {
	operation := signinStartWire()
	var fields map[string]json.RawMessage
	if json.Unmarshal(operation.Definition, &fields) != nil {
		return &identityhttp.WireOperation{}
	}
	fields["summary"] = json.RawMessage(`"Start opted-in enterprise sign-in or account linking"`)
	fields["description"] = json.RawMessage(`"Omit link and provide flowID for anonymous sign-in. To link explicitly, send link:true, omit flowID, and use the original fresh password-session cookie and X-CSRF-Token. Both variants require the trusted device and exact Origin. Keep the original command ID, request and idempotency key on retry. Neither variant issues a session."`)
	fields["requestBody"] = json.RawMessage(`{"required":true,"content":{"application/json":{"schema":{
  "type":"object","additionalProperties":false,"required":["commandID","providerID","callback","errorCallback"],
  "properties":{"flowID":{"type":"string","minLength":22,"maxLength":22},"link":{"const":true},"commandID":{"type":"string","minLength":22,"maxLength":22},"providerID":{"type":"string","minLength":1,"maxLength":128},"domain":{"type":"string","minLength":1,"maxLength":253},"callback":{"type":"string","format":"uri","maxLength":2048},"errorCallback":{"type":"string","format":"uri","maxLength":2048},"remember":{"type":"boolean"}},
  "oneOf":[{"required":["flowID"],"not":{"required":["link"]}},{"required":["link"],"not":{"required":["flowID"]},"properties":{"remember":{"const":false}}}]
}}}}`)
	fields["security"] = json.RawMessage(`[{},{"SSOMemberLinkSession":[],"SSOMemberLinkCSRF":[]}]`)
	definition, err := json.Marshal(fields)
	if err != nil {
		return &identityhttp.WireOperation{}
	}
	cookieScheme, err := json.Marshal(map[string]string{"type": "apiKey", "in": "cookie", "name": cookieName})
	if err != nil {
		return &identityhttp.WireOperation{}
	}
	operation.Definition = definition
	operation.SecuritySchemes = []identityhttp.WireComponent{
		{Name: "SSOMemberLinkSession", Definition: cookieScheme},
		{Name: "SSOMemberLinkCSRF", Definition: []byte(`{"type":"apiKey","in":"header","name":"X-CSRF-Token"}`)},
	}
	return operation
}

func memberSigninCallbackWire() *identityhttp.WireOperation {
	operation := signinCallbackWire()
	var fields map[string]json.RawMessage
	if json.Unmarshal(operation.Definition, &fields) != nil {
		return &identityhttp.WireOperation{}
	}
	fields["summary"] = json.RawMessage(`"Complete opted-in enterprise sign-in or member linking"`)
	fields["description"] = json.RawMessage(`"Query-only return for the configured provider. The authenticated original transaction selects anonymous sign-in or explicit member linking. A committed sign-in issues secure session and CSRF cookies; a committed link requires the original local cookie and redirects without issuing credentials. Denied or unresolved returns neither redirect nor credentials."`)
	var responses map[string]json.RawMessage
	if json.Unmarshal(fields["responses"], &responses) != nil {
		return &identityhttp.WireOperation{}
	}
	responses["303"] = json.RawMessage(`{"description":"Original success redirect; Set-Cookie is present only after sign-in.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}}}`)
	wire, err := json.Marshal(responses)
	if err != nil {
		return &identityhttp.WireOperation{}
	}
	fields["responses"] = wire
	operation.Definition, err = json.Marshal(fields)
	if err != nil {
		return &identityhttp.WireOperation{}
	}
	return operation
}

func discoveryWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{
		Definition: []byte(`{
  "operationId":"identity.sso.discover",
  "summary":"Discover an advertised enterprise SSO provider",
  "description":"Anonymous discovery for an exact mapped HTTPS tenant and a verified browser-device cookie. The cookie is correlation, not user authentication. An email local part is discarded; no account is looked up. The result is not login authority. Responses are not cacheable.",
  "parameters":[{"name":"emailOrDomain","in":"query","required":true,"description":"Exact ASCII domain or plain email address; one value, 1..320 bytes.","schema":{"type":"string","minLength":1,"maxLength":320}}],
  "security":[{"SSODiscoveryDevice":[]}],
  "responses":{
    "200":{"description":"Advertised provider choice or no match.","content":{"application/json":{"schema":{"oneOf":[
      {"type":"object","additionalProperties":false,"required":["matched","providerID","protocol","requiresConfirmation"],"properties":{"matched":{"const":true},"providerID":{"type":"string","minLength":1,"maxLength":128},"protocol":{"const":"oidc"},"requiresConfirmation":{"type":"boolean"}}},
      {"type":"object","additionalProperties":false,"required":["matched","requiresConfirmation"],"properties":{"matched":{"const":false},"requiresConfirmation":{"const":false}}}
    ]}}}},
    "400":{"description":"Invalid request.","content":{"application/json":{"schema":{"$ref":"#/components/schemas/SSODiscoveryError"}}}},
    "403":{"description":"Discovery denied.","content":{"application/json":{"schema":{"$ref":"#/components/schemas/SSODiscoveryError"}}}},
    "404":{"description":"Route not selected.","content":{"application/json":{"schema":{"$ref":"#/components/schemas/SSODiscoveryError"}}}},
    "421":{"description":"Host not configured.","content":{"application/json":{"schema":{"$ref":"#/components/schemas/SSODiscoveryError"}}}},
    "429":{"description":"The shared auth IP quota is exhausted.","headers":{"Retry-After":{"description":"Whole seconds before retry.","schema":{"type":"string","pattern":"^[0-9]+$"}}},"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SSODiscoveryError"}}}},
    "503":{"description":"Required authority unavailable.","content":{"application/json":{"schema":{"$ref":"#/components/schemas/SSODiscoveryError"}}}}
  }
}`),
		Schemas:         []identityhttp.WireComponent{{Name: "SSODiscoveryError", Definition: []byte(`{"type":"object","additionalProperties":false,"required":["error"],"properties":{"error":{"type":"string","enum":["invalid_request","forbidden","https_required","not_found","misdirected_request","rate_limited","unavailable"]}}}`)}},
		SecuritySchemes: []identityhttp.WireComponent{{Name: "SSODiscoveryDevice", Definition: []byte(`{"type":"apiKey","in":"cookie","name":"__Host-identity_device","description":"Same-origin browser correlation; not a session or user authentication."}`)}},
	}
}
