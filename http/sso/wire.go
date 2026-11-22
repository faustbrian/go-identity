package ssohttp

import identityhttp "github.com/faustbrian/go-identity/http"

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
