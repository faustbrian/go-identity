package ssohttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func providerLogoutStartWire(cookie string) *identityhttp.WireOperation {
	name, _ := json.Marshal(cookie)
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.oidc-logout",
  "summary":"Start opted-in enterprise OIDC logout",
  "description":"Revoke the original local session before sending the browser to its configured provider. Exact Origin and stored session CSRF are required. Only a confirmed local revocation deletes the original cookies. Preserve the original request and retry key if acknowledgement is unresolved.",
  "security":[{"SSOLogoutSession":[],"SSOLogoutCSRF":[]}],
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}},{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}],
  "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["finalRedirect"],"properties":{"finalRedirect":{"type":"string","format":"uri","maxLength":2048}}}}}},
  "responses":{"200":{"description":"Confirmed local-only logout; original cookies deleted.","headers":{"Set-Cookie":{"schema":{"type":"string"}}},"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["outcome"],"properties":{"outcome":{"const":"local-only"}}}}}},"303":{"description":"Original provider redirect after confirmed local revocation.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}}},"400":{"description":"Invalid request."},"403":{"description":"Logout denied."},"409":{"description":"Original operation conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no redirect or cookie."}}
}`), SecuritySchemes: []identityhttp.WireComponent{
		{Name: "SSOLogoutSession", Definition: []byte(`{"type":"apiKey","in":"cookie","name":` + string(name) + `}`)},
		{Name: "SSOLogoutCSRF", Definition: []byte(`{"type":"apiKey","in":"header","name":"X-CSRF-Token"}`)},
	}}
}

func providerLogoutCompleteWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.oidc-logout-complete",
  "summary":"Settle an opted-in enterprise OIDC logout return",
  "description":"Consume one original return at its exact HTTPS provider path. The already-revoked local session cookie is not needed. Providers cannot choose another issuer or final target. No return issues or clears credentials.",
  "security":[],
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}},{"name":"state","in":"query","required":true,"schema":{"type":"string","minLength":43,"maxLength":43}},{"name":"error","in":"query","required":false,"schema":{"type":"string","minLength":1,"maxLength":128}},{"name":"error_description","in":"query","required":false,"schema":{"type":"string","maxLength":1024}}],
  "responses":{"200":{"description":"Settled without redirect. Local revocation remains authoritative.","content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["outcome"],"properties":{"outcome":{"enum":["local-only","provider-complete","provider-error","timeout"]}}}}}},"303":{"description":"The original allowlisted final target.","headers":{"Location":{"schema":{"type":"string","format":"uri"}}}},"400":{"description":"Invalid return."},"403":{"description":"Return denied, including replay."},"409":{"description":"Original operation conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no redirect or cookie."}}
}`)}
}
