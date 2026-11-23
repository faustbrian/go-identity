package ssohttp

import identityhttp "github.com/faustbrian/go-identity/http"

func samlStartWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-start",
  "summary":"Start a selected SP-initiated SAML sign-in",
  "description":"Exact installed provider and SP HTTPS origin. Requires the exact Origin header or, for an ordinary GET document navigation without Origin, same-origin browser Fetch Metadata. A fresh native start creates one server-owned flow and signs the redirect. The optional Idempotency-Key is an alias only, never an authority or command selector. No session is delivered here.",
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}},{"name":"callback","in":"query","schema":{"type":"string","format":"uri","maxLength":8192}},{"name":"errorCallback","in":"query","schema":{"type":"string","format":"uri","maxLength":8192}},{"name":"remember","in":"query","schema":{"type":"boolean"}},{"name":"Idempotency-Key","in":"header","schema":{"type":"string","minLength":1,"maxLength":256}}],
  "responses":{"303":{"description":"Exact signed IdP redirect and five-minute path-scoped correlation cookie.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}}},"400":{"description":"Invalid request."},"403":{"description":"Origin or start denied."},"409":{"description":"Original command conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no redirect or cookie."}}
}`)}
}

func samlACSWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-acs",
  "summary":"Complete a selected SP-initiated SAML sign-in",
  "description":"This linked-member profile requires the original RelayState, the exact IdP HTTPS Origin and the dedicated path-scoped frontchannel cookie. Only acknowledged fresh native settlement returns the normal session and synchronizer. Denial, replay or an unresolved result issues no session.",
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}}],
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","additionalProperties":false,"required":["SAMLResponse","RelayState"],"properties":{"SAMLResponse":{"type":"string","minLength":1,"maxLength":1048576},"RelayState":{"type":"string","minLength":43,"maxLength":43}}}}}},
  "responses":{"303":{"description":"Original allowlisted success redirect, fresh session and CSRF cookies, and removal of the exact correlation cookie.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}}},"400":{"description":"Invalid form."},"403":{"description":"Callback denied."},"409":{"description":"Original callback conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no redirect or cookie."}}
}`)}
}
