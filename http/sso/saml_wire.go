package ssohttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func samlLogoutWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-slo",
  "summary":"Process a selected installed provider's signed SAML logout POST",
  "description":"Accept exactly one LogoutRequest or LogoutResponse at the installed SP destination from the configured IdP origin. No credentials, RelayState or caller redirect are selected. A fresh known revocation may return an explicit signed POST form. Only successful native response settlement can return the original allowlisted SP continuation.",
  "security":[],
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}}],
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"oneOf":[{"type":"object","additionalProperties":false,"required":["SAMLRequest"],"properties":{"SAMLRequest":{"type":"string","minLength":1,"maxLength":1048576}}},{"type":"object","additionalProperties":false,"required":["SAMLResponse"],"properties":{"SAMLResponse":{"type":"string","minLength":1,"maxLength":1048576}}}]}}}},
  "responses":{"200":{"description":"Signed POST LogoutResponse form to the installed IdP endpoint.","content":{"text/html":{"schema":{"type":"string"}}}},"204":{"description":"No response form or application continuation."},"303":{"description":"Original allowlisted SP continuation.","headers":{"Location":{"schema":{"type":"string","format":"uri"}}}},"400":{"description":"Invalid signed-message form."},"403":{"description":"Origin or logout denied."},"409":{"description":"Original signed-message conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no response form, redirect or cookie."}}
}`)}
}

func samlLogoutRequestWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-slo",
  "summary":"Process an installed IdP's signed SAML logout request",
  "description":"Accept one signed LogoutRequest at the installed SP destination from the configured IdP origin. No browser credentials, RelayState, caller redirect or inbound response settlement are selected.",
  "security":[],
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}}],
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","additionalProperties":false,"required":["SAMLRequest"],"properties":{"SAMLRequest":{"type":"string","minLength":1,"maxLength":1048576}}}}}},
  "responses":{"200":{"description":"Signed POST LogoutResponse form to the installed IdP endpoint.","content":{"text/html":{"schema":{"type":"string"}}}},"204":{"description":"No signed response form."},"400":{"description":"Invalid signed-request form."},"403":{"description":"Origin or logout denied."},"409":{"description":"Original signed-request conflict."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved; no response form or cookie."}}
}`)}
}

func samlLogoutRelayWire(settlesResponse bool) (*identityhttp.WireOperation, error) {
	const request = `{"type":"object","additionalProperties":false,"required":["SAMLRequest"],"properties":{"SAMLRequest":{"type":"string","minLength":1,"maxLength":1048576},"RelayState":{"type":"string","minLength":1,"maxLength":80,"pattern":"^[A-Za-z0-9_-]+$"}}}`
	const response = `{"type":"object","additionalProperties":false,"required":["SAMLResponse"],"properties":{"SAMLResponse":{"type":"string","minLength":1,"maxLength":1048576}}}`
	wire := samlLogoutRequestWire()
	schema := request
	if settlesResponse {
		wire = samlLogoutWire()
		schema = `{"oneOf":[` + request + `,` + response + `]}`
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire.Definition, &fields); err != nil {
		return nil, err
	}
	description := `"Accept a signed LogoutRequest from the configured IdP origin, with one optional opaque RelayState. Only a fresh POST form carrying a signed LogoutResponse echoes the exact value. The value is never browser, session or redirect authority."`
	if settlesResponse {
		description = `"Accept a signed LogoutRequest with one optional opaque RelayState, or a signed LogoutResponse without RelayState, from the configured IdP origin. Only a fresh POST form carrying a signed request reply echoes the exact value. Only native response settlement may select the original allowlisted SP continuation."`
	}
	fields["description"] = json.RawMessage(description)
	fields["requestBody"] = json.RawMessage(`{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":` + schema + `}}}`)
	var err error
	wire.Definition, err = json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return wire, nil
}

func samlMetadataWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-metadata",
  "summary":"Read the installed SAML service provider's metadata",
  "description":"Anonymous exact HTTPS GET for the selected SP-initiated profile. The response uses only current SP information and the public signing certificate. It is not cached and sets no cookie.",
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}}],
  "responses":{"200":{"description":"Current unsigned SAML SP metadata.","content":{"application/samlmetadata+xml":{"schema":{"type":"string"}}}},"400":{"description":"Invalid request."},"403":{"description":"Tenant or transport denied."},"404":{"description":"No current metadata for this path."},"429":{"description":"Safe read quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable; no metadata disclosed."}}
}`)}
}

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

func samlIDPInitWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-idp-init",
  "summary":"Confirm a selected IdP-initiated SAML sign-in",
  "description":"An exact IdP-origin form supplies only SAMLResponse. The response contains a same-origin confirmation form and an independent path-scoped browser cookie, not a session. Only that same-origin form and its original cookie can complete the sign-in. No SP transaction or RelayState is selected.",
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}}],
  "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"oneOf":[{"type":"object","additionalProperties":false,"required":["SAMLResponse"],"properties":{"SAMLResponse":{"type":"string","minLength":1,"maxLength":1048576}}},{"type":"object","additionalProperties":false,"required":["pending","confirmation"],"properties":{"pending":{"type":"string","minLength":22,"maxLength":22},"confirmation":{"type":"string","minLength":43,"maxLength":43}}}]}}}},
  "responses":{"200":{"description":"Explicit confirmation form, plus the path-scoped browser cookie.","headers":{"Set-Cookie":{"schema":{"type":"string"}}},"content":{"text/html":{"schema":{"type":"string"}}}},"303":{"description":"Fresh normal session and CSRF cookies, clearing the original browser cookie.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}}},"400":{"description":"Invalid form."},"403":{"description":"Arrival origin or confirmation denied."},"409":{"description":"A conflicting confirmation was denied."},"429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},"503":{"description":"Unavailable or unresolved, without credential delivery."}}
}`)}
}
