package oauthhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewProxyForwardFeature opts in to the exact production provider GET. It
// leaves the separately registered preview landing and completion unmounted.
// No browser credential, CORS exception, POST or provider alias is selected.
func NewProxyForwardFeature(c ProxyForwardConfig) (identityhttp.Feature, error) {
	h, err := NewProxyForwardHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	const owner = "identity/oauth/proxy"
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: owner, OperationID: proxyForwardOperation, Handler: h,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 16384,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = proxyForwardWire(c)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: owner, Operations: []identityhttp.OperationDescriptor{op}})
}

func proxyForwardWire(c ProxyForwardConfig) *identityhttp.WireOperation {
	parameter := func(name, description string, required bool, maximum int) map[string]any {
		return map[string]any{"name": name, "in": "query", "description": description, "required": required,
			"schema": map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}}
	}
	state := parameter("state", "Original canonical 32-byte state, not a credential by itself.", true, 43)
	state["schema"].(map[string]any)["pattern"] = `^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`
	issuer := parameter("iss", "Exact configured issuer, including for provider denial.", true, 2048)
	responses := map[string]any{
		"303": map[string]any{"description": "No-store empty redirect after original acknowledged settlement. No cookies or provider tokens.",
			"headers": map[string]any{"Location": map[string]any{"description": "Exact registered preview endpoint with the encrypted handoff in the URL fragment only.",
				"schema": map[string]any{"type": "string", "format": "uri"}}}},
	}
	for _, failure := range []struct{ status, code string }{
		{"400", "invalid_request"}, {"403", "denied"}, {"404", "not_found"}, {"405", "method_not_allowed"},
		{"421", "misdirected_request"}, {"429", "rate_limited"}, {"503", "unavailable"},
	} {
		response := map[string]any{"description": "Redacted denial without handoff or cookies.",
			"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"error"},
				"properties": map[string]any{"error": map[string]any{"type": "string", "const": failure.code}},
			}}}}
		if failure.status == "405" {
			response["headers"] = map[string]any{"Allow": map[string]any{"schema": map[string]any{"type": "string", "const": "GET"}}}
		}
		if failure.status == "429" {
			response["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": `^[1-9][0-9]*$`}}}
		}
		responses[failure.status] = response
	}
	definition, _ := json.Marshal(map[string]any{
		"operationId": proxyForwardOperation,
		"description": "Exact trusted production HTTPS provider query callback. Supply either code or error, never both. No body, bearer or retry key. Provider/IP, original-transaction and counted audited risk admission precede native exchange. Uncertain outcomes must not be retried here.",
		"parameters": []any{issuer, state, parameter("code", "Provider authorization code; do not log.", false, c.Provider.MaxCodeBytes),
			parameter("error", "Provider denial only.", false, 256),
			parameter("error_description", "Optional bounded provider denial diagnostic; never displayed or logged.", false, 1024),
			parameter("error_uri", "Optional provider denial identifier; never fetched.", false, 2048)},
		"responses": responses,
	})
	return &identityhttp.WireOperation{Definition: definition}
}
