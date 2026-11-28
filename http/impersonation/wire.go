package impersonationhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func stopWire() *identityhttp.WireOperation {
	responseFields := map[string]any{
		"stopped": map[string]any{"type": "boolean"}, "parentResumed": map[string]any{"type": "boolean"},
		"commandID":     map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"},
		"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "unknown", "not_committed", "conflict", "in_progress"}},
		"error":         map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "conflict", "unavailable", "misdirected_request", "not_found", "method_not_allowed"}},
	}
	shape := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"stopped", "parentResumed", "commitOutcome"}, "properties": responseFields}
	payload := func(s any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": s}}
	}
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "409", "421", "503"} {
		responses[status] = map[string]any{"description": "Credential-free stop outcome. Only error-free committed success clears the two child cookies.", "content": payload(shape)}
	}
	operation := map[string]any{
		"operationId": stopOperation.OperationID,
		"description": "Exact HTTPS tenant cookie self-stop. The stored child synchronizer is supplied in the single X-CSRF-Token header. Ordinary parent custody is optional and independent. No query, trailer, Authorization or Idempotency-Key. An unresolved command is not automatically retried.",
		"security":    []any{map[string]any{"ImpersonationChildCookie": []string{}}},
		"parameters": []any{
			map[string]any{"in": "header", "name": "Origin", "required": true, "schema": map[string]any{"type": "string"}},
			map[string]any{"in": "header", "name": "X-CSRF-Token", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}},
		},
		"requestBody": map[string]any{"required": true, "content": payload(map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}})},
		"responses":   responses,
	}
	definition, _ := json.Marshal(operation)
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": ChildCookieName, "description": "Dedicated child credential, never an ordinary actor session."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "ImpersonationChildCookie", Definition: scheme}}}
}
