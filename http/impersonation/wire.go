package impersonationhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func startWire(originalCookie string) *identityhttp.WireOperation {
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"}
	text := map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	responseFields := map[string]any{
		"started": map[string]any{"type": "boolean"}, "credentialIssued": map[string]any{"type": "boolean"},
		"commandID": id, "grantID": id, "actorID": text, "targetID": text,
		"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "unknown", "not_committed", "conflict", "in_progress"}},
		"error":         map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "conflict", "unavailable", "misdirected_request", "not_found", "method_not_allowed"}},
	}
	response := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"started", "credentialIssued", "commitOutcome"}, "properties": responseFields}
	payload := func(s any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": s}}
	}
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "409", "421", "503"} {
		responses[status] = map[string]any{"description": "Credential-free Start outcome. Only the original acknowledged commit can set the paired child cookies.", "content": payload(response)}
	}
	header := func(name string, schema map[string]any) map[string]any {
		return map[string]any{"in": "header", "name": name, "required": true, "schema": schema}
	}
	request := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"grantID", "expectedVersion"}, "properties": map[string]any{
		"grantID": id, "expectedVersion": map[string]any{"type": "integer", "const": 2},
	}}
	operation := map[string]any{
		"operationId": startOperation.OperationID,
		"description": "Start one independently approved grant using the original ordinary administrator cookie and its synchronizer. No child credential substitution. An exact keyed retry returns only the original metadata and does not replace any cookies.",
		"security":    []any{map[string]any{"ImpersonationOriginalCookie": []string{}}},
		"parameters": []any{
			header("Origin", map[string]any{"type": "string"}),
			header("X-CSRF-Token", map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}),
			header("Idempotency-Key", map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}),
		},
		"requestBody": map[string]any{"required": true, "content": payload(request)},
		"responses":   responses,
	}
	definition, _ := json.Marshal(operation)
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": originalCookie, "description": "Original ordinary administrator cookie."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "ImpersonationOriginalCookie", Definition: scheme}}}
}

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

func denyWire(cookie string) *identityhttp.WireOperation {
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"}
	payload := func(s any) map[string]any { return map[string]any{"application/json": map[string]any{"schema": s}} }
	request := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"grantID", "expectedVersion", "reason"}, "properties": map[string]any{
		"grantID": id, "expectedVersion": map[string]any{"type": "integer", "const": 1},
		"reason": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024, "writeOnly": true, "description": "Private non-blank reason, at most 1024 UTF-8 bytes."},
	}}
	response := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"denied", "commitOutcome"}, "properties": map[string]any{
		"denied": map[string]any{"type": "boolean"}, "commandID": id, "grantID": id,
		"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "unknown", "not_committed", "conflict", "in_progress"}},
		"error":         map[string]any{"type": "string", "enum": []string{"invalid_request", "denied", "conflict", "unavailable", "rate_limited", "misdirected_request", "not_found", "method_not_allowed"}},
	}}
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "409", "421", "429", "503"} {
		responses[status] = map[string]any{"description": "Credential-free denial result; no response issues or clears cookies.", "content": payload(response)}
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 60}}}
	operation := map[string]any{
		"operationId": denyOperation.OperationID,
		"description": "Deny one exact pending grant using a distinct administrator's ordinary session and stored synchronizer. The shared audited admin quota is required. Idempotency-Key is forbidden. No automatic retry occurs after an unknown outcome.",
		"security":    []any{map[string]any{"ImpersonationDenialCookie": []string{}}},
		"parameters": []any{
			map[string]any{"in": "header", "name": "Origin", "required": true, "schema": map[string]any{"type": "string"}},
			map[string]any{"in": "header", "name": "X-CSRF-Token", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}},
		},
		"requestBody": map[string]any{"required": true, "content": payload(request)}, "responses": responses,
	}
	definition, _ := json.Marshal(operation)
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie, "description": "Original ordinary administrator cookie."})
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: []identityhttp.WireComponent{{Name: "ImpersonationDenialCookie", Definition: scheme}}}
}
