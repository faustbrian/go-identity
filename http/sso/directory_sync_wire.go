package ssohttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
)

const (
	directoryWireID         = `{"type":"string","pattern":"^[A-Za-z0-9_-]{22}$"}`
	directoryWireCheckpoint = `{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"}`
	directoryWireVersion    = `{"type":"integer","minimum":1,"maximum":18446744073709551615}`
	directoryWireCount      = `{"type":"integer","minimum":0,"maximum":18446744073709551615}`
	directoryWireMode       = `{"enum":["apply","dry-run"]}`
	directoryWireProvider   = `{"type":"string","minLength":1,"maxLength":128,"pattern":"^[!-~]+$"}`
	directoryWireCompletion = `{"type":"object","additionalProperties":false,"required":["commandID","outcome"],"properties":{"commandID":` + directoryWireID + `,"outcome":{"const":"committed"}}}`
)

func directorySyncWire(op, cookieName string) *identityhttp.WireOperation {
	var summary, description, body, result string
	security := `[{"SSODirectorySession":[],"SSODirectoryCSRF":[]}]`
	var parameters json.RawMessage
	switch op {
	case directoryStart:
		summary = "Start an opted-in directory generation"
		description = "Use the exact provider and mapping versions, same-origin cookie and CSRF. Omit sourceCursor to use the configured initial position. Retain the original request and Idempotency-Key for recovery. This does not apply directory changes."
		parameters = json.RawMessage(`[{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}]`)
		body = `{"type":"object","additionalProperties":false,"required":["providerID","providerVersion","mappingVersion","mode"],"properties":{"providerID":` + directoryWireProvider + `,"providerVersion":` + directoryWireVersion + `,"mappingVersion":` + directoryWireVersion + `,"mode":` + directoryWireMode + `,"sourceCursor":` + directoryWireCheckpoint + `}}`
		result = `{"type":"object","additionalProperties":false,"required":["generationID","providerID","mappingVersion","mode","completion"],"properties":{"generationID":` + directoryWireID + `,"providerID":` + directoryWireProvider + `,"mappingVersion":` + directoryWireVersion + `,"mode":` + directoryWireMode + `,"completion":` + directoryWireCompletion + `}}`
	case directoryStatus:
		summary = "Read current directory generation status"
		description = "Read the exact known generation under current organization authority. The returned version is the expectedVersion for Cancel. No request body, CSRF header or Idempotency-Key is accepted."
		security = `[{"SSODirectorySession":[]}]`
		parameters = json.RawMessage(`[{"name":"generationID","in":"query","required":true,"schema":` + directoryWireID + `}]`)
		result = `{"type":"object","additionalProperties":false,"required":["generationID","version","state","readCount","appliedCount","rejectedCount","checkpoint","limitations","reconciliationRequired"],"properties":{"generationID":` + directoryWireID + `,"version":` + directoryWireVersion + `,"state":{"enum":["running","reconciling","canceling","canceled","finished"]},"readCount":` + directoryWireCount + `,"appliedCount":` + directoryWireCount + `,"rejectedCount":` + directoryWireCount + `,"checkpoint":` + directoryWireCheckpoint + `,"limitations":{"type":"array","items":{"type":"string"}},"reconciliationRequired":{"type":"boolean"}}}`
	case directoryCancel:
		summary = "Stop new work for the exact directory generation version"
		description = "Repeat the same generation and original expected version without an Idempotency-Key. Stopped means no new grants; a canceling state still has unresolved original work."
		body = `{"type":"object","additionalProperties":false,"required":["generationID","expectedVersion"],"properties":{"generationID":` + directoryWireID + `,"expectedVersion":{"type":"integer","minimum":1,"maximum":18446744073709551614}}}`
		result = `{"type":"object","additionalProperties":false,"required":["generationID","stopped","state","checkpoint","reconciliationRequired","completion"],"properties":{"generationID":` + directoryWireID + `,"stopped":{"const":true},"state":{"enum":["canceling","canceled"]},"checkpoint":` + directoryWireCheckpoint + `,"reconciliationRequired":{"type":"boolean"},"completion":` + directoryWireCompletion + `}}`
	default:
		return &identityhttp.WireOperation{}
	}
	responses := map[string]json.RawMessage{
		"200": json.RawMessage(`{"description":"Authorized safe directory projection.","content":{"application/json":{"schema":` + result + `}}}`),
		"400": json.RawMessage(`{"description":"Invalid request."}`),
		"403": json.RawMessage(`{"description":"Cookie, origin, CSRF, generation scope or organization authorization denied."}`),
		"409": json.RawMessage(`{"description":"Original request conflict or stale generation version."}`),
		"429": json.RawMessage(`{"description":"The shared quota is exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}}`),
		"503": json.RawMessage(`{"description":"Authority unavailable or outcome unresolved. No success projection is disclosed."}`),
	}
	wire := map[string]any{"operationId": op, "summary": summary, "description": description, "security": json.RawMessage(security), "responses": responses}
	if body != "" {
		wire["requestBody"] = json.RawMessage(`{"required":true,"content":{"application/json":{"schema":` + body + `}}}`)
	}
	if parameters != nil {
		wire["parameters"] = parameters
	}
	definition, err := json.Marshal(wire)
	if err != nil {
		return &identityhttp.WireOperation{}
	}
	// Start, Status and Cancel are selected as one feature; the renderer
	// requires shared security components to have exactly one declaration.
	if op != directoryStart {
		return &identityhttp.WireOperation{Definition: definition}
	}
	cookie, err := json.Marshal(map[string]string{"type": "apiKey", "in": "cookie", "name": cookieName})
	if err != nil {
		return &identityhttp.WireOperation{}
	}
	schemes := []identityhttp.WireComponent{
		{Name: "SSODirectorySession", Definition: cookie},
		{Name: "SSODirectoryCSRF", Definition: []byte(`{"type":"apiKey","in":"header","name":"X-CSRF-Token"}`)},
	}
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: schemes}
}
