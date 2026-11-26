package scimhttp

import identityhttp "github.com/faustbrian/go-identity/http"

func managedCreateWire() *identityhttp.WireOperation {
	id := fields{"type": "string", "minLength": 22, "maxLength": 22, "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": fields{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	provider := fields{"type": "string", "minLength": 1, "maxLength": 128, "pattern": `^[!-~]+$`, "not": fields{"pattern": `[/\\?#]`}}
	mapping := wireObject([]string{"source", "target", "writable"}, fields{
		"source": fields{"type": "string", "minLength": 1, "maxLength": 1024}, "target": fields{"type": "string", "minLength": 1, "maxLength": 128}, "writable": fields{"type": "boolean"},
	})
	mappings := fields{"type": "array", "minItems": 1, "maxItems": 128, "items": mapping}
	record := wireObject([]string{"tenantID", "organizationID", "providerID", "connectionID", "mappings", "deprovisionPolicy", "version"}, fields{
		"tenantID": id, "organizationID": id, "providerID": provider, "connectionID": id, "mappings": mappings, "deprovisionPolicy": fields{"const": "remove-membership"}, "version": fields{"const": 1},
	})
	success := wireObject([]string{"connection"}, fields{"connection": record, "bearer": fields{"type": "string", "minLength": 32, "maxLength": 4096, "readOnly": true, "description": "Sensitive invocation-local newly confirmed bearer only. Absent on every retained retry; never reconstructed or logged."}})
	errorSchema := wireObject([]string{"error"}, fields{"error": fields{"type": "string", "enum": []string{"invalid_request", "unauthenticated", "forbidden", "conflict", "rate_limited", "unavailable", "not_found", "method_not_allowed"}}})
	responses := fields{}
	for _, status := range []string{"200", "400", "401", "403", "404", "405", "409", "429", "503"} {
		schema := errorSchema
		if status == "200" {
			schema = success
		}
		responses[status] = fields{"description": "Bounded no-store JSON. Failure discloses neither a bearer nor an unrelated projection.", "content": fields{"application/json": fields{"schema": schema}}}
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "string", "pattern": "^[0-9]+$"}, "description": "Bounded ceiling seconds for a known audited rate.admin rejection."}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: "SCIMManagedCreateBearer", Definition: []byte(`{"type":"http","scheme":"bearer","bearerFormat":"opaque native session","description":"Exactly one explicit verified administrator session bearer. Cookies never supply authority."}`)}},
		Definition: wireJSON(fields{
			"operationId": managedCreateOperation, "security": []fields{{"SCIMManagedCreateBearer": []string{}}}, "responses": responses,
			"parameters":  []fields{{"name": "Idempotency-Key", "in": "header", "required": true, "schema": fields{"type": "string", "minLength": 1, "maxLength": 256, "writeOnly": true}}},
			"requestBody": fields{"required": true, "content": fields{"application/json": fields{"schema": wireObject([]string{"organizationID", "providerID", "mappings"}, fields{"organizationID": id, "providerID": provider, "mappings": mappings})}}},
			"description": "Explicit bearer-only alternative to the catalogued cookie/CSRF profile. Exact HTTPS tenant host and a current verified human session are mandatory; ambient cookies confer no authority. The existing shared atomic rate.admin charges actual actor, tenant and trusted IP on every attempt, with exact SCIM denial auditing and no fallback. Native current organization/org:scim-write authority and original key own creation and reveal-once custody. Retry identical intent under the same Idempotency-Key after an uncertain response; never allocate another key to re-execute unknown work. Metadata-only retry never reveals a second bearer. No query fields, tenant/actor/command override, browser mode, reads, Bulk, provisioning, rotate or delete is selected.",
		}),
	}
}
