package scimhttp

import identityhttp "github.com/faustbrian/go-identity/http"

func managedReadWire(operation string) *identityhttp.WireOperation {
	id := fields{"type": "string", "minLength": 22, "maxLength": 22, "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": fields{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	cursor := fields{"type": "string", "minLength": 74, "maxLength": 74, "pattern": "^[A-Za-z0-9_-]{73}[AQgw]$"}
	mapping := wireObject([]string{"source", "target", "writable"}, fields{
		"source":   fields{"type": "string", "minLength": 1, "maxLength": 1024},
		"target":   fields{"type": "string", "minLength": 1, "maxLength": 128},
		"writable": fields{"type": "boolean"},
	})
	record := wireObject([]string{"tenantID", "organizationID", "providerID", "connectionID", "mappings", "deprovisionPolicy", "version"}, fields{
		"tenantID": id, "organizationID": id, "providerID": fields{"type": "string", "minLength": 1, "maxLength": 128}, "connectionID": id,
		"mappings":          fields{"type": "array", "minItems": 1, "maxItems": 128, "items": mapping},
		"deprovisionPolicy": fields{"type": "string", "enum": []string{"suspend", "remove-membership", "delete-identity"}},
		"version":           fields{"type": "integer", "minimum": 1, "maximum": ^uint64(0)},
	})
	parameter := func(name string, required bool, schema fields) fields {
		return fields{"name": name, "in": "query", "required": required, "schema": schema}
	}
	parameters := []fields{parameter("connectionID", true, id)}
	response := record
	if operation == managedListOperation {
		parameters = []fields{parameter("organizationID", true, id), parameter("limit", true, fields{"type": "integer", "minimum": 1, "maximum": 200}), parameter("cursor", false, cursor)}
		response = wireObject([]string{"connections"}, fields{"connections": fields{"type": "array", "maxItems": 200, "items": record}, "nextCursor": cursor})
	}
	errorSchema := wireObject([]string{"error"}, fields{"error": fields{"type": "string", "enum": []string{"invalid_request", "unauthenticated", "forbidden", "rate_limited", "unavailable", "not_found", "method_not_allowed"}}})
	responses := fields{}
	for _, status := range []string{"200", "400", "401", "403", "404", "405", "429", "503"} {
		schema := errorSchema
		if status == "200" {
			schema = response
		}
		responses[status] = fields{"description": "Bounded no-store administrative JSON; no credentials or refreshed authority.", "content": fields{"application/json": fields{"schema": schema}}}
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "string", "pattern": "^[0-9]+$"}, "description": "Ceiling seconds for a known rate.safe denial."}}
	return &identityhttp.WireOperation{Definition: wireJSON(fields{
		"operationId": operation, "parameters": parameters, "responses": responses, "security": []fields{{"SCIMAdministratorBearer": []string{}}},
		"description": "Explicit current verified session bearer over HTTPS on an exact tenant host. Native current administrator and org:scim-read decisions fence the primary read. Canonical shared rate.safe admits the trusted IP and actual authenticated tenant-scoped subject; unavailable session authority never falls back to anonymous admission. Bodies, trailers, unknown or duplicate query parameters and Idempotency-Key are forbidden. No cookie authority, CSRF token, credential issuance or provisioning write. List pages are live, bytewise connection-ID ordered, with native scope-authenticated opaque continuations.",
	})}
}
