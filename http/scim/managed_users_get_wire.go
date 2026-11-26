package scimhttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedUsersGetWire(limits scim.Limits) *identityhttp.WireOperation {
	parameters := []fields{{"name": "resource_id", "in": "path", "required": true, "schema": fields{"type": "string", "minLength": 1, "maxLength": min(128, limits.StringBytes), "pattern": "^[A-Za-z0-9._~-]+$"}, "description": "One exact unescaped canonical resource segment. Dot, dot-dot and reserved .search are not resource IDs."}}
	for _, name := range []string{"attributes", "excludedAttributes"} {
		parameters = append(parameters, fields{"name": name, "in": "query", "required": false, "schema": fields{"type": "string", "maxLength": limits.BodyBytes}, "description": "Native schema-governed projection paths; each path consumes the effective SCIM path bound."})
	}
	resource := fields{"type": "object", "required": []string{"schemas", "id", "meta"}, "properties": fields{
		"schemas": fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"id":      fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"meta":    fields{"type": "object", "required": []string{"version"}, "properties": fields{"version": fields{"type": "string", "minLength": 3, "maxLength": 256}}},
	}, "additionalProperties": true, "description": "Bounded native schema-governed User projection, including selected declared extensions. Write-only and returned-never attributes are absent; native resource depth, attribute and string budgets apply."}
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	})
	success := wireResponse("Complete currently authorized native User representation and its unchanged version.", resource)
	success["headers"] = fields{"ETag": fields{"required": true, "schema": fields{"type": "string", "minLength": 3, "maxLength": 256}, "description": "Exact strong native resource version; no transport normalization."}}
	responses := fields{"200": success}
	for _, status := range []string{"400", "401", "403", "404", "405", "415", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM Error; no partial resource, ETag or credential.", errorSchema)
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}, "description": "Ceiling seconds for the longest exhausted protocol bucket."}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: "SCIMManagedUserGetBearer", Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped SCIM bearer. Native current connection, organization and operation authority remain mandatory; cookies never supply authority."}`)}},
		Definition:      wireJSON(fields{"operationId": managedUsersGetOperation, "parameters": parameters, "responses": responses, "security": []fields{{"SCIMManagedUserGetBearer": []string{}}}, "description": "Canonical HTTPS User Get only, with router-derived resource_id and bounded once-decoded projection scalars. Duplicate, unknown and malformed query input denies before native work. Current native bearer/connection/organization/policy authority precedes one shared atomic rate.protocol charge (client120/minute, full IP240/minute, tenant600/minute) and resource IO; failed or ambiguous admission has no local fallback. Preserve the native bounded body and exact ETag. No body, trailer, content encoding, Idempotency-Key, cookie fallback, caller scope, conditional read, range, collection, write, search, Groups or discovery selection. Original request and authority deadlines win; no partial data or version is emitted."}),
	}
}
