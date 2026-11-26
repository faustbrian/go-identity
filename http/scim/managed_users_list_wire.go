package scimhttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedUsersListWire(limits scim.Limits) *identityhttp.WireOperation {
	parameters := []fields{}
	for _, parameter := range []struct {
		name  string
		bound int
	}{
		{"filter", limits.FilterBytes}, {"sortBy", limits.PathBytes}, {"sortOrder", 10},
		{"attributes", limits.BodyBytes}, {"excludedAttributes", limits.BodyBytes},
	} {
		schema := fields{"type": "string", "maxLength": parameter.bound}
		if parameter.name == "sortOrder" {
			schema["enum"] = []string{"ascending", "descending"}
		}
		parameters = append(parameters, fields{"name": parameter.name, "in": "query", "required": false, "schema": schema})
	}
	for _, name := range []string{"startIndex", "count"} {
		parameters = append(parameters, fields{"name": name, "in": "query", "required": false, "schema": fields{"type": "integer"}, "description": "Signed decimal within the native Go integer range. Native RFC semantics normalize below-one startIndex to 1 and negative count to 0; omitted count uses the native default and supplied count is capped at the native maximum."})
	}
	resource := fields{"type": "object", "required": []string{"schemas", "id", "meta"}, "properties": fields{
		"schemas": fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"id":      fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"meta":    fields{"type": "object", "required": []string{"version"}, "properties": fields{"version": fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes}}},
	}, "additionalProperties": true, "description": "Native schema-governed User projection, including selected declared extensions. Write-only and returned-never attributes are absent."}
	success := wireObject([]string{"schemas", "totalResults", "Resources", "startIndex", "itemsPerPage"}, fields{
		"schemas":      schemaURN("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
		"totalResults": fields{"type": "integer", "minimum": 0}, "startIndex": fields{"type": "integer", "minimum": 1},
		"itemsPerPage": fields{"type": "integer", "minimum": 0, "maximum": limits.PageMax},
		"Resources":    fields{"type": "array", "maxItems": limits.PageMax, "items": resource},
	})
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	})
	responses := fields{"200": wireResponse("Complete currently authorized RFC User ListResponse from one native snapshot.", success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "415", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM Error; no partial page or credential.", errorSchema)
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}, "description": "Ceiling seconds for the longest exhausted protocol bucket."}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: "SCIMManagedUsersBearer", Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped SCIM bearer. Native current connection, organization and operation authority remain mandatory; cookies never supply authority."}`)}},
		Definition:      wireJSON(fields{"operationId": managedUsersListOperation, "parameters": parameters, "responses": responses, "security": []fields{{"SCIMManagedUsersBearer": []string{}}}, "description": "Exact HTTPS User collection read only. Query scalars decode once under transport URL/decoded bounds; duplicate, unknown and malformed encodings deny before native work. The native owner retains filter/sort/projection/page semantics and full snapshot limits. It supplies its currently authorized configured client to one shared atomic rate.protocol charge (client120/minute, full IP240/minute, resource tenant600/minute); failed/ambiguous admission has no local fallback. No body, trailer, Idempotency-Key, cookie fallback, caller tenant/client/connection, dynamic User Get, write, search, Groups or new discovery selection. Earlier request and original authority deadlines win; no partial data is emitted."}),
	}
}
