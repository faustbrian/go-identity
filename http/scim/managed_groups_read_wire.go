package scimhttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedGroupsReadWire(limits scim.Limits, maximumMembers int, operation scim.Operation) *identityhttp.WireOperation {
	get := operation == scim.GroupGet
	operationID, scheme := managedGroupsListOperation, "SCIMManagedGroupListBearer"
	parameters := []fields{}
	if get {
		operationID, scheme = managedGroupsGetOperation, "SCIMManagedGroupGetBearer"
		parameters = append(parameters, fields{"name": "resource_id", "in": "path", "required": true, "schema": fields{"type": "string", "minLength": 1, "maxLength": min(128, limits.StringBytes), "pattern": "^[A-Za-z0-9._~-]+$"}, "description": "One exact unescaped canonical Group resource segment. Dot, dot-dot and reserved .search are not resource IDs."})
	} else {
		for _, parameter := range []struct {
			name  string
			bound int
		}{{"filter", limits.FilterBytes}, {"sortBy", limits.PathBytes}, {"sortOrder", 10}} {
			schema := fields{"type": "string", "maxLength": parameter.bound}
			if parameter.name == "sortOrder" {
				schema["enum"] = []string{"ascending", "descending"}
			}
			parameters = append(parameters, fields{"name": parameter.name, "in": "query", "required": false, "schema": schema})
		}
		for _, name := range []string{"startIndex", "count"} {
			parameters = append(parameters, fields{"name": name, "in": "query", "required": false, "schema": fields{"type": "integer"}, "description": "Signed decimal within the native Go integer range. Native RFC semantics normalize below-one startIndex to 1 and negative count to 0; omitted count uses the native default and supplied count is capped at the native maximum."})
		}
	}
	for _, name := range []string{"attributes", "excludedAttributes"} {
		parameters = append(parameters, fields{"name": name, "in": "query", "required": false, "schema": fields{"type": "string", "maxLength": limits.BodyBytes}, "description": "Native schema-governed projection paths; each path consumes the effective SCIM path bound."})
	}
	resource := fields{"type": "object", "required": []string{"schemas", "id", "meta"}, "properties": fields{
		"schemas": fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"id":      fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"meta":    fields{"type": "object", "required": []string{"version"}, "properties": fields{"version": fields{"type": "string", "minLength": 3, "maxLength": 256}}},
		"members": fields{"type": "array", "maxItems": maximumMembers, "items": fields{"type": "object"}},
	}, "additionalProperties": true, "description": "Bounded native schema-governed Group projection, including declared selected extensions and immutable member references. Native resource depth, attribute, string and explicit Group member budgets apply; returned-never attributes are absent."}
	success := wireResponse("Complete currently authorized native Group representation and its unchanged version.", resource)
	if get {
		success["headers"] = fields{"ETag": fields{"required": true, "schema": fields{"type": "string", "minLength": 3, "maxLength": 256}, "description": "Exact strong native Group version; no transport normalization."}}
	} else {
		list := wireObject([]string{"schemas", "totalResults", "Resources", "startIndex", "itemsPerPage"}, fields{
			"schemas":      schemaURN("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
			"totalResults": fields{"type": "integer", "minimum": 0}, "startIndex": fields{"type": "integer", "minimum": 1},
			"itemsPerPage": fields{"type": "integer", "minimum": 0, "maximum": limits.PageMax},
			"Resources":    fields{"type": "array", "maxItems": limits.PageMax, "items": resource},
		})
		success = wireResponse("Complete currently authorized RFC Group ListResponse from one native snapshot; no transport ETag or Location.", list)
	}
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	})
	responses := fields{"200": success}
	for _, status := range []string{"400", "401", "403", "404", "405", "415", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM Error; no partial Group, page, version or credential.", errorSchema)
	}
	routerError := wireObject([]string{"error"}, fields{"error": fields{"type": "string", "minLength": 1, "maxLength": 64}})
	// Transport denials may precede SCIM dispatch, so they keep the router's
	// separate JSON envelope. An unselected host never reaches SCIM.
	for _, status := range []string{"400", "403", "404", "405", "503"} {
		response := responses[status].(fields)
		response["description"] = "Redacted SCIM or outer transport error; no partial Group, page, version or credential."
		response["content"].(fields)["application/json"] = fields{"schema": routerError}
	}
	responses["421"] = fields{
		"description": "Request host is not selected for this router.",
		"content":     fields{"application/json": fields{"schema": routerError}},
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}, "description": "Ceiling seconds for the longest exhausted protocol bucket."}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: scheme, Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped SCIM bearer. Native current connection, organization and operation authority remain mandatory; cookies never supply authority."}`)}},
		Definition:      wireJSON(fields{"operationId": operationID, "parameters": parameters, "responses": responses, "security": []fields{{scheme: []string{}}}, "description": "Exact canonical HTTPS Group read only. Get uses router-derived resource_id and only projection scalars; List accepts bounded RFC filter/sort/page/projection scalars. Scalars decode once; duplicates, unknown names and malformed encodings deny before native work. Native current bearer/connection/organization/policy authority precedes one shared atomic rate.protocol charge (client120/minute, full IP240/minute, tenant600/minute), Group IO and final disclosure. Native schema and snapshot semantics and explicit configured Group member ceiling remain authoritative. No body, trailer, content encoding, Idempotency-Key, conditional/range read, cookie fallback, caller-selected tenant/client/connection, User operation, write, search or discovery selection. Earlier request and original authority deadlines win; no partial data or version is emitted."}),
	}
}
