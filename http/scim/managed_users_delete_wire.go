package scimhttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedUsersDeleteWire(limits scim.Limits) *identityhttp.WireOperation {
	parameters := []fields{
		{"name": "resource_id", "in": "path", "required": true, "schema": fields{"type": "string", "minLength": 1, "maxLength": min(128, limits.StringBytes), "pattern": "^[A-Za-z0-9._~-]+$"}, "description": "Exact unescaped canonical resource segment, excluding dot, dot-dot and reserved .search."},
		{"name": "If-Match", "in": "header", "required": true, "schema": fields{"type": "string", "minLength": 3, "maxLength": 256}, "description": "One exact strong native version, unchanged. Native authority owns required/strong validation and current comparison: missing returns 428, invalid 400, stale live version 412."},
	}
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	})
	responses := fields{"204": fields{"description": "Native conditional deletion or canonical tombstone-backed headerless replay. Exactly no response body, representation headers, ETag or Location."}}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "412", "415", "428", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM Error without partial output, ETag, Location or credential. Failure alone does not prove rollback.", errorSchema)
	}
	for _, failure := range []struct{ status, code string }{
		{"400", "invalid_request"}, {"403", "https_required"}, {"404", "not_found"}, {"405", "method_not_allowed"}, {"421", "misdirected_request"}, {"503", "unavailable"},
	} {
		response, exists := responses[failure.status]
		if !exists {
			response = fields{"content": fields{}}
			responses[failure.status] = response
		}
		entry := response.(fields)
		entry["description"] = "Native SCIM denial or the established outer transport denial; no resource or credential."
		entry["content"].(fields)["application/json"] = fields{"schema": wireObject([]string{"error"}, fields{"error": fields{"const": failure.code}})}
	}
	responses["403"].(fields)["content"].(fields)["text/plain"] = fields{"schema": fields{"type": "string", "const": "identity.http.origin_denied\n", "description": "Fixed outer origin-guard denial."}}
	responses["405"].(fields)["headers"] = fields{"Allow": fields{"schema": fields{"type": "string"}, "description": "Sorted exact methods selected for this resource path, without implicit HEAD or OPTIONS."}}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: "SCIMManagedUserDeleteBearer", Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped managed SCIM bearer; cookies never supply authority. Native current connection, organization and operation policy remain mandatory."}`)}},
		Definition: wireJSON(fields{"operationId": managedUsersDeleteOperation, "parameters": parameters, "responses": responses,
			"security":    []fields{{"SCIMManagedUserDeleteBearer": []string{}}},
			"description": "Exact HTTPS conditional User DELETE only. Router supplies resource_id; a single If-Match is forwarded unchanged to the native owner. No query, body, trailer, encoding, client Idempotency-Key, cookie fallback, CSRF requirement, automatic retry or response cache. Native schema/current bearer/connection/organization/policy and target/precondition validation precede one shared atomic rate.protocol charge (client120/minute, full IP240/minute, tenant600/minute), then native command/effect authority. Preserve canonical server-owned headerless replay and original deadlines without new custody. Success is exactly empty 204; errors disclose no partial representation or version. No other read/write, search, Groups, discovery or connection lifecycle is selected."}),
	}
}
