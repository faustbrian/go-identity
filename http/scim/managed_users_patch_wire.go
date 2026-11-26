package scimhttp

import (
	"strconv"

	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedUsersPatchWire(limits scim.Limits, bodyMaximum int) *identityhttp.WireOperation {
	patch := wireObject([]string{"schemas", "Operations"}, fields{
		"schemas": schemaURN("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
		"Operations": fields{"type": "array", "minItems": 1, "maxItems": limits.PatchOperations, "items": wireObject([]string{"op"}, fields{
			"op":    fields{"type": "string", "enum": []string{"add", "remove", "replace"}},
			"path":  fields{"type": "string", "minLength": 1, "maxLength": limits.PathBytes},
			"value": fields{},
		})},
	})
	patch["description"] = "Forward raw UTF-8 SCIM PatchOp up to " + strconv.Itoa(bodyMaximum) + " bytes. Native policy validates operation shapes, exact path byte and resource limits, mutability and supported attributes. Password writes are unselected."
	return managedUsersConditionalWire(limits, managedUsersPatchOperation, "SCIMManagedUserPatchBearer", patch,
		"Opt-in conditional User PATCH. The native owner authenticates the bearer and validates the scoped request before one shared atomic quota charge and the original durable command. No query, caller Idempotency-Key, cookies, trailers, automatic retry, or separate replay authority. Other routes are not selected.")
}

func managedUsersReplaceWire(limits scim.Limits, bodyMaximum int) *identityhttp.WireOperation {
	replacement := fields{"type": "object", "required": []string{"schemas", "userName"}, "properties": fields{
		"schemas":    fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"userName":   fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"externalId": fields{"type": "string", "maxLength": limits.StringBytes},
	}, "additionalProperties": true, "description": "Forward the raw UTF-8 SCIM User up to " + strconv.Itoa(bodyMaximum) + " bytes. The selected native schema owns mutability, supported extensions and complete replacement, including omission of optional writable attributes."}
	return managedUsersConditionalWire(limits, managedUsersReplaceOperation, "SCIMManagedUserReplaceBearer", replacement,
		"Opt-in conditional User PUT. The native owner authenticates the issued bearer and validates the complete replacement before one shared atomic quota charge and the original durable command. No query, caller Idempotency-Key, cookies, trailers, automatic retry, or separate replay authority. Other routes are not selected.")
}

func managedUsersConditionalWire(limits scim.Limits, operationID, bearerScheme string, request fields, description string) *identityhttp.WireOperation {
	version := fields{"type": "string", "minLength": 3, "maxLength": 256}
	location := fields{"type": "string", "format": "uri"}
	parameters := []fields{
		{"name": "resource_id", "in": "path", "required": true, "schema": fields{"type": "string", "minLength": 1, "maxLength": min(128, limits.StringBytes), "pattern": "^[A-Za-z0-9._~-]+$"}, "description": "One exact unescaped User segment, excluding dot, dot-dot and .search."},
		{"name": "If-Match", "in": "header", "required": true, "schema": version, "description": "One strong native version forwarded unchanged. Missing, malformed and stale return 428, 400 and 412 respectively."},
	}
	resource := fields{"type": "object", "required": []string{"schemas", "id", "meta"}, "properties": fields{
		"schemas": fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"id":      fields{"type": "string", "minLength": 22, "maxLength": 22},
		"meta": fields{"type": "object", "required": []string{"resourceType", "version", "location"}, "properties": fields{
			"resourceType": fields{"const": "User"}, "version": version, "location": location,
		}},
	}, "additionalProperties": true}
	success := wireResponse("Complete native User and original version, including on replay. The response ID, ETag and Location match the selected resource.", resource)
	success["headers"] = fields{"ETag": fields{"required": true, "schema": version}, "Location": fields{"required": true, "schema": location}}
	responses := fields{"200": success}
	errorProperties := fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	}
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, errorProperties)
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "412", "415", "428", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM denial without partial output, ETag, Location or credential. Failure alone does not prove rollback.", errorSchema)
	}
	responses["413"] = wireResponse("SCIM payload denial; the outer stream-cap error has schemas/status and native denials may include detail.", wireObject([]string{"schemas", "status"}, errorProperties))
	for _, failure := range []struct{ status, code string }{
		{"400", "invalid_request"}, {"403", "https_required"}, {"404", "not_found"}, {"405", "method_not_allowed"}, {"421", "misdirected_request"}, {"503", "unavailable"},
	} {
		if _, exists := responses[failure.status]; !exists {
			responses[failure.status] = fields{"content": fields{}}
		}
		entry := responses[failure.status].(fields)
		entry["description"] = "Native SCIM denial or the established outer transport denial; no resource or credential."
		entry["content"].(fields)["application/json"] = fields{"schema": wireObject([]string{"error"}, fields{"error": fields{"const": failure.code}})}
	}
	responses["403"].(fields)["content"].(fields)["text/plain"] = fields{"schema": fields{"type": "string", "const": "identity.http.origin_denied\n", "description": "Fixed outer origin-guard denial."}}
	responses["405"].(fields)["headers"] = fields{"Allow": fields{"schema": fields{"type": "string"}, "description": "Only selected resource methods."}}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: bearerScheme, Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped managed SCIM bearer. Cookies never supply authority."}`)}},
		Definition: wireJSON(fields{"operationId": operationID, "parameters": parameters, "responses": responses,
			"security":    []fields{{bearerScheme: []string{}}},
			"requestBody": fields{"required": true, "content": fields{scimMedia: fields{"schema": request}}},
			"description": description}),
	}
}
