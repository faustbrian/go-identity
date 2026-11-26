package scimhttp

import (
	"strconv"

	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedUsersCreateWire(limits scim.Limits, bodyMaximum int) *identityhttp.WireOperation {
	// The native schema owner validates declared extensions and field policies.
	// This is the writable envelope, never the response id/meta projection.
	writable := fields{"type": "object", "required": []string{"schemas", "userName"}, "properties": fields{
		"schemas":    fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"userName":   fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"externalId": fields{"type": "string", "maxLength": limits.StringBytes},
	}, "not": fields{"anyOf": []fields{{"required": []string{"id"}}, {"required": []string{"meta"}}}}, "additionalProperties": true,
		"description": "Native schema-governed writable User and declared extensions. Raw/decoded body bound is " + strconv.Itoa(bodyMaximum) + " bytes. Native resource depth, attributes and strings apply; server id/meta and unsupported password writes deny before admission."}
	resource := fields{"type": "object", "required": []string{"schemas", "id", "meta"}, "properties": fields{
		"schemas": fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"id":      fields{"type": "string", "minLength": 22, "maxLength": 22},
		"meta": fields{"type": "object", "required": []string{"resourceType", "version", "location"}, "properties": fields{
			"resourceType": fields{"const": "User"}, "version": fields{"type": "string", "minLength": 3, "maxLength": 256}, "location": fields{"type": "string", "format": "uri"},
		}},
	}, "additionalProperties": true, "description": "Exact bounded native User response; write-only and returned-never attributes are absent."}
	errorProperties := fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	}
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, errorProperties)
	success := wireResponse("Native User Create committed/recovered representation, with its exact authoritative ETag and Location.", resource)
	success["headers"] = fields{
		"ETag":     fields{"required": true, "schema": fields{"type": "string", "minLength": 3, "maxLength": 256}},
		"Location": fields{"required": true, "schema": fields{"type": "string", "format": "uri"}, "description": "Exact native canonical HTTPS resource location on the selected effective origin."},
	}
	responses := fields{"201": success}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "413", "415", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM Error, without partial resource, ETag, Location or credential. Failure does not itself prove rollback.", errorSchema)
	}
	responses["413"] = wireResponse("SCIM payload rejection. The fixed outer stream-cap error contains schemas/status; native rejections may also contain detail.", wireObject([]string{"schemas", "status"}, errorProperties))
	for _, failure := range []struct{ status, code string }{
		{"400", "invalid_request"}, {"403", "https_required"}, {"421", "misdirected_request"}, {"503", "unavailable"},
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
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: "SCIMManagedUserCreateBearer", Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped managed SCIM bearer; cookies never supply authority. Native current connection, organization and operation authorization remain mandatory."}`)}},
		Definition: wireJSON(fields{"operationId": managedUsersCreateOperation, "responses": responses,
			"security":    []fields{{"SCIMManagedUserCreateBearer": []string{}}},
			"requestBody": fields{"required": true, "content": fields{scimMedia: fields{"schema": writable}}},
			"description": "Exact HTTPS User collection POST only, with no query, client request key, cookie authority, CSRF requirement, If-Match or range. Forward bounded raw UTF-8/identity SCIM input unchanged; native schema/current bearer/connection/organization/policy checks precede one shared atomic rate.protocol charge (client120/minute, full IP240/minute, tenant600/minute) and all mapping/command effects. No fallback, private replay authority or automatic retry. Native canonical command/replay and original deadlines remain authoritative. Emit only complete native 201 body with bound strong ETag and canonical Location; failures expose neither header nor partial data. No read, other write, search, Groups, discovery or connection lifecycle is selected."}),
	}
}
