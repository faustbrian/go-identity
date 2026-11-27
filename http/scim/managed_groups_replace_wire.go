package scimhttp

import (
	"strconv"

	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

func managedGroupWireMember(limits scim.Limits) fields {
	return wireObject([]string{"value"}, fields{
		"value":   fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"type":    fields{"type": "string", "maxLength": limits.StringBytes, "description": "Optional native case-insensitive User or Group discriminator; native resolves an omitted or empty value."},
		"$ref":    fields{"type": "string", "maxLength": limits.StringBytes, "description": "Optional native canonical member reference; native resolves an omitted or empty value."},
		"display": fields{"type": "string", "maxLength": limits.StringBytes},
	})
}

func managedGroupsReplaceWire(limits scim.Limits, bodyMaximum, maximumMembers int) *identityhttp.WireOperation {
	member := managedGroupWireMember(limits)
	// The native schema owner validates declared extensions and field policies.
	// This is the writable Group envelope, never a second native schema mapper.
	writable := fields{"type": "object", "required": []string{"schemas", "displayName"}, "properties": fields{
		"schemas":     fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"displayName": fields{"type": "string", "minLength": 1, "maxLength": limits.StringBytes},
		"externalId":  fields{"type": "string", "maxLength": limits.StringBytes},
		"members":     fields{"type": "array", "maxItems": maximumMembers, "items": member},
	}, "not": fields{"anyOf": []fields{{"required": []string{"id"}}, {"required": []string{"meta"}}}}, "additionalProperties": true,
		"description": "Native schema-governed writable Group and declared extensions. Raw/decoded body bound is " + strconv.Itoa(bodyMaximum) + " bytes. Native resource depth, attributes and strings apply. Server id/meta writes deny; the explicit configured member ceiling and immutable reference rules apply before admission."}
	return managedGroupsConditionalWire(limits, maximumMembers, writable, member,
		managedGroupsReplaceOperation, "SCIMManagedGroupReplaceBearer", "Native Group Replace committed/recovered representation, with its exact authoritative ETag and Location.",
		"Exact HTTPS Group resource PUT only, with required original If-Match and no query, client request key, cookie authority, CSRF requirement or range. Forward bounded raw UTF-8/identity SCIM input unchanged; native schema/current bearer/connection/organization/policy checks precede one shared atomic rate.protocol charge (client120/minute, full IP240/minute, tenant600/minute) and all mapping/command effects. No fallback, private replay authority or automatic retry. Native canonical command/replay and original deadlines remain authoritative. Equivalent headerless retries reuse the original command, representation and ETag; each transport attempt obtains one fresh protocol admission. Complete replacement omission semantics, atomic CAS and typed scoped Group member integrity stay native-owned. Emit only complete native 200 body with bound strong ETag and canonical Location; failures expose neither header nor partial data. The configured Group member ceiling is "+strconv.Itoa(maximumMembers)+" (zero allows only empty Groups). No read, other write, search, Users, discovery or connection lifecycle is selected.")
}

func managedGroupsPatchWire(limits scim.Limits, bodyMaximum, maximumMembers int) *identityhttp.WireOperation {
	patch := wireObject([]string{"schemas", "Operations"}, fields{
		"schemas": schemaURN("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
		"Operations": fields{"type": "array", "minItems": 1, "maxItems": limits.PatchOperations, "items": wireObject([]string{"op"}, fields{
			"op":    fields{"type": "string", "enum": []string{"add", "remove", "replace"}},
			"path":  fields{"type": "string", "minLength": 1, "maxLength": limits.PathBytes},
			"value": fields{},
		})},
	})
	patch["description"] = "Canonical SCIM PatchOp form; native validation owns case matching, required paths and values, mutable fields, ordered operations and typed member limits. Raw/decoded body bound is " + strconv.Itoa(bodyMaximum) + " bytes."
	return managedGroupsConditionalWire(limits, maximumMembers, patch, managedGroupWireMember(limits),
		managedGroupsPatchOperation, "SCIMManagedGroupPatchBearer", "Native Group PATCH returns its exact committed or recovered representation, including ETag and Location.",
		"Opt-in HTTPS Group PATCH forwards the exact strong original If-Match and bounded raw PatchOp. Current native bearer, connection and authorization precede one shared protocol quota admission and any mapping or effects. Native original-command replay and atomic CAS preserve conditional writes, read-back and typed members. Replays do not reapply writes. The configured Group member ceiling is "+strconv.Itoa(maximumMembers)+" (zero allows only empty Groups). No query, caller key, cookie authority, automatic retry, or other route is selected.")
}

func managedGroupsConditionalWire(limits scim.Limits, maximumMembers int, request, member fields, operation, bearer, successDescription, description string) *identityhttp.WireOperation {
	resource := fields{"type": "object", "required": []string{"schemas", "id", "meta"}, "properties": fields{
		"schemas": fields{"type": "array", "minItems": 1, "maxItems": limits.ResourceAttributes, "items": fields{"type": "string", "maxLength": limits.StringBytes}},
		"id":      fields{"type": "string", "minLength": 22, "maxLength": 22},
		"members": fields{"type": "array", "maxItems": maximumMembers, "items": member},
		"meta": fields{"type": "object", "required": []string{"resourceType", "version", "location"}, "properties": fields{
			"resourceType": fields{"const": "Group"}, "version": fields{"type": "string", "minLength": 3, "maxLength": 256}, "location": fields{"type": "string", "format": "uri"},
		}},
	}, "additionalProperties": true, "description": "Exact bounded native Group response; write-only and returned-never attributes are absent."}
	errorProperties := fields{
		"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"}, "detail": fields{"type": "string"}, "scimType": fields{"type": "string"},
	}
	errorSchema := wireObject([]string{"schemas", "status", "detail"}, errorProperties)
	success := wireResponse(successDescription, resource)
	success["headers"] = fields{
		"ETag":     fields{"required": true, "schema": fields{"type": "string", "minLength": 3, "maxLength": 256}},
		"Location": fields{"required": true, "schema": fields{"type": "string", "format": "uri"}, "description": "Exact native canonical HTTPS resource location on the selected effective origin."},
	}
	responses := fields{"200": success}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "412", "428", "413", "415", "429", "500", "501", "503"} {
		responses[status] = wireResponse("Redacted SCIM Error, without partial resource, ETag, Location or credential. Failure does not itself prove rollback.", errorSchema)
	}
	responses["413"] = wireResponse("SCIM payload rejection. The fixed outer stream-cap error contains schemas/status; native rejections may also contain detail.", wireObject([]string{"schemas", "status"}, errorProperties))
	routerError := wireObject([]string{"error"}, fields{"error": fields{"type": "string", "minLength": 1, "maxLength": 64}})
	// Outer transport denials retain the router's distinct JSON envelope.
	for _, status := range []string{"400", "403", "404", "405", "503"} {
		response := responses[status].(fields)
		response["description"] = "Redacted SCIM or outer transport error; no partial Group, version or credential."
		response["content"].(fields)["application/json"] = fields{"schema": routerError}
	}
	responses["403"].(fields)["content"].(fields)["text/plain"] = fields{"schema": fields{"type": "string", "const": "identity.http.origin_denied\n", "description": "Fixed outer origin-guard denial."}}
	responses["421"] = fields{
		"description": "Request host is not selected for this router.",
		"content":     fields{"application/json": fields{"schema": routerError}},
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{"schema": fields{"type": "integer", "minimum": 1, "maximum": 3600}}}
	responses["405"].(fields)["headers"] = fields{"Allow": fields{"schema": fields{"type": "string"}, "description": "Only selected resource methods."}}
	return &identityhttp.WireOperation{
		SecuritySchemes: []identityhttp.WireComponent{{Name: bearer, Definition: []byte(`{"type":"http","scheme":"bearer","description":"Exactly one issued scoped managed SCIM bearer; cookies never supply authority. Native current connection, organization and operation authorization remain mandatory."}`)}},
		Definition: wireJSON(fields{"operationId": operation, "responses": responses,
			"security": []fields{{bearer: []string{}}},
			"parameters": []fields{
				{"name": "resource_id", "in": "path", "required": true, "schema": fields{"type": "string", "minLength": 1, "maxLength": min(128, limits.StringBytes), "pattern": "^[A-Za-z0-9._~-]+$"}, "description": "One exact unescaped Group segment, excluding dot, dot-dot and .search."},
				{"name": "If-Match", "in": "header", "required": true, "schema": fields{"type": "string", "minLength": 3, "maxLength": 256}, "description": "One exact strong native version. Native missing, malformed and stale denials are 428, 400 and 412."},
			},
			"requestBody": fields{"required": true, "content": fields{scimMedia: fields{"schema": request}}},
			"description": description}),
	}
}
