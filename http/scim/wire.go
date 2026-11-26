package scimhttp

import (
	"encoding/json"
	"strconv"

	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

type fields = map[string]any

const (
	bulkRequestURN  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	bulkResponseURN = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	discoveryURN    = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	errorURN        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

func scimOperationWire(operation string, policy scim.BulkPolicy) *identityhttp.WireOperation {
	responses := fields{}
	for status, description := range map[int]string{
		400: "Invalid request.", 401: "A SCIM bearer credential is required.",
		403: "The authenticated client or resource tenant is not authorized.",
		429: "The shared protocol quota is exhausted.", 503: "Authority or the outcome is unavailable.",
	} {
		responses[strconv.Itoa(status)] = wireResponse(description, fields{"$ref": "#/components/schemas/SCIMError"})
	}
	responses["429"].(fields)["headers"] = fields{"Retry-After": fields{
		"description": "Seconds until the longest exhausted bucket permits a retry.",
		"schema":      fields{"type": "integer", "minimum": 1, "maximum": 3600},
	}}
	op := fields{
		"operationId": operation, "security": []fields{{"SCIMBearer": []string{}}}, "responses": responses,
	}
	wire := &identityhttp.WireOperation{}
	if operation == bulkOperation {
		op["summary"] = "Execute a complete bounded SCIM Bulk request"
		op["description"] = "Processed children are returned in request order. The executor retains the original authorized result on replay and does not issue a partial response for unresolved work."
		op["parameters"] = []fields{{"name": "Idempotency-Key", "in": "header", "required": false,
			"schema": fields{"type": "string", "minLength": 1, "maxLength": 256}}}
		op["requestBody"] = fields{"required": true, "content": fields{scimMedia: fields{"schema": bulkRequestSchema(policy)}}}
		responses["200"] = wireResponse("Complete BulkResponse.", bulkResponseSchema(policy))
		for status, description := range map[string]string{
			"409": "The optional key conflicts with the canonical request.",
			"413": "The request or preflight response exceeds an effective limit.",
			"415": "SCIM JSON with identity content encoding is required.",
			"501": "The requested profile is not supported by this executor.",
		} {
			responses[status] = wireResponse(description, fields{"$ref": "#/components/schemas/SCIMError"})
		}
		wire.SecuritySchemes = []identityhttp.WireComponent{{Name: "SCIMBearer", Definition: wireJSON(fields{"type": "http", "scheme": "bearer"})}}
		wire.Schemas = []identityhttp.WireComponent{{Name: "SCIMError", Definition: wireJSON(wireObject([]string{"schemas", "status", "detail"}, fields{
			"schemas": schemaURN(errorURN), "status": fields{"type": "string", "pattern": "^[45][0-9]{2}$"},
			"scimType": fields{"type": "string"}, "detail": fields{"type": "string"},
		}))}}
	} else {
		op["summary"] = "Read SCIM capabilities for the selected Bulk executor"
		responses["200"] = wireResponse("Authorized effective ServiceProviderConfig.", discoverySchema(policy))
		responses["415"] = wireResponse("A discovery request cannot carry content encoding.", fields{"$ref": "#/components/schemas/SCIMError"})
	}
	wire.Definition = wireJSON(op)
	return wire
}

func bulkRequestSchema(policy scim.BulkPolicy) fields {
	child := wireObject([]string{"method", "path"}, fields{
		"method": fields{"type": "string"}, "path": fields{"type": "string"}, "bulkId": fields{"type": "string"},
		"version": fields{"type": "string"}, "data": fields{"type": "object"},
	})
	return wireObject([]string{"schemas", "Operations"}, fields{
		"schemas": schemaURN(bulkRequestURN), "failOnErrors": fields{"type": "integer", "minimum": 0, "maximum": 100},
		"Operations": fields{"type": "array", "minItems": 1, "maxItems": policy.MaxOperations, "items": child},
	})
}

func bulkResponseSchema(policy scim.BulkPolicy) fields {
	child := wireObject([]string{"method", "status"}, fields{
		"method": fields{"type": "string"}, "bulkId": fields{"type": "string"},
		"status": fields{"type": "string", "pattern": "^[245][0-9]{2}$"}, "location": fields{"type": "string"},
		"version": fields{"type": "string"}, "response": fields{"$ref": "#/components/schemas/SCIMError"},
	})
	return wireObject([]string{"schemas", "Operations"}, fields{
		"schemas":    schemaURN(bulkResponseURN),
		"Operations": fields{"type": "array", "maxItems": policy.MaxOperations, "items": child},
	})
}

func discoverySchema(policy scim.BulkPolicy) fields {
	flag := func(supported bool) fields {
		return wireObject([]string{"supported"}, fields{"supported": fields{"const": supported}})
	}
	return wireObject(
		[]string{"schemas", "bulk", "patch", "filter", "changePassword", "sort", "etag", "authenticationSchemes"},
		fields{
			"schemas": schemaURN(discoveryURN), "documentationUri": fields{"type": "string"},
			"bulk": wireObject([]string{"supported", "maxOperations", "maxPayloadSize"}, fields{
				"supported": fields{"const": true}, "maxOperations": fields{"const": policy.MaxOperations},
				"maxPayloadSize": fields{"const": policy.MaxPayloadBytes},
			}),
			"patch": flag(true), "sort": flag(true), "etag": flag(true), "changePassword": flag(false),
			"filter": wireObject([]string{"supported", "maxResults"}, fields{
				"supported": fields{"const": true}, "maxResults": fields{"type": "integer", "minimum": 1, "maximum": 1000},
			}),
			"authenticationSchemes": fields{"type": "array", "minItems": 1, "maxItems": 1, "items": fields{"type": "object"}},
		},
	)
}

func wireObject(required []string, properties fields) fields {
	return fields{"type": "object", "required": required, "properties": properties, "additionalProperties": false}
}

func schemaURN(urn string) fields {
	return fields{"type": "array", "minItems": 1, "maxItems": 1, "items": fields{"const": urn}}
}

func wireResponse(description string, schema fields) fields {
	return fields{"description": description, "content": fields{scimMedia: fields{"schema": schema}}}
}

// Values built above are finite literals and bounded policy integers.
func wireJSON(v fields) []byte {
	encoded, _ := json.Marshal(v)
	return encoded
}
