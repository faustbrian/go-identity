package organizationhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

func operationWire(op organization.Operation) *identityhttp.WireOperation {
	text := func(min, max int) any { return map[string]any{"type": "string", "minLength": min, "maxLength": max} }
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	version := func(min uint64) any {
		return map[string]any{"type": "integer", "minimum": min, "maximum": ^uint64(0), "description": "Exact unsigned decimal integer, including the terminal durable version."}
	}
	// Root validOperationVersions requires expected versions to leave room for
	// a successor. Actual durable receipts and reads may contain MaxUint64.
	requestVersion := func(min uint64) any {
		return map[string]any{"type": "integer", "minimum": min, "maximum": ^uint64(0) - 1, "description": "Advanceable expected version; exact unsigned decimal integer. Fractions, exponent notation and overflow are rejected."}
	}
	id := text(1, 128)
	command := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	errorCode := map[string]any{"type": "string", "enum": []string{"invalid_request", "forbidden", "last_owner", "conflict", "limit_exceeded", "unavailable", "in_progress", "rate_limited", "not_found", "method_not_allowed", "misdirected_request", "https_required"}}
	member := object([]string{"userID", "role", "version"}, map[string]any{"userID": id, "role": map[string]any{"enum": []string{"owner", "administrator", "member"}, "type": "string"}, "version": version(1)})
	org := object([]string{"id", "name", "slug", "version"}, map[string]any{"id": id, "name": text(1, 256), "slug": text(1, 63), "version": version(1)})
	readFields := map[string]any{"organization": org, "membership": member}
	readRequired := []string{"organization", "membership"}
	if op == organization.ListMembers {
		readRequired = append(readRequired, "members")
		readFields["members"] = map[string]any{"type": "array", "maxItems": 100, "items": member}
		readFields["nextCursor"] = id
	}
	scope := object([]string{"commandID", "tenantID", "userID", "actorID", "actorKind", "operationID", "recordID", "policyID", "policyVersion", "schemaID", "schemaVersion", "correlationID"}, map[string]any{"commandID": command, "tenantID": id, "userID": id, "actorID": id, "actorKind": map[string]any{"const": "user"}, "operationID": map[string]any{"const": string(op)}, "recordID": id, "policyID": id, "policyVersion": version(1), "schemaID": id, "schemaVersion": version(1), "correlationID": id})
	mutationFields := map[string]any{"committed": map[string]any{"type": "boolean"}, "commitOutcome": map[string]any{"enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}, "type": "string"}, "commandID": command, "organizationID": id, "memberID": id, "beforeVersion": version(0), "afterVersion": version(1), "recovery": scope, "error": errorCode}
	mutationRequired := []string{"commandID", "organizationID", "memberID", "afterVersion", "recovery"}
	if op == organization.InvitationSend {
		delete(mutationFields, "memberID")
		mutationFields["invitationID"] = id
		mutationFields["invitation"] = invitationViewSchema()
		mutationFields["deliveryState"] = map[string]any{"type": "string", "enum": []string{"queued", "attempting", "accepted", "delivered", "rejected", "bounced", "cancelled", "unknown", "retry_wait", "expired", "exhausted", "superseded", "transient_failure"}, "description": "Current authorized delivery observation; queued is local durable admission and accepted is provider acceptance, neither confirms delivery."}
		mutationRequired = []string{"commandID", "organizationID", "invitationID", "afterVersion", "recovery", "invitation", "deliveryState"}
	}
	mutation := object([]string{"committed", "commitOutcome"}, mutationFields)
	errorSchema := object([]string{"error"}, map[string]any{"error": errorCode})
	failure := any(errorSchema)
	success := object(readRequired, readFields)
	if selectedMutation(op) {
		failure = map[string]any{"oneOf": []any{errorSchema, mutation}}
		success = map[string]any{"allOf": []any{
			mutation,
			map[string]any{
				"required":   mutationRequired,
				"properties": map[string]any{"committed": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}},
				"not":        map[string]any{"required": []string{"error"}},
			},
		}}
	}
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "404", "405", "409", "421", "429", "503"} {
		schema := failure
		if status == "200" {
			schema = success
		}
		responses[status] = map[string]any{"description": "Bounded no-store JSON. Original command outcome and safe recovery correlation grant no authority; no credentials or redirects are issued.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Bounded ceiling seconds for a known audited rate rejection; no automatic retry.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	description := "Explicit bearer-only organization profile. Exactly one Authorization Bearer credential; cookies never supply fallback authority. Exact HTTPS host-mapped tenant and trusted full client IP; closed bounded JSON/query and no identity, tenant, actor or command override. Current native authorization/protected effects remain with the organization owner. No invitation acceptance, teams, browser workflow or active organization selection. "
	if selectedMutation(op) {
		description += "Canonical shared rate.admin atomically charges actor30/minute, tenant100/minute and trustedIP60/minute; denial/outage fails closed with mandatory secret-free auditing. "
	} else {
		description += "Canonical rate.safe applies before the current authorized primary read; no session refresh or positive authority cache. "
	}
	parameters := []any{}
	definition := map[string]any{"operationId": string(op), "security": []any{map[string]any{"OrganizationBearer": []string{}}}, "responses": responses}
	if op == organization.Create || op == organization.AddMember || op == organization.InvitationSend {
		description += "Exactly one unchanged Idempotency-Key header is required. Owner-allocated organization/command identity and original keyed recovery never rebuild authority, renew deadlines or resubmit unknown work. "
		parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[!#$%&'*+.^_`|~A-Za-z0-9-]+$", "writeOnly": true}})
	} else {
		description += "Idempotency-Key and all alternate request-key channels are forbidden. "
	}
	if selectedMutation(op) {
		var fields map[string]any
		var required []string
		if op == organization.Create {
			required = []string{"name", "slug"}
			fields = map[string]any{"name": text(1, 256), "slug": map[string]any{"type": "string", "minLength": 1, "maxLength": 63, "pattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"}}
		} else if op == organization.InvitationSend {
			required = []string{"organizationID", "organizationVersion", "recipientUserID", "recipientIdentifierID"}
			fields = map[string]any{"organizationID": id, "organizationVersion": version(1), "recipientUserID": id, "recipientIdentifierID": id}
			description += "Exact verified recipient selection, never a submitted email address or claimed actor. The native owner allocates invitation/command IDs and atomically queues encrypted proof delivery. Matching keys recover original metadata only. A successful current read returns invitation and delivery status; if that read fails, the original committed outcome remains explicit without current metadata. No proof or delivery effect ID is exported. "
		} else {
			required = []string{"organizationID", "userID", "organizationVersion", "memberVersion"}
			minimum := uint64(0)
			if op == organization.RemoveMember {
				minimum = 1
			}
			fields = map[string]any{"organizationID": id, "userID": id, "organizationVersion": requestVersion(1), "memberVersion": requestVersion(minimum)}
			if op == organization.AddMember {
				required = append(required, "role")
				fields["role"] = map[string]any{"type": "string", "enum": []string{"owner", "administrator", "member"}}
			}
		}
		definition["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object(required, fields)}}}
		if op == organization.RemoveMember {
			description += "Removal is naturally repeatable at exact organization/member versions, not keyed. Only an actual matching original durable effect and current-authorized native receipt prove a prior removal; absence or a tombstone alone is never success. Last-owner denial is distinct. "
		}
	} else {
		parameters = append(parameters, map[string]any{"name": "organizationID", "in": "query", "required": true, "schema": id})
		if op == organization.ListMembers {
			parameters = append(parameters, map[string]any{"name": "cursor", "in": "query", "required": false, "schema": id}, map[string]any{"name": "limit", "in": "query", "required": false, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 100}})
		}
	}
	definition["parameters"], definition["description"] = parameters, description
	wire, _ := json.Marshal(definition)
	return &identityhttp.WireOperation{Definition: wire}
}
