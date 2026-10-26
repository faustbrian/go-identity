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
	if op == organization.InvitationAccept {
		mutationFields["invitationID"] = id
		mutationRequired = append(mutationRequired, "invitationID")
	}
	if op == organization.InvitationResend {
		delete(mutationFields, "memberID")
		mutationFields["invitationID"] = id
		mutationFields["deliveryState"] = map[string]any{"type": "string", "enum": []string{"queued", "attempting", "accepted", "delivered", "rejected", "bounced", "cancelled", "unknown", "retry_wait", "expired", "exhausted", "superseded", "transient_failure"}, "description": "Authorized observation of this original command's delivery, not the latest successor. Queued is local admission, accepted is provider acceptance, neither confirms delivery. Absent on observation failure; unknown never authorizes redispatch."}
		mutationRequired = []string{"commandID", "organizationID", "invitationID", "beforeVersion", "afterVersion", "recovery", "deliveryState"}
	}
	if op == organization.InvitationCancel || op == organization.InvitationReject {
		delete(mutationFields, "memberID")
		mutationFields["invitationID"] = id
		state := "cancelled"
		if op == organization.InvitationReject {
			state = "rejected"
		}
		mutationFields["state"] = map[string]any{"type": "string", "const": state}
		mutationRequired = []string{"commandID", "organizationID", "invitationID", "beforeVersion", "afterVersion", "recovery", "state"}
	}
	mutation := object([]string{"committed", "commitOutcome"}, mutationFields)
	errorSchema := object([]string{"error"}, map[string]any{"error": errorCode})
	failure := any(errorSchema)
	success := object(readRequired, readFields)
	if op == organization.SlugAvailable {
		success = object([]string{"available"}, map[string]any{"available": map[string]any{"type": "boolean"}})
	}
	if op == organization.ListOrganizations {
		success = object([]string{"organizations"}, map[string]any{"organizations": map[string]any{"type": "array", "maxItems": 200, "items": org}, "nextCursor": map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[A-Za-z0-9_-]+$"}})
	}
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
	if op == organization.InvitationAccept {
		description = "Explicit bearer-only one-time invitation acceptance. Exactly one Authorization Bearer session and HTTPS mapped tenant are mandatory; ambient cookies provide no authority. Current native recipient/session/verified identifier, exact invitation/organization versions and signed original capability are required. Canonical rate.secret charges trusted IP10/10m, authenticated subject10/10m and original challenge5/signed lifetime before the same native preparation executes. Membership, one-use proof, scoped authority, audit and lifecycle effects commit atomically. Preserve the caller-known original command ID. Re-posting a consumed proof is not original-outcome recovery; use the safe returned binding and organization through the direct current-authorized native recovery API. A bare command ID is insufficient after complete response loss. No automatic retry, recovery route, refreshed validity, credential or delivery is provided. "
	} else if selectedMutation(op) && op != organization.InvitationReject && op != organization.LeaveMember {
		description += "Canonical shared rate.admin atomically charges actor30/minute, tenant100/minute and trustedIP60/minute; denial/outage fails closed with mandatory secret-free auditing. "
	} else if op == organization.InvitationReject {
		description = "Explicit bearer-only intended-recipient rejection with canonical rate.safe admission. Exact HTTPS host-mapped tenant, current verified recipient/session and exact organization/invitation versions are mandatory. IP100/minute and tenant-scoped subject300/minute counters are shared with other safe routes; known shared-store unavailability retains the canonical bounded IP20/minute emergency policy with required degradation recording. No manager, membership, proof or organization-read permission substitutes for recipient authority. "
	} else if op == organization.LeaveMember {
		description += "Canonical rate.safe applies before the native protected self-leave mutation; no post-departure membership read, session refresh or positive authority cache. "
	} else {
		description += "Canonical rate.safe applies before the current authorized primary read; no session refresh or positive authority cache. "
	}
	parameters := []any{}
	definition := map[string]any{"operationId": string(op), "security": []any{map[string]any{"OrganizationBearer": []string{}}}, "responses": responses}
	if op == organization.Create || op == organization.Update || op == organization.AddMember || op == organization.UpdateMember || op == organization.InvitationSend || op == organization.InvitationResend {
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
		} else if op == organization.Update {
			required = []string{"organizationID", "organizationVersion", "name", "slug"}
			fields = map[string]any{"organizationID": id, "organizationVersion": requestVersion(1), "name": text(1, 256), "slug": map[string]any{"type": "string", "minLength": 1, "maxLength": 63, "pattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"}}
		} else if op == organization.LeaveMember {
			required = []string{"organizationID", "organizationVersion"}
			fields = map[string]any{"organizationID": id, "organizationVersion": requestVersion(1)}
			description += "Naturally repeatable self-leave uses shared rate.safe admission, never administrator admission. The current verified human is the target; no user, member version, command ID, key or proof override is accepted. Native current policy, last-owner protection and atomic effects remain authoritative. Matching repeats return actual original metadata after departure, never infer success from absence or remove a readmitted membership. An unknown outcome requires reconciliation, not automatic replay. No post-leave membership read or HTTP recovery route is added. "
		} else if op == organization.InvitationSend {
			required = []string{"organizationID", "organizationVersion", "recipientUserID", "recipientIdentifierID"}
			fields = map[string]any{"organizationID": id, "organizationVersion": version(1), "recipientUserID": id, "recipientIdentifierID": id}
			description += "Exact verified recipient selection, never a submitted email address or claimed actor. The native owner allocates invitation/command IDs and atomically queues encrypted proof delivery. Matching keys recover original metadata only. A successful current read returns invitation and delivery status; if that read fails, the original committed outcome remains explicit without current metadata. No proof or delivery effect ID is exported. "
		} else if op == organization.InvitationReject {
			required = []string{"organizationID", "organizationVersion", "invitationID", "invitationVersion"}
			fields = map[string]any{"organizationID": id, "organizationVersion": requestVersion(1), "invitationID": id, "invitationVersion": requestVersion(1)}
			description += "The native owner allocates and atomically commits the original rejection command. Natural repeats recover only actual original metadata under current recipient/session authority, never inferred from a terminal or absent row. Unknown outcomes require reconciliation, never automatic redispatch. No caller command, key, proof, membership or delivery projection is accepted or issued. "
		} else if op == organization.InvitationCancel {
			required = []string{"organizationID", "organizationVersion", "invitationID", "invitationVersion"}
			fields = map[string]any{"organizationID": id, "organizationVersion": requestVersion(1), "invitationID": id, "invitationVersion": requestVersion(1)}
			description += "Cancellation requires current native owner or administrator invitation permission, not recipient credentials or organization-read permission. The native owner allocates the original command and atomically terminally revokes the exact pending invitation. Matching natural repeats disclose only actual original metadata under current authority; missing or cancelled rows alone never prove success. Original committed state is returned without a membership, recipient or delivery read. Unknown outcomes require reconciliation, never automatic redispatch. "
		} else if op == organization.InvitationResend {
			required = []string{"organizationID", "organizationVersion", "invitationID", "invitationVersion"}
			fields = map[string]any{"organizationID": id, "organizationVersion": version(1), "invitationID": id, "invitationVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 2, "description": "Exact advanceable invitation version leaving room for successor issuance and its terminal transition. Fractions, exponent notation and overflow are rejected."}}
			description += "Resend requires current native owner or administrator authority for the exact pending invitation; recipient, member role and original exclusive expiry cannot be overridden or renewed. The sole native command atomically supersedes the predecessor proof and enqueues one encrypted successor. Matching keys never reprepare, regenerate or redispatch, including unknown outcomes. Returns the original command's authorized delivery state, not a latest-invitation read; status/authority failure retains known commitment without delivery observation. No proof, delivery effect identity, address or new command selector is accepted or exported. "
		} else if op == organization.InvitationAccept {
			required = []string{"commandID", "organizationID", "invitationID", "organizationVersion", "invitationVersion", "token"}
			fields = map[string]any{"commandID": command, "organizationID": id, "invitationID": id, "organizationVersion": version(1), "invitationVersion": version(1), "token": map[string]any{"type": "string", "minLength": 32, "maxLength": 4096, "writeOnly": true}}
		} else {
			required = []string{"organizationID", "userID", "organizationVersion", "memberVersion"}
			minimum := uint64(0)
			if op == organization.RemoveMember || op == organization.UpdateMember {
				minimum = 1
			}
			fields = map[string]any{"organizationID": id, "userID": id, "organizationVersion": requestVersion(1), "memberVersion": requestVersion(minimum)}
			if op == organization.AddMember || op == organization.UpdateMember {
				required = append(required, "role")
				fields["role"] = map[string]any{"type": "string", "enum": []string{"owner", "administrator", "member"}}
			}
		}
		definition["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": object(required, fields)}}}
		if op == organization.RemoveMember {
			description += "Removal is naturally repeatable at exact organization/member versions, not keyed. Only an actual matching original durable effect and current-authorized native receipt prove a prior removal; absence or a tombstone alone is never success. Last-owner denial is distinct. "
		}
	} else if op == organization.ListOrganizations {
		parameters = append(parameters,
			map[string]any{"name": "limit", "in": "query", "required": true, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 200}, "description": "Required canonical unsigned decimal; no default, leading zeros, sign or exponent."},
			map[string]any{"name": "cursor", "in": "query", "required": false, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[A-Za-z0-9_-]+$"}})
		description += "Lists only the current authenticated human's active organizations under current membership and per-organization policy. No arbitrary user, tenant or organization selector. Bytewise organization-ID order and an unchanged native continuation are not a snapshot: earlier additions require restarting. Omit cursor to start; no default limit. Authority errors disclose no partial page. "
	} else if op == organization.SlugAvailable {
		parameters = append(parameters, map[string]any{"name": "slug", "in": "query", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 63, "pattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"}})
		description += "An authenticated human may check one tenant-local candidate without organization membership or management permission. Returns only advisory availability, including retained archived occupancy; no reservation or later create/update guarantee, organization ID or metadata. "
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
