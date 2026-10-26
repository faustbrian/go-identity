package organizationhttp

import (
	"encoding/json"

	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

func invitationWire(op organization.Operation) *identityhttp.WireOperation {
	id := map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	cursor := map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[A-Za-z0-9_-]+$"}
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	invitation := invitationViewSchema()
	success := object([]string{"invitation"}, map[string]any{"invitation": invitation})
	parameters := []any{map[string]any{"name": "organizationID", "in": "query", "required": true, "schema": id}, map[string]any{"name": "invitationID", "in": "query", "required": true, "schema": id}}
	description := "Explicit bearer-only owner-authorized invitation metadata read. Recipient access is not inferred from an invitation ID or membership; the native Get owner retains its owner-only policy. "
	if op == organization.InvitationListMine {
		success = object([]string{"invitations"}, map[string]any{"invitations": map[string]any{"type": "array", "maxItems": 200, "items": invitation}, "nextCursor": cursor})
		parameters = []any{map[string]any{"name": "cursor", "in": "query", "required": false, "schema": cursor}, map[string]any{"name": "limit", "in": "query", "required": false, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "default": 100}}}
		description = "Current verified recipient discovery without organization membership. Native ListMine matches each invitation's original verified identifier ID/version against current authority; no address or recipient selector is accepted. All installed lifecycle states are included; expiry is projected at its exclusive boundary. Pages are current-state keysets in bytewise invitation-ID order, not snapshots; use the same subject-bound opaque cursor unchanged, and restart to see earlier additions. "
	}
	if op == organization.InvitationList {
		success = object([]string{"invitations"}, map[string]any{"invitations": map[string]any{"type": "array", "maxItems": 100, "items": invitation}, "nextCursor": id})
		parameters = []any{map[string]any{"name": "organizationID", "in": "query", "required": true, "schema": id}, map[string]any{"name": "cursor", "in": "query", "required": false, "schema": id}, map[string]any{"name": "limit", "in": "query", "required": true, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}}
		description = "Current organization-owner-only invitation list. Explicit limit1..100; cursor is the exclusive last invitation ID in bytewise order, not the recipient's opaque cursor. Pages are current state, not snapshots; restart to see earlier additions. Each request rechecks native organization and owner authority. No recipient, delivery or proof authority is disclosed. "
	}
	description += "Exactly one strict Authorization Bearer native session token, exact HTTPS tenant host, current verified session and shared canonical rate.safe admission are required. Cookies supply no fallback authority. Idempotency-Key, request body, alternate identity and tenant channels are forbidden. Closed bounded no-store JSON contains no email, proof, encrypted delivery custody, internal authority or acceptance permission. No session refresh, mutation, automatic retry or positive authority cache."
	failure := object([]string{"error"}, map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "forbidden", "unavailable", "rate_limited", "not_found", "method_not_allowed", "misdirected_request", "https_required"}}})
	responses := map[string]any{}
	for _, status := range []string{"200", "400", "403", "404", "405", "421", "429", "503"} {
		schema := failure
		if status == "200" {
			schema = success
		}
		responses[status] = map[string]any{"description": "Bounded no-store JSON; no credentials or redirects.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Ceiling seconds for a known rate rejection; no automatic retry.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	wire, _ := json.Marshal(map[string]any{"operationId": string(op), "description": description, "parameters": parameters, "security": []any{map[string]any{"OrganizationBearer": []string{}}}, "responses": responses})
	return &identityhttp.WireOperation{Definition: wire}
}

func invitationViewSchema() any {
	id := map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"id", "organizationID", "role", "status", "version", "expiresAt"}, "properties": map[string]any{"id": id, "organizationID": id, "role": map[string]any{"type": "string", "const": "member"}, "status": map[string]any{"type": "string", "enum": []string{"pending", "accepted", "expired", "cancelled", "rejected"}}, "version": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}, "expiresAt": map[string]any{"type": "string", "format": "date-time"}}}
}

func invitationSendWire() *identityhttp.WireOperation {
	return operationWire(organization.InvitationSend)
}
