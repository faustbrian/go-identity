package mfahttp

import (
	"encoding/json"
	"slices"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
)

func factorUpdateWire(c FactorUpdateConfig) *identityhttp.WireOperation {
	actions, _ := factorUpdateActions(c.Actions)
	verbs := make([]string, 0, len(actions))
	states := make([]int, 0, len(actions))
	legacyStates := make([]int, 0, len(actions))
	for _, action := range actions {
		if action == mfa.Remove {
			verbs = append(verbs, "remove")
			states = append(states, 3)
			legacyStates = append(legacyStates, 3)
		} else if action == mfa.Replace {
			verbs = append(verbs, "replace")
			states = append(states, 1)
		} else {
			verbs = append(verbs, "rename")
			states = append(states, 2)
			legacyStates = append(legacyStates, 2)
		}
	}
	object := func(required []string, fields map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": fields}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	label := map[string]any{"type": "string", "maxLength": 128, "description": "Untrusted presentation text, at most128 UTF-8 bytes; empty string explicitly clears the label. No control characters."}
	version := map[string]any{"type": "integer", "minimum": 1, "maximum": uint64(^uint64(0) - 1)}
	factor := object([]string{"id", "method", "label", "state", "createdAt", "version"}, map[string]any{"id": id, "method": map[string]any{"const": "totp"}, "label": label, "state": map[string]any{"enum": states}, "createdAt": map[string]any{"type": "string", "format": "date-time"}, "lastUsedAt": map[string]any{"type": "string", "format": "date-time"}, "version": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}})
	success := object([]string{"commitOutcome", "commandID", "factor"}, map[string]any{"commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "factor": factor})
	if slices.Contains(actions, mfa.Replace) {
		s := success.(map[string]any)
		s["properties"].(map[string]any)["replacement"] = object([]string{"enrollmentID", "factorMethod", "expiresAt", "version", "recoveryCodes"}, map[string]any{"enrollmentID": id, "factorMethod": map[string]any{"const": "totp"}, "expiresAt": map[string]any{"type": "string", "format": "date-time"}, "version": map[string]any{"const": 1}, "recoveryCodes": map[string]any{"type": "array", "minItems": c.ReplacementCodeCount, "maxItems": c.ReplacementCodeCount, "uniqueItems": true, "items": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"}}})
		if len(legacyStates) == 0 {
			s["required"] = []string{"commitOutcome", "commandID", "factor", "replacement"}
		} else {
			s["oneOf"] = []any{
				map[string]any{"properties": map[string]any{"factor": map[string]any{"properties": map[string]any{"state": map[string]any{"const": 1}}}}, "required": []string{"replacement"}},
				map[string]any{"properties": map[string]any{"factor": map[string]any{"properties": map[string]any{"state": map[string]any{"enum": legacyStates}}}}, "not": map[string]any{"required": []string{"replacement"}}},
			}
		}
	}
	failure := object([]string{"commitOutcome", "error"}, map[string]any{"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_or_csrf_denied", "denied", "rate_limited", "unavailable", "conflict", "in_progress"}}})
	response := func(schema any) any {
		return map[string]any{"description": "No-store metadata/observation. A known commitment is conserved even when metadata is withheld; absence is not rollback.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	properties := map[string]any{"factorID": id, "proofID": id, "action": map[string]any{"enum": verbs}, "expectedVersion": version}
	if slices.Contains(actions, mfa.Rename) {
		properties["name"] = label
	}
	body := object([]string{"factorID", "proofID", "action", "expectedVersion"}, properties).(map[string]any)
	if len(actions) == 1 && actions[0] == mfa.Rename {
		body["required"] = []string{"factorID", "proofID", "action", "name", "expectedVersion"}
	}
	if len(actions) == 1 && actions[0] == mfa.Replace {
		properties["expectedVersion"] = map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 2}
	}
	if len(actions) > 1 {
		branches := make([]any, 0, len(actions))
		for _, action := range actions {
			verb := "rename"
			if action == mfa.Remove {
				verb = "remove"
			} else if action == mfa.Replace {
				verb = "replace"
			}
			branch := map[string]any{"properties": map[string]any{"action": map[string]any{"const": verb}}}
			if action == mfa.Replace {
				branch["properties"].(map[string]any)["expectedVersion"] = map[string]any{"maximum": ^uint64(0) - 2}
			}
			if action == mfa.Rename {
				branch["required"] = []string{"name"}
			} else {
				branch["not"] = map[string]any{"required": []string{"name"}}
			}
			branches = append(branches, branch)
		}
		body["oneOf"] = branches
	}
	description := "Explicit cookie-only TOTP management with original action/session-bound factor proof, native recent-primary policy, keyed shared quotas, optimistic version and protected atomic proof/session/audit effects. "
	if slices.Contains(actions, mfa.Remove) {
		description += "Removal is explicitly selected and requires native current recovery-path authority; it erases factor material and retires dependent recovery codes. "
	} else if !slices.Contains(actions, mfa.Replace) {
		description += "Only rename is selected; removal is unavailable. "
	} else {
		description += "Removal is unavailable. "
	}
	if slices.Contains(actions, mfa.Replace) {
		description += "Replacement starts a distinct pending successor and explicitly delivers its recovery codes once. The predecessor, existing recovery and source session remain usable until code-confirmed successor activation, which retires predecessor authority and revokes sessions atomically. Command identity is derived by the native keyed owner, never supplied in the body. No Authorization, query, target-user, method/purpose override, trailer or session issuance. Replay/recovery disclose no fresh factor metadata or recovery codes."
	} else {
		description += "Replacement is unavailable. Command identity is derived by the native keyed owner, never supplied in the body. No Authorization, query, target-user, method/purpose override, trailer, secret or session issuance. Original evidence expiry is never renewed; retry/recovery disclose no fresh factor metadata."
	}
	d, _ := json.Marshal(map[string]any{"operationId": "identity.mfa.factor-update", "description": description, "security": []any{map[string]any{"MFAFactorUpdateSession": []string{}}}, "parameters": []any{map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}}, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"type": "string", "enum": c.TrustedOrigins}}, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses})
	cookie, _ := c.Cookie.DeletionAttributes()
	scheme, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name})
	return &identityhttp.WireOperation{Definition: d, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAFactorUpdateSession", Definition: scheme}}}
}
