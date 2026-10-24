package passkeyhttp

import (
	"encoding/json"
	"strings"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func wireObject(required []string, properties map[string]any) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}
func wireText(maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
}
func wireID() map[string]any {
	return map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
}
func passkeyWire(c FeatureConfig, name string) *identityhttp.WireOperation {
	registration := strings.HasPrefix(name, "register-")
	options := strings.HasSuffix(name, "-options")
	list := name == "list"
	update := name == "update"
	deletion := name == "delete"
	management := update || deletion
	parameters := []any{}
	if !list {
		parameters = append(parameters, map[string]any{"name": "Origin", "in": "header", "required": true, "schema": wireText(2048)})
	}
	if registration && c.Registration != nil || management {
		description := "Original stored-session synchronizer; required with exact Origin."
		if registration && c.Signup != nil {
			description = "Required for the enrollment branch; forbidden for explicit signup."
		}
		parameters = append(parameters, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": !registration || c.Signup == nil, "description": description, "schema": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", "writeOnly": true}})
	}
	if options || management {
		parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$"}})
	}
	if list {
		parameters = append(parameters,
			map[string]any{"name": "after", "in": "query", "required": false, "schema": wireID()},
			map[string]any{"name": "limit", "in": "query", "required": false, "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 100}})
	}
	var request any
	if deletion {
		// A stored reference is an exact bounded kernel ID, not a newly
		// allocated command ID. In particular, imported ULIDs remain unchanged.
		reference := map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": `^[^\x00-\x20\x7f]+$`, "description": "Exact canonical kernel credential reference, at most128 UTF-8 bytes; never a raw authenticator credential."}
		request = wireObject([]string{"proofID", "referenceID", "expectedVersion"}, map[string]any{"proofID": wireID(), "referenceID": reference, "expectedVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 1}})
	} else if update {
		request = wireObject([]string{"proofID", "referenceID", "expectedVersion", "name"}, map[string]any{"proofID": wireID(), "referenceID": wireID(), "expectedVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 1}, "name": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "Exact UTF-8 display label, at most128bytes, non-whitespace and no controls; not authenticator provenance."}})
		if c.SessionUpdate != nil {
			request = sessionUpdateRequestWire()
		}
	} else if registration {
		fields, required := map[string]any{"proofID": wireID()}, []string{"proofID"}
		if !options {
			fields["commandID"], fields["ceremonyID"], fields["response"], fields["label"] = wireID(), wireID(), browserResponseWire(true), map[string]any{"type": "string", "maxLength": 128}
			required = append(required, "commandID", "ceremonyID", "response")
		}
		request = wireObject(required, fields)
		if c.Signup != nil {
			fields, required := map[string]any{"mode": map[string]any{"const": "signup"}, "flowID": wireID()}, []string{"mode", "flowID"}
			if !options {
				fields["commandID"], fields["ceremonyID"], fields["response"], fields["label"] = wireID(), wireID(), browserResponseWire(true), map[string]any{"type": "string", "maxLength": 128}
				required = append(required, "commandID", "ceremonyID", "response")
			}
			signup := wireObject(required, fields)
			if c.Registration != nil {
				request = map[string]any{"oneOf": []any{request, signup}}
			} else {
				request = signup
			}
		}
	} else if !list {
		variant := func(discovery bool) any {
			fields := map[string]any{"mode": map[string]any{"const": "identified"}, "flowID": wireID()}
			required := []string{"mode", "flowID"}
			if discovery {
				fields["mode"] = map[string]any{"const": "discoverable"}
			} else {
				fields["identifier"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 320, "pattern": `^[^\s\x00-\x1f\x7f-\x9f]+$`, "writeOnly": true, "description": "Exact mailbox parsed by the configured email owner; local comparison and fixed nontransitional domain IDNA are separate. Never an account lookup."}
				required = append(required, "identifier")
			}
			if !options {
				fields["commandID"], fields["ceremonyID"], fields["response"] = wireID(), wireID(), browserResponseWire(false)
				required = append(required, "commandID", "ceremonyID", "response")
			}
			return wireObject(required, fields)
		}
		request = variant(false)
		if c.Signin.DiscoverableOnly {
			request = variant(true)
		} else if c.Signin.Discoverable {
			request = map[string]any{"oneOf": []any{request, variant(true)}}
		}
	}
	var success any
	switch {
	case deletion:
		success = wireObject([]string{"commandID", "commitOutcome", "replayed"}, map[string]any{"commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"type": "boolean"}})
	case update:
		fields := map[string]any{"commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"const": false}, "credential": metadataWire()}
		fresh := wireObject([]string{"commandID", "commitOutcome", "replayed", "credential"}, fields)
		replay := wireObject([]string{"commandID", "commitOutcome", "replayed"}, map[string]any{"commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"const": true}})
		success = map[string]any{"oneOf": []any{fresh, replay}}
		if c.SessionUpdate != nil {
			success = sessionUpdateResultWire(fresh, replay)
		}
	case options:
		var browserOptions any = protocolOptionsWire(registration)
		if !registration && c.Signin.Conditional {
			conditional := protocolOptionsWire(false)
			conditional["required"] = []string{"publicKey", "mediation"}
			conditional["properties"].(map[string]any)["mediation"] = map[string]any{"const": "conditional"}
			if c.Signin.DiscoverableOnly {
				browserOptions = conditional
			} else {
				browserOptions = map[string]any{"oneOf": []any{browserOptions, conditional}}
			}
		}
		fresh := wireObject([]string{"commandID", "commitOutcome", "replayed", "options"}, map[string]any{"commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"const": false}, "options": browserOptions})
		replay := wireObject([]string{"commandID", "commitOutcome", "replayed"}, map[string]any{"commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"const": true}})
		success = map[string]any{"oneOf": []any{fresh, replay}}
	case registration:
		success = wireObject([]string{"registered", "commandID", "commitOutcome"}, map[string]any{"registered": map[string]any{"const": true}, "commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}})
		if c.Signup != nil {
			signup := wireObject([]string{"registered", "signedIn", "commandID", "commitOutcome", "sessionID", "counterRisk"}, map[string]any{"registered": map[string]any{"const": true}, "signedIn": map[string]any{"const": true}, "commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "sessionID": wireText(128), "counterRisk": map[string]any{"const": false}})
			if c.Registration != nil {
				success = map[string]any{"oneOf": []any{success, signup}}
			} else {
				success = signup
			}
		}
	case list:
		success = wireObject([]string{"credentials"}, map[string]any{"credentials": map[string]any{"type": "array", "maxItems": 100, "items": metadataWire()}, "next": wireID()})
	default:
		success = wireObject([]string{"signedIn", "commandID", "commitOutcome", "sessionID", "counterRisk"}, map[string]any{"signedIn": map[string]any{"const": true}, "commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "sessionID": wireText(128), "counterRisk": map[string]any{"type": "boolean"}})
	}
	failure := wireObject([]string{"error"}, map[string]any{"error": wireText(64), "commandID": wireID(), "commitOutcome": map[string]any{"type": "string", "enum": []string{"committed", "not_committed", "unknown", "conflict", "in_progress"}}})
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store/nosniff JSON. Challenges occur only for the fresh options winner; session cookie and synchronizer occur only for fresh committed signin or signup. Metadata is not an execution lease or renewed expiry.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "408", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	for _, status := range []string{"403", "408"} {
		responses[status].(map[string]any)["content"].(map[string]any)["text/plain"] = map[string]any{"schema": wireText(128)}
	}
	if name == "signin-verify" || name == "register-verify" && c.Signup != nil {
		responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Owned secure HttpOnly session cookie; never replayed.", "schema": wireText(4096)}, "X-CSRF-Token": map[string]any{"description": "Original session synchronizer, never replayed.", "schema": wireText(43)}}
	}
	operation := map[string]any{"operationId": "identity.passkey." + name, "description": "Explicit existing-account cookie-only passkey profile. Trusted HTTPS tenant/origin and original session/proof or original flow/mode custody are mandatory; ceremonies additionally require original device custody. Header-only keys apply to options, label update and deletion; ceremony completion forbids keys and is one-use. No body identity/remember/cookie/CSRF/command-allocation override, signup, conditional UI or fallback. Native authorization, recovery, risk and atomic consumption remain authoritative. Responses are synchronously bounded; hooks cannot acquire credential custody.", "parameters": parameters, "responses": responses}
	if update && c.SessionUpdate != nil {
		operation["description"] = "Explicit password-free current-session UV rename. phase=options binds exact reference/version/name to the current cookie session, CSRF, Origin and trusted client network. phase=complete repeats that intent with the returned commandID as ceremonyID and a genuine assertion. Each phase requires its own distinct header-only Idempotency-Key under the same protected rate.secret action. No proofID, device cookie, caller command, tenant or credential override. Matching retries expose original metadata only; no challenge, authentication cookie or renewed validity. Native ownership retains atomic current authority, assertion consumption, risk, metadata, audit and lifecycle effects. No fallback to password-proof update."
	}
	if !registration && !management && !list && c.Signin.DiscoverableOnly {
		operation["description"] = "Explicit identifier-free-only resident passkey signin. Identified mode and identifier input are not selected. Original flow/device/origin, UV, risk, current native authority, one-use completion and original remember policy remain mandatory. Header-only original keys apply to options; completion forbids keys. Historical responses expose no challenge or session. No email/password comparison owner, fallback or browser UI is enabled."
	}
	if name == "signin-options" && c.Signin.Conditional {
		operation["description"] = operation["description"].(string) + " Explicitly selected discoverable options carry mediation=conditional outside publicKey. This is presentation of the same original discoverable ceremony, not a third mode, extended expiry or browser-support assertion. Complete through unchanged mode=discoverable verification; retries return metadata only. Applications check browser support and deserialize publicKey before navigator.credentials.get()."
	}
	if registration && c.Signup != nil {
		operation["description"] = "Explicit passkey registration variants. Signup requires mode=signup, original flow/device cookies and exact Origin; session cookies, session CSRF and proofID are forbidden. Enrollment, when selected, retains its unchanged proofID/session/synchronizer contract with no mode field. Neither branch falls back after failure. Options require the original header-only Idempotency-Key; completion forbids it. Only fresh committed signup issues a session cookie and synchronizer. Native risk, protocol, account/session transaction and metadata-only recovery remain authoritative. No browser identity, RP or remember override is accepted."
	}
	if !list {
		operation["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}}
	}
	prefix := "Passkey" + strings.ReplaceAll(name, "-", "")
	var schemes []identityhttp.WireComponent
	security := map[string]any{}
	cookie := func(suffix, cookieName string) {
		definition, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookieName})
		schemes = append(schemes, identityhttp.WireComponent{Name: prefix + suffix, Definition: definition})
		security[prefix+suffix] = []any{}
	}
	switch {
	case deletion:
		policy, _ := c.Delete.SessionCookie.DeletionAttributes()
		cookie("Session", policy.Name)
	case update:
		var cookieName string
		if c.SessionUpdate != nil {
			policy, _ := c.SessionUpdate.SessionCookie.DeletionAttributes()
			cookieName = policy.Name
		} else {
			policy, _ := c.Update.SessionCookie.DeletionAttributes()
			cookieName = policy.Name
		}
		cookie("Session", cookieName)
	case registration:
		if c.Registration != nil {
			policy, _ := c.Registration.SessionCookie.DeletionAttributes()
			cookie("Session", policy.Name)
		} else {
			policy, _ := c.Signup.FlowCookie.DeletionAttributes()
			cookie("Flow", policy.Name)
		}
	case list:
		policy, _ := c.Inventory.SessionCookie.DeletionAttributes()
		cookie("Session", policy.Name)
	default:
		policy, _ := c.Signin.FlowCookie.DeletionAttributes()
		cookie("Flow", policy.Name)
	}
	if !list && !management {
		cookie("Device", "__Host-identity_device")
	}
	operation["security"] = []any{security}
	if registration && c.Signup != nil && c.Registration != nil {
		// Security Requirement entries are alternatives, not an AND of an
		// anonymous flow and an authenticated session. Device is common to both.
		enrollment := security
		security = map[string]any{prefix + "Device": []any{}}
		policy, _ := c.Signup.FlowCookie.DeletionAttributes()
		cookie("Flow", policy.Name)
		operation["security"] = []any{enrollment, security}
	}
	definition, _ := json.Marshal(operation)
	return &identityhttp.WireOperation{Definition: definition, SecuritySchemes: schemes}
}

func sessionReferenceWire() any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": `^[^\x00-\x20\x7f]+$`, "description": "Exact canonical kernel credential reference, at most128 UTF-8 bytes; imported ULIDs remain unchanged."}
}
func sessionUpdateRequestWire() any {
	variant := func(complete bool) any {
		phase := "options"
		if complete {
			phase = "complete"
		}
		fields := map[string]any{"phase": map[string]any{"const": phase}, "referenceID": sessionReferenceWire(), "expectedVersion": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0) - 1}, "name": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "At most128 UTF-8 bytes, non-whitespace and no controls."}}
		required := []string{"phase", "referenceID", "expectedVersion", "name"}
		if complete {
			fields["ceremonyID"], fields["response"] = wireID(), browserResponseWire(false)
			required = append(required, "ceremonyID", "response")
		}
		return wireObject(required, fields)
	}
	return map[string]any{"oneOf": []any{variant(false), variant(true)}}
}
func sessionUpdateResultWire(fresh, replay map[string]any) any {
	fresh["properties"].(map[string]any)["credential"].(map[string]any)["properties"].(map[string]any)["referenceID"] = sessionReferenceWire()
	options := protocolOptionsWire(false)
	key := options["properties"].(map[string]any)["publicKey"].(map[string]any)
	key["properties"].(map[string]any)["allowCredentials"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": wireObject([]string{"type", "id"}, map[string]any{"type": map[string]any{"const": "public-key"}, "id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1366, "pattern": "^[A-Za-z0-9_-]+$"}})}
	key["required"] = append(key["required"].([]string), "allowCredentials")
	freshOptions := wireObject([]string{"commandID", "commitOutcome", "replayed", "options"}, map[string]any{"commandID": wireID(), "commitOutcome": map[string]any{"const": "committed"}, "replayed": map[string]any{"const": false}, "options": options})
	return map[string]any{"oneOf": []any{fresh, freshOptions, replay}}
}

func metadataWire() any {
	stamp := map[string]any{"type": "string", "format": "date-time"}
	return wireObject([]string{"referenceID", "version", "state", "label", "aaguid", "backupEligible", "backupState", "createdAt"}, map[string]any{
		"referenceID": wireID(), "version": map[string]any{"type": "integer", "minimum": 1, "maximum": ^uint64(0)}, "state": wireText(64), "label": map[string]any{"type": "string", "maxLength": 128}, "aaguid": map[string]any{"type": "array", "minItems": 16, "maxItems": 16, "items": map[string]any{"type": "integer", "minimum": 0, "maximum": 255}}, "backupEligible": map[string]any{"type": "boolean"}, "backupState": map[string]any{"type": "boolean"}, "createdAt": stamp, "lastUsedAt": stamp,
	})
}

func browserResponseWire(registration bool) any {
	encoded := map[string]any{"type": "string", "minLength": 1, "maxLength": 262144, "pattern": "^[A-Za-z0-9_-]+$", "writeOnly": true}
	fields := map[string]any{"clientDataJSON": encoded}
	required := []string{"clientDataJSON"}
	if registration {
		fields["attestationObject"] = encoded
		required = append(required, "attestationObject")
	} else {
		fields["authenticatorData"], fields["signature"], fields["userHandle"] = encoded, encoded, map[string]any{"type": []string{"string", "null"}, "maxLength": 1366, "writeOnly": true}
		required = append(required, "authenticatorData", "signature")
	}
	return wireObject([]string{"id", "rawId", "type", "response"}, map[string]any{"id": encoded, "rawId": encoded, "type": map[string]any{"const": "public-key"}, "response": wireObject(required, fields), "clientExtensionResults": map[string]any{"type": "object", "maxProperties": 16}})
}

func protocolOptionsWire(registration bool) map[string]any {
	challenge := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"}
	fields := map[string]any{"challenge": challenge, "timeout": map[string]any{"const": 300000}, "userVerification": map[string]any{"const": "required"}}
	required := []string{"challenge", "timeout", "userVerification"}
	if registration {
		fields["rp"] = wireObject([]string{"id", "name"}, map[string]any{"id": wireText(253), "name": wireText(256)})
		fields["user"] = wireObject([]string{"id", "name", "displayName"}, map[string]any{"id": challenge, "name": challenge, "displayName": challenge})
		fields["pubKeyCredParams"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": wireObject([]string{"type", "alg"}, map[string]any{"type": map[string]any{"const": "public-key"}, "alg": map[string]any{"const": -7}})}
		fields["attestation"] = map[string]any{"const": "none"}
		fields["authenticatorSelection"] = wireObject([]string{"userVerification", "residentKey", "requireResidentKey"}, map[string]any{"userVerification": map[string]any{"const": "required"}, "residentKey": map[string]any{"const": "required"}, "requireResidentKey": map[string]any{"const": true}})
		fields["excludeCredentials"] = map[string]any{"type": "array", "maxItems": 100, "items": wireObject([]string{"type", "id"}, map[string]any{"type": map[string]any{"const": "public-key"}, "id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1366, "pattern": "^[A-Za-z0-9_-]+$"}})}
		fields["extensions"] = wireObject(nil, map[string]any{"credProps": map[string]any{"const": true}, "credentialProtectionPolicy": map[string]any{"type": "string", "enum": []string{"userVerificationOptional", "userVerificationOptionalWithCredentialIDList", "userVerificationRequired"}}, "enforceCredentialProtectionPolicy": map[string]any{"type": "boolean"}})
		required = append(required, "rp", "user", "pubKeyCredParams", "attestation", "authenticatorSelection")
	} else {
		fields["rpId"] = wireText(253)
		required = append(required, "rpId")
	}
	return wireObject([]string{"publicKey"}, map[string]any{"publicKey": wireObject(required, fields)})
}
