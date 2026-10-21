package anonymoushttp

import (
	"encoding/json"
	"maps"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// FeatureConfig selects precisely its non-nil operations. Nil exposes no route,
// metadata or implicit sibling method. Owners stay borrowed; configuration is
// frozen during construction and must not be concurrently changed then.
type FeatureConfig struct {
	Signin   *SigninConfig
	Deletion *DeletionConfig
	Upgrade  *UpgradeConfig
}

// NewFeature contributes only explicitly selected native browser workflows.
// It publishes no global registry and performs no IO or owner callbacks.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware binds trusted synchronous hooks to real execution
// phases. Hooks cannot replace frozen custody or authorize protected work.
func NewFeatureWithMiddleware(c FeatureConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if c.Signin == nil && c.Deletion == nil && c.Upgrade == nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var operations []identityhttp.OperationDescriptor
	add := func(id string, h http.Handler, err error, cookies []string) error {
		if err != nil {
			return err
		}
		h, err = identityhttp.WithOperationMiddleware(h, m)
		if err != nil {
			return err
		}
		csrf := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
		if id == "signin" {
			csrf = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/anonymous", OperationID: "identity.anonymous." + id, Handler: h, CSRF: csrf, MaximumSerializedBytes: 16384})
		if err != nil {
			return err
		}
		op.Wire = anonymousWire(id, cookies)
		operations = append(operations, op)
		return nil
	}
	if c.Signin != nil {
		h, err := NewSigninHandler(*c.Signin)
		if err := add("signin", h, err, []string{"__Host-identity_flow", "__Host-identity_device"}); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	if c.Deletion != nil {
		h, err := NewDeletionHandler(*c.Deletion)
		cookie, _ := c.Deletion.Cookie.DeletionAttributes()
		if err := add("delete", h, err, []string{cookie.Name, "__Host-identity_device"}); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	if c.Upgrade != nil {
		h, err := NewUpgradeHandler(*c.Upgrade)
		guest, _ := c.Upgrade.GuestCookie.DeletionAttributes()
		target, _ := c.Upgrade.TargetCookie.DeletionAttributes()
		if err := add("upgrade", h, err, []string{guest.Name, target.Name, "__Host-identity_device"}); err != nil {
			return identityhttp.Feature{}, err
		}
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/anonymous", Operations: operations})
}

func anonymousWire(id string, cookies []string) *identityhttp.WireOperation {
	text := func(max int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": max}
	}
	object := func(required []string, p map[string]any) map[string]any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": p}
	}
	command := text(128)
	recovery := object([]string{"commandID", "tenantID", "userID", "actorID", "actorKind", "operationID", "recordID"}, map[string]any{"commandID": command, "tenantID": text(128), "userID": text(128), "actorID": text(128), "actorKind": map[string]any{"const": "user"}, "operationID": map[string]any{"const": "identity.anonymous." + id}, "recordID": map[string]any{"type": "string", "maxLength": 128}})
	props := map[string]any{"commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "not_committed", "committed", "unknown", "conflict", "in_progress"}}, "replayed": map[string]any{"type": "boolean"}, "error": map[string]any{"type": "string", "enum": []string{"invalid_request", "not_found", "method_not_allowed", "misdirected_request", "origin_denied", "origin_or_csrf_denied", "rate_limited", "denied", "conflict", "in_progress", "unavailable"}}}
	flag := "deleted"
	var request map[string]any
	if id == "signin" {
		flag = "signedIn"
		request = object([]string{"flowID", "callbackURL"}, map[string]any{"flowID": text(22), "callbackURL": map[string]any{"type": "string", "maxLength": 2048}, "remember": map[string]any{"type": "boolean"}})
		recovery = object([]string{"commandID", "tenantID", "flowID", "actorID", "actorKind"}, map[string]any{"commandID": command, "tenantID": text(128), "flowID": text(22), "actorID": text(128), "actorKind": map[string]any{"const": "service-account"}})
	} else if id == "delete" {
		request = object([]string{"expectedVersion", "reason"}, map[string]any{"expectedVersion": map[string]any{"type": "integer", "minimum": 1}, "reason": text(64)})
	} else {
		flag = "upgraded"
		request = object([]string{"guestID", "expectedVersion", "proofID", "conflicts"}, map[string]any{"guestID": text(22), "expectedVersion": map[string]any{"type": "integer", "minimum": 1}, "proofID": text(128), "conflicts": map[string]any{"type": "array", "maxItems": 1, "items": object([]string{"field", "disposition"}, map[string]any{"field": map[string]any{"const": "profile.display_name"}, "disposition": map[string]any{"const": "keep_target"}})}})
	}
	props[flag] = map[string]any{"type": "boolean"}
	if id == "upgrade" {
		props["preparation"], props["recovery"] = recovery, recovery
	} else {
		props["commandID"], props["recovery"] = command, recovery
	}
	errorProps := maps.Clone(props)
	errorProps[flag] = map[string]any{"const": false}
	failure := object([]string{flag, "commitOutcome", "error"}, errorProps)
	freshProps := maps.Clone(props)
	delete(freshProps, "error")
	freshProps[flag] = map[string]any{"const": true}
	freshProps["commitOutcome"] = map[string]any{"const": "committed"}
	metadata := []string{"commandID", "recovery"}
	if id == "upgrade" {
		metadata = []string{"preparation", "recovery"}
	}
	required := append([]string{flag, "commitOutcome"}, metadata...)
	fresh := object(required, freshProps)
	var success any = fresh
	if id != "delete" {
		freshProps["replayed"] = map[string]any{"const": false}
		replayProps := maps.Clone(freshProps)
		replayProps[flag] = map[string]any{"const": false}
		replayProps["replayed"] = map[string]any{"const": true}
		success = map[string]any{"oneOf": []any{fresh, object(append(append([]string{}, required...), "replayed"), replayProps)}}
	}
	response := func(schema any) map[string]any {
		return map[string]any{"description": "No-store/nosniff original command metadata. Unknown is not rollback; historical responses never deliver session or CSRF credentials.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{}
	responses["200"] = response(success)
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(failure)
	}
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Fresh acknowledged credential delivery only; delete clears original guest. Upgrade also clears guest. Never replay issuance.", "schema": text(4096)}, "X-CSRF-Token": map[string]any{"description": "Fresh session synchronizer only, absent on deletion and historical replies.", "schema": text(256)}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	parameters := []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": text(2048)}, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": text(256)}}
	if id != "signin" {
		parameters = append(parameters, map[string]any{"name": "X-CSRF-Token", "in": "header", "required": true, "schema": text(43)})
	}
	if id == "upgrade" {
		parameters = append(parameters, map[string]any{"name": "X-Target-CSRF-Token", "in": "header", "required": true, "schema": text(43), "description": "Original permanent session synchronizer, distinct from guest X-CSRF-Token."})
	}
	wire := &identityhttp.WireOperation{}
	security := map[string]any{}
	for i, cookie := range cookies {
		name := "Anonymous_" + id + "_" + []string{"first", "second", "third"}[i]
		security[name] = []string{}
		data, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": cookie, "description": "Original native browser custody. Device is correlation only; guest is never verified-user authority."})
		wire.SecuritySchemes = append(wire.SecuritySchemes, identityhttp.WireComponent{Name: name, Definition: data})
	}
	wire.Definition, _ = json.Marshal(map[string]any{"operationId": "identity.anonymous." + id, "description": "Explicit native anonymous browser profile; original retry key and possession, one-use protected transition, no credential redelivery or authority renewal.", "security": []any{security}, "parameters": parameters, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": request}}}, "responses": responses})
	return wire
}
