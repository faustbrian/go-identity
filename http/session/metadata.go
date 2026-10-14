package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// MetadataConfig explicitly selects session-authenticated administrator
// metadata. Read supplies the same valid owner, cookie/bearer, host, clock,
// duration and shared rate configuration used by session reads; only mapped
// tenant hosts are supported. Public-host/global administration is not inferred.
// Authorization is a borrowed concurrency-safe existing policy engine/authorizer;
// PolicyRevision must be positive. Action and ResourceType are explicit bounded
// deployment policy identifiers, never request fields or inferred token scopes.
// The resource ID is always identity.openapi.document. All owners must honor
// context cancellation and outlive this handler; no owner is closed here.
type MetadataConfig struct {
	Read           GetConfig
	Authorization  authorization.Authorizer
	PolicyRevision authorization.Revision
	Action         authorization.Action
	ResourceType   authorization.ResourceType
}

// NewMetadataRouter explicitly adds protected GET /openapi.json to selected
// services and constructs their secure router and exact immutable OpenAPI
// snapshot. Neither session routes nor public metadata are implicitly selected.
// Selecting a competing metadata route fails atomically. Construction invokes
// no authentication, authorization, rate, readiness or domain work.
//
// The real owner phases are bounded decode -> one session read -> one shared
// rate.safe admission -> revision-fenced explicit administrator authorization ->
// exact snapshot export. Missing/inactive sessions return401; explicit policy
// deny returns403; stale/error/expired authority returns503; rate denial429.
// A 401 challenge names Bearer for bearer mode or the private Session scheme
// for cookie mode; it never advertises credential fallback or redirects.
// Shared transport rejects plaintext with JSON https_required (403); disabled
// cross-origin access returns fixed text/plain origin_denied (403, or408 when
// cancellation is observed during origin admission), before session work.
// Cookies never replace selected bearer credentials; cookie mode rejects
// Authorization. Metadata GET mutates nothing and emits no cookie or secret.
// Original session validity is rechecked after rate/policy work and hooks; no
// copied evidence gains freshness. Middleware observes the actual GetState.
//
// Transport uses Read.Network and Read.MaximumDuration; CORS grants are disabled.
// Other selected features must share those policies and retain their own owners.
// Global hooks require every selected handler to support the existing binder.
// Start the returned handler with NewHTTPServer for bounded raw IO/streaming.
// This is an optional session profile, not JWT/API-key administration, public
// realm mapping, a complete reference server or release qualification.
func NewMetadataRouter(ctx context.Context, document identityhttp.DocumentConfig, c MetadataConfig, services identityhttp.FeatureServices, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, identityhttp.OpenAPIDocument, error) {
	if ctx == nil || c.PolicyRevision == 0 || !metadataPolicyName(string(c.Action)) || !metadataPolicyName(string(c.ResourceType)) || len(services.Features) >= 64 {
		return nil, identityhttp.OpenAPIDocument{}, identityhttp.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	decide, err := authorization.NewDecisionService(c.Authorization)
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, identityhttp.ErrInvalidInput
	}
	decode, err := newSessionReadDecoder(c.Read, "/openapi.json")
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	var exported []byte
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
		failure := getFailure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			failure = getFailure{status: 400, code: "invalid_request"}
		}
		var specific getFailure
		if errors.As(err, &specific) {
			failure = specific
		}
		if failure.allow != "" {
			w.Header().Set("Allow", failure.allow)
		}
		if failure.status == 401 {
			challenge := "Bearer"
			if c.Read.Transport == session.CredentialCookie {
				challenge = "Session"
			}
			w.Header().Set("WWW-Authenticate", challenge)
		}
		if failure.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((failure.retry+time.Second-1)/time.Second), 10))
		}
		response(w, failure.status, `{"error":"`+failure.code+`"}`)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[GetState]{
		MaximumDuration: c.Read.MaximumDuration, Decode: decode, Reject: reject,
		Authenticate: func(r *http.Request, state GetState) (GetState, error) { return authenticateSession(c.Read, r, state) },
		Admit: func(r *http.Request, state GetState) error {
			if state.result.Authenticated && state.result.ValidateAt(c.Read.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			admitted, err := c.Read.Rate.Admit(r.Context(), state.facts, "identity.openapi.document", state.principal.UserID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return getFailure{status: 429, code: "rate_limited", retry: admitted.RetryAfter}
			}
			if err != nil || !admitted.Allowed || (state.result.Authenticated && state.result.ValidateAt(c.Read.Now()) != nil) {
				return identityhttp.ErrUnavailable
			}
			if !state.result.Authenticated {
				return getFailure{status: 401, code: "unauthenticated"}
			}
			decision, err := decide.Decide(r.Context(), authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{
				Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(state.principal.UserID)},
				Tenant:  authorization.TenantID(state.principal.TenantID), Action: c.Action,
				Resource: authorization.Resource{Type: c.ResourceType, ID: "identity.openapi.document"}, Environment: authorization.Environment{Time: c.Read.Now()},
			}})
			if err != nil || r.Context().Err() != nil || state.result.ValidateAt(c.Read.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			if decision.Outcome != authorization.Allow {
				return getFailure{status: 403, code: "denied"}
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state GetState) {
			if state.result.ValidateAt(c.Read.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			w.Write(exported)
		},
	})
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	handler := &protectedPipeline{pipeline: pipeline, serve: func(h http.Handler, w http.ResponseWriter, r *http.Request) {
		serveSessionResponse(h, w, r, func() string { return "" })
	}}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/http", OperationID: "identity.openapi.document", Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16 << 20})
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	op.Wire = protectedMetadataWire(c.Read)
	feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/http", Operations: []identityhttp.OperationDescriptor{op}})
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	selected := identityhttp.FeatureServices{Features: append(append([]identityhttp.Feature(nil), services.Features...), feature)}
	ops, err := identityhttp.NewOperationDescriptors(selected)
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	h, snapshot, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Read.Network, HandlerTimeout: c.Read.MaximumDuration, Document: document}, ops, middleware)
	if err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, identityhttp.OpenAPIDocument{}, err
	}
	exported = snapshot.JSON()
	return h, snapshot, nil
}

func metadataPolicyName(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func protectedMetadataWire(c GetConfig) *identityhttp.WireOperation {
	schemeName := "MetadataSessionBearer"
	scheme := map[string]any{"type": "http", "scheme": "bearer", "description": "Exactly one strict session bearer credential. Ambient cookies confer no authority."}
	if c.Transport == session.CredentialCookie {
		cookie, _ := c.Cookie.DeletionAttributes()
		schemeName = "MetadataSessionCookie"
		scheme = map[string]any{"type": "apiKey", "in": "cookie", "name": cookie.Name, "description": "Required configured secure session cookie; Authorization is forbidden."}
	}
	success := map[string]any{"type": "object", "required": []string{"openapi", "info", "paths"}, "properties": map[string]any{"openapi": map[string]any{"const": "3.1.1"}, "info": map[string]any{"type": "object"}, "paths": map[string]any{"type": "object"}}}
	errorSchema := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"error"}, "properties": map[string]any{"error": map[string]any{"type": "string", "enum": []string{"invalid_request", "unauthenticated", "denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "unavailable"}}}}
	response := func(schema any) any {
		return map[string]any{"description": "Static metadata or redacted denial; no-store, nosniff, no-referrer; no cookie emission.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	for _, status := range []string{"400", "401", "403", "404", "405", "421", "429", "503"} {
		responses[status] = response(errorSchema)
	}
	// The shared CORS owner rejects before the session JSON response guard.
	// Describe its real fixed media/body rather than implying normalization.
	originContent := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = originContent
	responses["408"] = map[string]any{"description": "Cancellation observed during shared origin admission; no session work or cookie emission.", "content": map[string]any{"text/plain": originContent}}
	responses["429"].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"description": "Whole seconds before another admission attempt.", "schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	data, _ := json.Marshal(map[string]any{"operationId": "identity.openapi.document", "description": "Explicit session-authenticated administrator metadata; exact empty HTTPS GET, no query, body, trailer or Idempotency-Key. Trusted tenant/user owner custody and revision-fenced policy; canonical shared rate.safe. No implicit session routes or public alternative.", "security": []any{map[string]any{schemeName: []string{}}}, "responses": responses})
	definition, _ := json.Marshal(scheme)
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: schemeName, Definition: definition}}}
}
