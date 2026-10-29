package identityhttp

import (
	"io"
	"net/http"
	"slices"
	"strings"
)

// CanonicalOperationConfig binds one trusted feature-owned handler to the
// embedded canonical direct-contract record. Owner must be accountable for the
// operation. CSRF selects an actually enforced profile, not a request-selected
// fallback. Conditional pre-auth/session rows additionally admit ExactOrigin
// with denied Referer fallback for pre-auth-only handlers that reject session
// and MFA variants. Self-signout and password-change additionally admit None
// (explicit bearer) or SessionState (cookie origin plus active-state token).
// Password change requires an active session; only self-signout admits absent/
// inactive origin-only success. Password verification additionally admits None
// for strict bearer custody or SessionState with a configured valid header,
// zero independent token age and denied Referer fallback for native protected
// cookie custody. Factories own enforcement; selection issues no CSRF token.
// Organization create/update/member-add/member-update/member-remove/member-leave,
// owner-transfer, archive/restore, team create/update/delete/member-add/member-remove
// role create/update/delete and invitation send/accept/resend/cancel/reject/expire
// additionally admit None only for explicitly selected strict bearer handlers
// that ignore ambient cookies. Owner-transfer retains its native fresh proof.
// Other organization mutations retain their canonical policy.
// API-key create/rotate/delete/update additionally admit explicit bearer-only None
// with keyed custody, matching the native management contracts. Those handlers
// must reject cookie fallback and require the original Idempotency-Key.
// MaximumSerializedBytes
// bounds each schema summary (1..16MiB); it is not response-size enforcement.
// Handler must be usable/concurrency-safe and own its declared security. Nil
// handlers and typed-nil HandlerFunc are invalid. No callback is invoked here.
type CanonicalOperationConfig struct {
	Owner                  ModuleID
	OperationID            string
	Handler                http.Handler
	CSRF                   CSRFPolicy
	MaximumSerializedBytes uint64
}

// NewCanonicalOperation constructs a detached descriptor from owned catalog
// data, avoiding feature-maintained policy/digest copies. Unknown, direct-only,
// middleware, shared-token variant and incompatible owner/policy inputs deny
// atomically. The three schema summaries bind DIRECT public contracts, not HTTP
// wire schemas or rendered OpenAPI. Construction is side-effect-free and does
// not certify that arbitrary caller handlers enforce authentication or policy;
// use the owned feature factory, not a placeholder handler for identity routes.
func NewCanonicalOperation(c CanonicalOperationConfig) (OperationDescriptor, error) {
	if !moduleID(c.Owner) || !identifier(c.OperationID, 128) || c.MaximumSerializedBytes == 0 || c.MaximumSerializedBytes > 16<<20 {
		return OperationDescriptor{}, ErrInvalidInput
	}
	catalog := readCatalog()
	row, ok := catalog[c.OperationID]
	if !ok {
		return OperationDescriptor{}, ErrInvalidInput
	}
	r := row.record()
	r.CSRFOrigin = c.CSRF
	if apiKeyManagementOperation(r.OperationID) && c.CSRF.Mode == CSRFNone {
		r.Idempotency = "keyed"
	}
	r.RequestSchema = schemaSummary(row.RequestSchema, row.RequestDigest)
	r.ResultSchema = schemaSummary(row.ResultSchema, row.ResultDigest)
	r.ErrorSchema = schemaSummary(row.ErrorSchema, row.ErrorDigest)
	op := OperationDescriptor{Record: r, Route: Route{Method: r.Method, Path: r.Path, Authorization: r.Authorization, CSRF: r.CSRFOrigin, RatePolicy: r.RatePolicy}, Handler: c.Handler}
	for i, schema := range []TypedSchema{r.RequestSchema, r.ResultSchema, r.ErrorSchema} {
		op.Schemas = append(op.Schemas, OpenAPISchema{Name: strings.ReplaceAll(r.OperationID, ".", "_") + []string{"_request", "_result", "_error"}[i], Schema: schema, MaximumSerializedBytes: c.MaximumSerializedBytes})
	}
	if !validOperation(c.Owner, op, catalog) {
		return OperationDescriptor{}, ErrInvalidInput
	}
	return op, nil
}

// NewSelectedHandler freezes exact dispatch for validated explicitly selected
// feature contributions. Empty selects nothing and returns 404 for all paths.
// Construction validates dependencies/collisions and invokes no handler or IO.
// Routes are exact, root-mounted and case-sensitive: no cleaning, prefix match,
// escaped aliases, redirects, implicit HEAD or automatic OPTIONS. Query/body,
// authentication, authorization, CSRF, rate and domain outcomes remain owned by
// the selected real feature handlers; no second read, authentication or debit
// is performed. Callers must use owned feature factories or trusted extension
// handlers that implement their full declared controls. This dispatcher is NOT
// the planned complete NewRouter/security/OpenAPI builder and exports no
// metadata endpoint. Full wire-schema/router qualification remains required.
//
// Wrong paths return 404, wrong methods 405 with a sorted Allow, malformed nil
// requests 400 and already canceled requests 503. Dispatcher errors are fixed
// no-store/nosniff JSON; HEAD errors omit the body. Returned routing is immutable
// and concurrency-safe; handlers/dependencies remain borrowed and must outlive
// requests. The server owns whole-request/write deadlines and resource cleanup.
func NewSelectedHandler(services FeatureServices) (http.Handler, error) {
	ops, err := NewOperationDescriptors(services)
	if err != nil {
		return nil, err
	}
	return selectedHandler(ops)
}

func selectedHandler(ops []OperationDescriptor) (http.Handler, error) {
	type selectedPath struct {
		methods map[string]http.Handler
		allow   string
	}
	paths := make(map[string]selectedPath, len(ops))
	for _, op := range ops {
		p := paths[op.Route.Path]
		if p.methods == nil {
			p.methods = make(map[string]http.Handler)
		}
		p.methods[op.Route.Method] = op.Handler
		paths[op.Route.Path] = p
	}
	for path, p := range paths {
		methods := make([]string, 0, len(p.methods))
		for method := range p.methods {
			methods = append(methods, method)
		}
		slices.Sort(methods)
		p.allow = strings.Join(methods, ", ")
		paths[path] = p
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func(status int, code string) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(status)
			if r == nil || r.Method != http.MethodHead {
				io.WriteString(w, `{"error":"`+code+"\"}\n")
			}
		}
		if r == nil || r.URL == nil {
			deny(400, "invalid_request")
			return
		}
		if !validPath(r.URL.Path) || r.URL.RawPath != "" {
			deny(404, "not_found")
			return
		}
		p, ok := paths[r.URL.Path]
		if !ok {
			deny(404, "not_found")
			return
		}
		handler, ok := p.methods[r.Method]
		if !ok {
			w.Header().Set("Allow", p.allow)
			deny(405, "method_not_allowed")
			return
		}
		if r.Context().Err() != nil {
			deny(503, "unavailable")
			return
		}
		handler.ServeHTTP(w, r)
	}), nil
}
