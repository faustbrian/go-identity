package identityhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
)

// TransportPolicy selects shared transport enforcement for NewRouter. Network
// is a complete copied host/proxy/input-limit policy; unknown hosts never select
// a tenant. HandlerTimeout is 1ms..30s and cannot extend an inbound deadline.
// Document supplies public static title/version, not runtime host information.
// CORS is opt-in per exact selected method/path (at most 1024 policies); empty
// disables cross-origin grants. All origins and bounds are validated/copied.
//
// Canonical routes are root-mounted exactly as declared, including probes and
// protocol endpoints. There is no prefix rewrite, redirect or implicit metadata
// endpoint. Feature factories remain the single owners of their cookie policy,
// credential acquisition, authorization, rate admission and transactional CSRF.
// Share their actual network policy with Network; a router admission alone is
// not a credential, session, rate decision or proof of feature enforcement.
type TransportPolicy struct {
	Network        NetworkConfig
	CORS           []CORSRoutePolicy
	HandlerTimeout time.Duration
	Document       DocumentConfig
}

// NewRouter validates and freezes exact selected routing, shared transport
// policy, feature-owned middleware phases and matching OpenAPI 3.1.1. Obtain
// operations from NewOperationDescriptors, which validates selected feature
// dependencies; this constructor revalidates every descriptor and collision.
// Empty selection exposes nothing. Invalid policy/wire/metadata or unsupported
// middleware binding returns no handler/document. No request, authentication,
// readiness, store or network work occurs during construction. Trusted wrapper
// factories may run once per operation only after static validation/document
// validation; their own frozen-pipeline conflicts may still reject construction.
//
// Runtime order is bounded envelope/network/HTTPS -> route-specific CORS ->
// exact dispatch -> real feature Decode/authentication/admission/domain phases.
// Preflight never enters feature handlers or hooks. Middleware is appended via
// OperationMiddlewareBinder, never wrapped around fictitious auth boundaries;
// nonempty middleware with an opaque handler is rejected. The selected owner
// must actually enforce its advertised authentication, rate and CSRF controls:
// metadata/arbitrary caller handlers are not evidence of those decisions.
//
// Responses retain no-store, nosniff and no-referrer through supported write,
// flush and ReaderFrom paths. CORS retains its separate grant/Vary custody;
// cookie emission remains with the feature serializer. Trusted code must not
// unwrap/hijack writers or retain request/writer state. Panics before commitment
// yield redacted 503; after commitment they abort with http.ErrAbortHandler.
// Requests are cloned, raw bodies are bounded but not pre-read or closed, and
// context deadlines never extend upstream bounds. Server raw read/write and
// connection deadlines remain required: use NewHTTPServer. Arbitrary callbacks
// ignoring cancellation cannot be forcibly terminated; no detached work is
// started. Before any response commitment, a canceled owner may synchronously
// return one explicit 503 outcome of at most 16KiB; only content type, retry and
// CORS headers survive, never credentials or trailers. Other canceled writes
// deny; already committed responses abort. This preserves known command status
// without retrying work or asserting that a disconnected client received it.
// Returned snapshots are concurrent-safe when borrowed handlers are.
func NewRouter(policy TransportPolicy, operations []OperationDescriptor, middleware []MiddlewareDescriptor) (http.Handler, OpenAPIDocument, error) {
	if policy.HandlerTimeout < time.Millisecond || policy.HandlerTimeout > 30*time.Second || len(operations) > 1024 || !validMiddleware(middleware) {
		return nil, OpenAPIDocument{}, ErrInvalidInput
	}
	network, err := NewNetworkResolver(policy.Network)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	catalog := readCatalog()
	components, wireBytes := 0, 0
	for _, op := range operations {
		if len(op.Record.Owners) == 0 || !validOperation(op.Record.Owners[0], op, catalog) || !validWireBounds(op.Wire) {
			return nil, OpenAPIDocument{}, ErrInvalidInput
		}
		components += len(op.Schemas)
		wireBytes += wireSize(op.Wire)
		if components > 4096 || wireBytes > 16<<20 {
			return nil, OpenAPIDocument{}, ErrInvalidInput
		}
		if len(middleware) != 0 {
			if _, ok := op.Handler.(OperationMiddlewareBinder); !ok {
				return nil, OpenAPIDocument{}, ErrInvalidInput
			}
		}
	}
	if !uniqueOperations(operations) || len(policy.CORS) > 1024 {
		return nil, OpenAPIDocument{}, ErrInvalidInput
	}
	selected := make(map[string]bool, len(operations))
	for _, op := range operations {
		selected[op.Route.Method+" "+op.Route.Path] = true
	}
	for _, route := range policy.CORS {
		if !selected[route.Method+" "+route.Path] {
			return nil, OpenAPIDocument{}, ErrInvalidInput
		}
	}
	ops := cloneOperations(operations)
	slices.SortFunc(ops, func(a, b OperationDescriptor) int { return strings.Compare(a.Record.OperationID, b.Record.OperationID) })
	// Validate CORS before callback construction, retaining one policy owner.
	cors, err := NewCORSHandler(CORSConfig{Network: network, Routes: policy.CORS}, http.NotFoundHandler())
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	_, document, err := documentedOperations(context.Background(), policy.Document, ops)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	for i := range ops {
		ops[i].Handler, err = WithOperationMiddleware(ops[i].Handler, middleware)
		if err != nil {
			return nil, OpenAPIDocument{}, err
		}
	}
	dispatch, err := selectedHandler(ops)
	if err != nil {
		return nil, OpenAPIDocument{}, err
	}
	cors.(*corsHandler).next = dispatch
	document.operations = cloneOperations(ops)
	return &routerHandler{network: network, next: cors, timeout: policy.HandlerTimeout}, document, nil
}

func validMiddleware(middleware []MiddlewareDescriptor) bool {
	if len(middleware) > 64 {
		return false
	}
	names, orders := map[string]bool{}, map[[2]uint32]bool{}
	for _, descriptor := range middleware {
		m := descriptor.Middleware
		name, order := string(descriptor.Owner)+"\x00"+m.Name, [2]uint32{uint32(m.Phase), m.Order}
		if !moduleID(descriptor.Owner) || !identifier(m.Name, 128) || m.Phase < MiddlewareBeforeAuth || m.Phase > MiddlewareAfterHandler || m.Order < 1 || m.Order > 10000 || m.Handler == nil || names[name] || orders[order] {
			return false
		}
		names[name], orders[order] = true, true
	}
	return true
}

type routerHandler struct {
	network *NetworkResolver
	next    http.Handler
	timeout time.Duration
}

func (h *routerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	routerHeaders(w.Header())
	if r == nil || r.URL == nil {
		routerDeny(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	owned := r.Clone(ctx)
	facts, err := h.network.resolve(owned)
	if err != nil {
		status, code := http.StatusBadRequest, "invalid_request"
		if errors.Is(err, ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status, code = http.StatusServiceUnavailable, "unavailable"
		}
		routerDeny(w, r, status, code)
		return
	}
	if facts.Realm() == 0 {
		routerDeny(w, r, http.StatusMisdirectedRequest, "misdirected_request")
		return
	}
	if facts.Scheme() != "https" {
		routerDeny(w, r, http.StatusForbidden, "https_required")
		return
	}
	if !validPath(owned.URL.Path) || owned.URL.RawPath != "" {
		routerDeny(w, r, http.StatusNotFound, "not_found")
		return
	}
	var body *routerBody
	if owned.Body != nil && owned.Body != http.NoBody {
		body = &routerBody{ReadCloser: http.MaxBytesReader(w, owned.Body, int64(h.network.decoder.limits.MaximumBodyBytes)), ctx: ctx}
		owned.Body = body
	}
	owned.GetBody = nil
	committed := false
	invalidEnvelopeSent := false
	canceledFailure := false
	canceledBytes := 0
	canceledOverflow := false
	before := func() error {
		routerHeaders(w.Header())
		if ctx.Err() != nil {
			routerCanceledHeaders(w.Header())
		}
		if body != nil && body.exceeded {
			if !committed {
				routerDeny(w, r, http.StatusBadRequest, "invalid_request")
				committed = true
				invalidEnvelopeSent = true
			}
			return DecodeError{}
		}
		if err := ctx.Err(); err != nil {
			if !canceledFailure || canceledOverflow {
				return err
			}
		}
		return nil
	}
	var writer http.ResponseWriter
	writer = httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) {
				if ctx.Err() != nil && !committed && status == http.StatusServiceUnavailable {
					canceledFailure = true
				}
				if canceledFailure && status != http.StatusServiceUnavailable {
					return
				}
				if before() == nil {
					if status >= 200 {
						committed = true
					}
					next(status)
				}
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(p []byte) (int, error) {
				if err := before(); err != nil {
					return 0, err
				}
				if canceledFailure {
					if len(p) > 16384-canceledBytes {
						canceledOverflow = true
						return 0, ErrUnavailable
					}
					canceledBytes += len(p)
				}
				committed = true
				return next(p)
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if before() == nil {
					committed = true
					next()
				}
			}
		},
		ReadFrom: func(_ httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(source io.Reader) (int64, error) {
				if err := before(); err != nil {
					return 0, err
				}
				// An arbitrary source may mutate headers while ReadFrom reads it.
				// Commit through the same Write guard after each source callback,
				// not the underlying writer's unguarded fast path.
				return io.Copy(struct{ io.Writer }{writer}, source)
			}
		},
	})
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler || committed {
				panic(http.ErrAbortHandler)
			}
			if ctx.Err() != nil {
				routerCanceledHeaders(w.Header())
			}
			routerDeny(w, r, http.StatusServiceUnavailable, "unavailable")
		}
	}()
	h.next.ServeHTTP(writer, owned)
	routerHeaders(w.Header())
	if ctx.Err() != nil {
		routerCanceledHeaders(w.Header())
	}
	if body != nil && body.exceeded && !invalidEnvelopeSent {
		if committed {
			panic(http.ErrAbortHandler)
		}
		routerDeny(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	if ctx.Err() != nil {
		if canceledFailure && committed && !canceledOverflow {
			return
		}
		if committed {
			panic(http.ErrAbortHandler)
		}
		routerDeny(w, r, http.StatusServiceUnavailable, "unavailable")
	}
}

// On cancellation, headers retained by a failed or late callback cannot become
// credential delivery through either the owned outcome or generic fallback.
// Preserve only transport-owned grants and non-credential failure metadata.
func routerCanceledHeaders(header http.Header) {
	for name := range header {
		switch strings.ToLower(name) {
		case "content-type", "retry-after", "access-control-allow-origin", "access-control-allow-credentials", "access-control-expose-headers", "vary":
		default:
			delete(header, name)
		}
	}
	routerHeaders(header)
}

// Body reads remain synchronous and feature-owned. Detect an unknown-length
// overflow even when a trusted handler neglects its read error; never permit a
// later successful response for the rejected envelope. The server owns Close.
type routerBody struct {
	io.ReadCloser
	ctx      context.Context
	exceeded bool
}

func (b *routerBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := b.ReadCloser.Read(p)
	var limit *http.MaxBytesError
	if errors.As(err, &limit) {
		b.exceeded = true
	}
	return n, err
}

func routerHeaders(header http.Header) {
	for name := range header {
		if strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") || strings.EqualFold(name, "Referrer-Policy") {
			delete(header, name)
		}
	}
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
}

func routerDeny(w http.ResponseWriter, r *http.Request, status int, code string) {
	routerHeaders(w.Header())
	for name := range w.Header() {
		if strings.EqualFold(name, "Location") || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Content-Encoding") || strings.EqualFold(name, "Set-Cookie") {
			delete(w.Header(), name)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r == nil || r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "{\"error\":\""+code+"\"}\n")
	}
}
