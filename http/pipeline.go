package identityhttp

import (
	"context"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/felixge/httpsnoop"
)

// MiddlewarePhase identifies a real execution boundary, not a metadata claim.
type MiddlewarePhase uint8

const (
	// MiddlewareBeforeAuth runs after Decode, before credential validation.
	MiddlewareBeforeAuth MiddlewarePhase = iota + 1
	// MiddlewareAfterAuth runs after Authenticate, before Admit.
	MiddlewareAfterAuth
	// MiddlewareBeforeHandler runs after Admit, before the protected operation.
	MiddlewareBeforeHandler
	// MiddlewareAfterHandler observes a normally returned operation attempt.
	// It cannot change the response and does not imply a committed transaction.
	MiddlewareAfterHandler
)

// MiddlewareFunc constructs a trusted, synchronous wrapper once. It must not
// perform IO during construction, retain requests, start goroutines or unwrap
// response writers. Calling next is optional; repeated calls cannot repeat an
// owned stage. Returned handlers must support concurrent independent requests.
type MiddlewareFunc func(http.Handler) http.Handler

// Middleware names one wrapper at a fixed phase and order. Name contains
// 1..128 ASCII letters, digits, underscores, dots or hyphens; Order is 1..10000. An equal order
// within a phase is rejected, not resolved using incidental slice order.
type Middleware struct {
	Name    string
	Phase   MiddlewarePhase
	Order   uint32
	Handler MiddlewareFunc
}

// MiddlewareDescriptor attributes a wrapper to a validated ModuleID. The
// owner/name pair must be unique across phases. Attribution is not authority.
type MiddlewareDescriptor struct {
	Owner      ModuleID
	Middleware Middleware
}

// OperationPipelineConfig exposes feature-owned execution stages to transport
// composition without importing optional implementations or repeating their
// security work. Every callback is required, including explicit public/no-auth
// decisions. Decode owns bounded input acquisition; Authenticate acquires the
// owner's request-scoped identity exactly once; Admit owns authorization, rate,
// origin and transactional CSRF admission appropriate to that operation.
// Handle owns the domain call, response and ambiguous outcome semantics. Reject
// maps errors to a redacted response; it must never expose raw diagnostics.
//
// T is a feature's typed per-request state, never a package-global principal or
// caller-supplied authorization proof. Callbacks and middleware are trusted
// concurrency-safe borrowed code, must honor the request context and must not
// retain requests/state or start detached work. MaximumDuration is 1ms..30s;
// the server separately owns raw IO and response streaming bounds. This seam
// alone is not NewRouter, network admission, a decoder or an authentication
// implementation; real feature integrations must supply their existing owners.
type OperationPipelineConfig[T any] struct {
	MaximumDuration time.Duration
	Middleware      []MiddlewareDescriptor
	Decode          func(*http.Request) (T, error)
	Authenticate    func(*http.Request, T) (T, error)
	Admit           func(*http.Request, T) error
	Handle          func(http.ResponseWriter, *http.Request, T)
	Reject          func(http.ResponseWriter, *http.Request, error)
}

type pipelineKey struct{}
type pipelineFrame[T any] struct {
	owner   *byte
	request *http.Request
	value   T
	ready   atomic.Bool
	entered [4]atomic.Bool
}

type pipelineView[T any] struct {
	frame *pipelineFrame[T]
	phase int
}

func pipelineRequest[T any](frame *pipelineFrame[T], phase int) *http.Request {
	view := frame.request.Clone(context.WithValue(frame.request.Context(), pipelineKey{}, pipelineView[T]{frame: frame, phase: phase}))
	view.Body, view.GetBody = http.NoBody, nil
	view.Form, view.PostForm, view.MultipartForm = nil, nil, nil
	// Request.Clone retains TLS/Response pointers. Middleware has no custody of
	// mutable connection/certificate state or an associated response body.
	view.TLS, view.Response = nil, nil
	return view
}

// PipelineValue returns this pipeline's typed state only after successful
// Authenticate. It is for trusted synchronous middleware, not a general-purpose
// credential or a reusable proof. T is copied shallowly; immutable opaque owner
// values retain their original validity limits. Before-auth, nil, unrelated and
// differently typed requests return false. The original borrowed request never
// receives this private context state; middleware cannot inject it using headers.
func PipelineValue[T any](r *http.Request) (T, bool) {
	var zero T
	if r == nil {
		return zero, false
	}
	view, ok := r.Context().Value(pipelineKey{}).(pipelineView[T])
	if !ok || view.phase == 0 || !view.frame.ready.Load() {
		return zero, false
	}
	return view.frame.value, true
}

// NewOperationPipeline validates the complete configuration before invoking any
// wrapper constructor, then freezes deterministic phase/order composition. It
// invokes no feature stage, store or network operation. Invalid values, duplicate
// ownership/order, nil returned handlers or constructor panics fail atomically.
// At most 64 wrappers are accepted. Inputs must remain stable during construction.
//
// Request processing is Decode -> BeforeAuth -> Authenticate -> AfterAuth ->
// Admit -> BeforeHandler -> Handle -> AfterHandler. Wrapper entry order is
// ascending and unwind order descending within each phase. A short circuit or
// error stops later phases. AfterHandler sees a read-only response facade and
// runs only after Handle returns normally, regardless of its domain outcome.
// Middleware receives detached metadata, no TLS/Response pointers and no readable
// body; owner stages use
// the original bounded request snapshot, so wrapper metadata changes cannot
// replace credential/tenant inputs or extend the owner deadline. Cancellation
// is checked before each stage. Re-entry does not repeat authentication, admission
// or mutation. Precommit panics map to ErrUnavailable. After output/streaming has
// begun, panics abort the transport via http.ErrAbortHandler rather than completing
// a partial response or overwriting committed bytes. An intentional ErrAbortHandler
// is preserved in either state; no raw panic value escapes to server diagnostics.
func NewOperationPipeline[T any](c OperationPipelineConfig[T]) (handler http.Handler, err error) {
	if c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.Middleware) > 64 || c.Decode == nil || c.Authenticate == nil || c.Admit == nil || c.Handle == nil || c.Reject == nil {
		return nil, ErrInvalidInput
	}
	middleware := slices.Clone(c.Middleware)
	c.Middleware = middleware
	names := make(map[string]bool)
	orders := make(map[[2]uint32]bool)
	for _, d := range middleware {
		m := d.Middleware
		key := string(d.Owner) + "\x00" + m.Name
		order := [2]uint32{uint32(m.Phase), m.Order}
		if !moduleID(d.Owner) || !identifier(m.Name, 128) || m.Phase < MiddlewareBeforeAuth || m.Phase > MiddlewareAfterHandler || m.Order < 1 || m.Order > 10000 || m.Handler == nil || names[key] || orders[order] {
			return nil, ErrInvalidInput
		}
		names[key], orders[order] = true, true
	}
	slices.SortFunc(middleware, func(a, b MiddlewareDescriptor) int {
		if a.Middleware.Phase != b.Middleware.Phase {
			return int(a.Middleware.Phase) - int(b.Middleware.Phase)
		}
		return int(a.Middleware.Order) - int(b.Middleware.Order)
	})
	defer func() {
		if recover() != nil {
			handler, err = nil, ErrInvalidInput
		}
	}()
	var phases [4]http.Handler
	owner := new(byte)
	for phase := 3; phase >= 0; phase-- {
		phases[phase] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			view, ok := r.Context().Value(pipelineKey{}).(pipelineView[T])
			if !ok || view.phase != phase {
				return
			}
			f := view.frame
			if f.owner != owner || !f.entered[phase].CompareAndSwap(false, true) {
				return
			}
			// Observation has no response custody or remaining owned stage. In
			// particular, never call Reject through its read-only writer.
			if phase == 3 {
				return
			}
			if err := f.request.Context().Err(); err != nil {
				c.Reject(w, f.request, err)
				return
			}
			advance := func(next int) {
				if err := f.request.Context().Err(); err != nil {
					c.Reject(w, f.request, err)
					return
				}
				phases[next].ServeHTTP(w, pipelineRequest(f, next))
			}
			switch phase {
			case 0:
				value, err := c.Authenticate(f.request, f.value)
				if err != nil {
					c.Reject(w, f.request, err)
					return
				}
				f.value = value
				f.ready.Store(true)
				advance(1)
			case 1:
				if err := c.Admit(f.request, f.value); err != nil {
					c.Reject(w, f.request, err)
					return
				}
				advance(2)
			case 2:
				c.Handle(w, f.request, f.value)
				if f.request.Context().Err() != nil {
					return
				}
				phases[3].ServeHTTP(pipelineObservation{header: w.Header().Clone()}, pipelineRequest(f, 3))
			}
		})
		for i := len(middleware) - 1; i >= 0; i-- {
			if int(middleware[i].Middleware.Phase)-1 != phase {
				continue
			}
			phases[phase] = middleware[i].Middleware.Handler(phases[phase])
			if phases[phase] == nil {
				return nil, ErrInvalidInput
			}
			if fn, ok := phases[phase].(http.HandlerFunc); ok && fn == nil {
				return nil, ErrInvalidInput
			}
		}
	}
	run := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || r.URL == nil {
			c.Reject(w, r, ErrInvalidInput)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), c.MaximumDuration)
		defer cancel()
		owned := r.Clone(ctx)
		committed := false
		writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(status int) {
					if status >= 200 {
						committed = true
					}
					next(status)
				}
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(body []byte) (int, error) { committed = true; return next(body) }
			},
			Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { committed = true; next() } },
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(reader io.Reader) (int64, error) {
					// ReadFrom may bypass Write. Conservatively retain response custody
					// once the underlying writer's streaming fast path is entered.
					committed = true
					return next(reader)
				}
			},
		})
		defer func() {
			if recovered := recover(); recovered != nil {
				if committed || recovered == http.ErrAbortHandler {
					panic(http.ErrAbortHandler)
				}
				c.Reject(writer, owned, ErrUnavailable)
			}
		}()
		if err := ctx.Err(); err != nil {
			c.Reject(writer, owned, err)
			return
		}
		value, err := c.Decode(owned)
		if err != nil {
			c.Reject(writer, owned, err)
			return
		}
		if err := ctx.Err(); err != nil {
			c.Reject(writer, owned, err)
			return
		}
		frame := &pipelineFrame[T]{owner: owner, request: owned, value: value}
		defer frame.ready.Store(false)
		phases[0].ServeHTTP(writer, pipelineRequest(frame, 0))
	})
	return &operationPipeline[T]{handler: run, config: c}, nil
}

type pipelineObservation struct{ header http.Header }

func (w pipelineObservation) Header() http.Header     { return w.header.Clone() }
func (pipelineObservation) WriteHeader(int)           {}
func (pipelineObservation) Write([]byte) (int, error) { return 0, ErrInvalidInput }
