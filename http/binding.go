package identityhttp

import (
	"net/http"
	"slices"
)

// OperationMiddlewareBinder exposes an already constructed feature's actual
// execution phases to selected transport composition. Implementations retain
// the same immutable policy and borrowed domain owners, append to existing
// hooks and validate combined ownership/order before constructing wrappers.
// They must return an independent concurrent-safe handler, perform no request,
// store or network work, and preserve all response protections. This is a
// trusted integration contract, not proof that an arbitrary handler is secure.
// Construction must not race mutation of supplied descriptors. Existing
// handlers remain usable and unchanged; binding never transfers resource ownership.
type OperationMiddlewareBinder interface {
	http.Handler
	WithOperationMiddleware([]MiddlewareDescriptor) (http.Handler, error)
}

// WithOperationMiddleware binds trusted synchronous hooks into the real owned
// phases of handler. Empty selection returns the original nonnil handler.
// Nonempty selection requires OperationMiddlewareBinder; opaque complete
// handlers fail closed rather than receiving fabricated after-authentication
// phases. The returned handler preserves existing hooks and owners; the new
// binding's wrapper factories may run once each, including existing factories.
// No request stage is invoked. Binding errors, nil results and panics return
// redacted ErrInvalidInput without a partial result. This seam does not replace
// NewRouter's policy, route/document validation or real feature security.
func WithOperationMiddleware(handler http.Handler, middleware []MiddlewareDescriptor) (bound http.Handler, err error) {
	if handler == nil {
		return nil, ErrInvalidInput
	}
	if fn, ok := handler.(http.HandlerFunc); ok && fn == nil {
		return nil, ErrInvalidInput
	}
	if len(middleware) == 0 {
		return handler, nil
	}
	if len(middleware) > 64 {
		return nil, ErrInvalidInput
	}
	binder, ok := handler.(OperationMiddlewareBinder)
	if !ok {
		return nil, ErrInvalidInput
	}
	defer func() {
		if recover() != nil {
			bound, err = nil, ErrInvalidInput
		}
	}()
	bound, err = binder.WithOperationMiddleware(slices.Clone(middleware))
	if err != nil || bound == nil {
		return nil, ErrInvalidInput
	}
	if fn, ok := bound.(http.HandlerFunc); ok && fn == nil {
		return nil, ErrInvalidInput
	}
	return bound, nil
}

type operationPipeline[T any] struct {
	handler http.Handler
	config  OperationPipelineConfig[T]
}

func (p *operationPipeline[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.handler.ServeHTTP(w, r)
}

func (p *operationPipeline[T]) WithOperationMiddleware(middleware []MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.handler == nil || len(middleware) > 64-len(p.config.Middleware) {
		return nil, ErrInvalidInput
	}
	c := p.config
	c.Middleware = append(slices.Clone(c.Middleware), middleware...)
	return NewOperationPipeline(c)
}
