package sessionhttp

import (
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// Keep response ownership outside the real typed pipeline when the router
// binds additional middleware. Reconstructing from caller config here would
// reacquire mutable deployment policy instead of preserving the frozen owner.
type protectedPipeline struct {
	pipeline http.Handler
	serve    func(http.Handler, http.ResponseWriter, *http.Request)
}

func (p *protectedPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serve(p.pipeline, w, r)
}

func (p *protectedPipeline) WithOperationMiddleware(middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.serve == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	bound, err := identityhttp.WithOperationMiddleware(p.pipeline, middleware)
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: bound, serve: p.serve}, nil
}
