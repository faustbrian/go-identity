package emailhttp

import (
	"context"
	"io"
	"net/http"
	"strings"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/felixge/httpsnoop"
)

// The no-session profile never acquires credential response custody. Protect
// final commitment and middleware unwind, including noncanonical header names
// and magic Trailer: fields that net/http publishes only after handler return.
type confirmationPipeline struct{ pipeline http.Handler }

func (p *confirmationPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &confirmationPipeline{pipeline: h}, nil
}
func (p *confirmationPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), attemptKey{}, &confirmationAttempt{out: ConfirmationResponse{CommitOutcome: "none"}}))
	}
	protect := func() {
		for name := range w.Header() {
			if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r != nil {
			a := attemptFor(r)
			if a.out.Signin != nil && a.out.Signin.SignedIn && a.cookie != "" && a.csrf != "" {
				w.Header().Set("Set-Cookie", a.cookie)
				w.Header().Set("X-CSRF-Token", a.csrf)
			}
		}
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) { protect(); next(status) }
	}, Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(body []byte) (int, error) { protect(); return next(body) }
	}, Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { protect(); next() } }, ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
		return func(body io.Reader) (int64, error) { protect(); return next(body) }
	}})
	p.pipeline.ServeHTTP(writer, r)
}
