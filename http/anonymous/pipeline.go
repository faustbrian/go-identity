package anonymoushttp

import (
	"context"
	"io"
	"net/http"
	"strings"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/felixge/httpsnoop"
)

// All response custody is request-local. The operation pipeline owns the
// bounded context; wrappers cannot turn a completed command into permission
// to reveal credentials after that original context/validity has expired.
type browserAttempt struct {
	signin   SigninResponse
	deletion DeletionResponse
	upgrade  UpgradeResponse
	ctx      context.Context
	cookies  []string
	csrf     string
	fresh    func() bool
	revoke   func()
}
type browserAttemptKey struct{}

func attemptFor(r *http.Request) *browserAttempt {
	a, _ := r.Context().Value(browserAttemptKey{}).(*browserAttempt)
	return a
}

type browserPipeline struct{ pipeline http.Handler }

func (p *browserPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &browserPipeline{pipeline: h}, nil
}

func (p *browserPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &browserAttempt{signin: SigninResponse{CommitOutcome: "none"}, deletion: DeletionResponse{CommitOutcome: "none"}, upgrade: UpgradeResponse{CommitOutcome: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), browserAttemptKey{}, a))
	committed := false
	protect := func(deliver bool) {
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "X-Content-Type-Options") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !deliver {
			return
		}
		for _, cookie := range a.cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
		if a.csrf != "" {
			w.Header().Set("X-CSRF-Token", a.csrf)
		}
	}
	commit := func(status int) int {
		if status >= 100 && status < 200 {
			// Informational headers are not credential delivery, even while the
			// pending native result is live. Only a final fresh commit may reveal.
			protect(false)
			return status
		}
		if committed {
			return status
		}
		if a.fresh != nil && (status != http.StatusOK || a.ctx == nil || a.ctx.Err() != nil || !a.fresh()) {
			a.cookies, a.csrf = nil, ""
			if a.revoke != nil {
				a.revoke()
			}
			if status == http.StatusOK {
				status = http.StatusServiceUnavailable
			}
		}
		protect(true)
		committed = true
		return status
	}
	protect(true)
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) { next(commit(status)) }
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(b []byte) (int, error) {
				if !committed {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect(true)
				return next(b)
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if !committed {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect(true)
				next()
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(body io.Reader) (int64, error) {
				if !committed {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect(true)
				return next(body)
			}
		},
	})
	defer func() {
		if !committed {
			w.WriteHeader(commit(http.StatusOK))
			return
		}
		protect(true)
	}()
	p.pipeline.ServeHTTP(writer, r)
}
