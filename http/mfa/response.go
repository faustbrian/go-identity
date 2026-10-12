package mfahttp

import (
	"context"
	"io"
	"net/http"
	"strings"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/felixge/httpsnoop"
)

type responsePipeline struct{ pipeline http.Handler }

func (p *responsePipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &responsePipeline{pipeline: h}, nil
}

func (p *responsePipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &attempt{out: TOTPVerifyResponse{CommitOutcome: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), attemptKey{}, a))
	defer func() {
		_ = a.proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		a.cookie, a.csrf = "", ""
	}()
	var committed, committing bool
	var cookie, csrf string
	protect := func() {
		for name := range w.Header() {
			if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		c, s := cookie, csrf
		if !committed && committing && a.out.SignedIn && a.ctx != nil && a.ctx.Err() == nil {
			c, s = a.cookie, a.csrf
		}
		if c != "" && s != "" {
			w.Header().Set("Set-Cookie", c)
			w.Header().Set("X-CSRF-Token", s)
		}
	}
	commit := func(status int) {
		if !committed && a.out.SignedIn && (status != http.StatusOK || a.ctx == nil || a.ctx.Err() != nil || a.fresh == nil || !a.fresh()) {
			a.cookie, a.csrf = "", ""
			a.out.SignedIn = false
			a.out.RecoveryRequired = nil
			a.out.SessionID = ""
			a.out.Error = "unavailable"
		}
		committing = true
		protect()
		committing = false
		if !committed {
			cookie, csrf = w.Header().Get("Set-Cookie"), w.Header().Get("X-CSRF-Token")
			committed = true
		}
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) {
				if status >= 200 {
					commit(status)
					if status == http.StatusOK && a.out.Error == "unavailable" {
						status = http.StatusServiceUnavailable
					}
				} else {
					protect()
				}
				next(status)
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(body []byte) (int, error) { commit(http.StatusOK); return next(body) }
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { commit(http.StatusOK); next() } },
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(body io.Reader) (int64, error) { commit(http.StatusOK); return next(body) }
		},
	})
	p.pipeline.ServeHTTP(writer, r)
}
