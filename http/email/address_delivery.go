package emailhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/felixge/httpsnoop"
)

type addressDeliveryKey struct{}
type addressDelivery struct {
	body    []byte
	fresh   func() bool
	status  int
	written bool
}

func (s *addressDelivery) valid(r *http.Request) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return s != nil && s.fresh != nil && r.Context().Err() == nil && s.fresh()
}

func writeAddressJSON(w http.ResponseWriter, r *http.Request, body []byte, fresh func() bool) {
	s, ok := r.Context().Value(addressDeliveryKey{}).(*addressDelivery)
	if !ok || s == nil || s.fresh != nil {
		w.WriteHeader(503)
		return
	}
	s.body = bytes.Clone(body)
	// The operation owns a shorter deadline than the outer HTTP request.
	// Preserve its original context through synchronous middleware unwind too.
	owned := r.Context()
	s.fresh = func() bool { return owned.Err() == nil && fresh() }
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func (s *addressDelivery) write(r *http.Request, body []byte, next func([]byte) (int, error)) (int, error) {
	if s.fresh == nil {
		return next(body)
	}
	if s.written {
		return len(body), nil
	}
	s.written = true
	if s.status == 200 && s.valid(r) && bytes.Equal(body, s.body) {
		return next(body)
	}
	_, e := next([]byte(`{"error":"unavailable"}`))
	return len(body), e
}

type addressPipeline struct{ pipeline http.Handler }

func (p *addressPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, e := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if e != nil {
		return nil, e
	}
	return &addressPipeline{pipeline: h}, nil
}
func (p *addressPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := &addressDelivery{}
	// Synchronous middleware may buffer output and flush while unwinding after
	// the domain handler returns. Keep the disclosure guard until that finishes.
	defer func() { clear(s.body); s.body, s.fresh = nil, nil }()
	r = r.WithContext(context.WithValue(r.Context(), addressDeliveryKey{}, s))
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) {
				if s.fresh != nil {
					w.Header().Del("Content-Length")
					if status == 200 && !s.valid(r) {
						status = 503
					}
				}
				if status >= 200 && s.status == 0 {
					s.status = status
				}
				next(status)
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(body []byte) (int, error) { return s.write(r, body, next) }
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(reader io.Reader) (int64, error) {
				if s.fresh == nil {
					return next(reader)
				}
				body, e := io.ReadAll(io.LimitReader(reader, int64(len(s.body))+1))
				defer clear(body)
				if e != nil {
					return 0, e
				}
				n, e := s.write(r, body, w.Write)
				return int64(n), e
			}
		},
	})
	p.pipeline.ServeHTTP(writer, r)
}
