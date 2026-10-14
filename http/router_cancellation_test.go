package identityhttp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestRouterPreservesBoundedCanceledFailureWithoutCredentials(t *testing.T) {
	for _, mode := range []string{"failure", "success", "oversized", "boundary", "read-from", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			op := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cancel()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Set-Cookie", "forbidden=value")
				w.Header().Set("X-CSRF-Token", "forbidden")
				w.Header().Set("Trailer", "X-CSRF-Token")
				if mode == "panic" {
					panic("private owner diagnostic")
				}
				if mode == "success" {
					w.WriteHeader(200)
					w.Write([]byte(`{"success":true}`))
					return
				}
				w.WriteHeader(503)
				if mode == "oversized" {
					w.Write([]byte(strings.Repeat("x", 16385)))
				} else if mode == "boundary" {
					w.Write([]byte(strings.Repeat("x", 16384)))
				} else if mode == "read-from" {
					w.(io.ReaderFrom).ReadFrom(strings.NewReader(`{"commitOutcome":"committed","commandID":"original"}`))
				} else {
					w.Write([]byte(`{"commitOutcome":"committed","commandID":"original"}`))
				}
				w.Header()[http.TrailerPrefix+"Set-Cookie"] = []string{"forbidden=value"}
			}))
			h, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{op}, nil)
			if err != nil {
				t.Fatal(err)
			}
			w := &corsReadFromRecorder{httptest.NewRecorder()}
			var aborted bool
			func() {
				defer func() {
					if p := recover(); p != nil {
						if p != http.ErrAbortHandler {
							t.Error("unexpected panic")
						}
						aborted = true
					}
				}()
				h.ServeHTTP(w, corsRequest("GET", op.Route.Path, "").WithContext(ctx))
			}()
			res := w.Result()
			if res.StatusCode != 503 || len(res.Cookies()) != 0 || res.Header.Get("X-CSRF-Token") != "" || res.Trailer.Get("Set-Cookie") != "" || res.Trailer.Get("X-CSRF-Token") != "" {
				t.Fatal("canceled response gained credential output")
			}
			if mode == "failure" || mode == "read-from" {
				if aborted || !strings.Contains(w.Body.String(), `"commandID":"original"`) {
					t.Fatal("original failure outcome lost")
				}
			} else if mode == "boundary" {
				if aborted || w.Body.Len() != 16384 {
					t.Fatal("exact canceled outcome bound denied")
				}
			} else if mode == "panic" {
				if aborted || strings.Contains(w.Body.String(), "private") {
					t.Fatal("canceled panic exposed owner diagnostics")
				}
			} else if mode == "success" {
				if aborted || strings.Contains(w.Body.String(), "success") {
					t.Fatal("canceled success admitted")
				}
			} else if !aborted || w.Body.Len() > 16384 {
				t.Fatal("unbounded canceled response")
			}
		})
	}
}
