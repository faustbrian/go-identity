package anonymoushttp_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	"github.com/felixge/httpsnoop"
)

type streamingRecorder struct {
	*httptest.ResponseRecorder
	informational *[]http.Header
}

// Match net/http's informational/final distinction, which ResponseRecorder
// itself does not model. Only final responses capture its committed headers.
func (w streamingRecorder) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		if w.informational != nil {
			*w.informational = append(*w.informational, w.Header().Clone())
		}
		return
	}
	w.ResponseRecorder.WriteHeader(status)
}
func (w streamingRecorder) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w.ResponseRecorder, r)
}

var flushFailure = errors.New("synthetic flush failure")

func (w streamingRecorder) FlushError() error {
	w.Flush()
	return flushFailure
}

func TestAnonymousPipelineProtectsEveryResponseCommit(t *testing.T) {
	for _, mode := range []string{"write", "flush", "flush-error", "reader-from", "no-output", "informational"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, request := signinFixture(t)
			h, err := anonymoushttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/anonymous", Middleware: identityhttp.Middleware{Name: "short-circuit", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if mode == "informational" {
						w.WriteHeader(http.StatusEarlyHints)
					}
					w.Header().Set("Set-Cookie", "synthetic=untrusted")
					w.Header().Set("X-CSRF-Token", "synthetic-synchronizer")
					w.Header().Set("Cache-Control", "public")
					w.Header().Del("X-Content-Type-Options")
					switch mode {
					case "write":
						_, _ = w.Write([]byte("{}"))
					case "informational":
						w.WriteHeader(http.StatusOK)
					case "flush":
						w.(http.Flusher).Flush()
					case "flush-error":
						if err := http.NewResponseController(w).Flush(); !errors.Is(err, flushFailure) {
							t.Error("optional flush error was lost", err)
						}
					case "reader-from":
						if _, err := w.(io.ReaderFrom).ReadFrom(strings.NewReader("{}")); err != nil {
							t.Error(err)
						}
					}
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := streamingRecorder{ResponseRecorder: httptest.NewRecorder()}
			bound.ServeHTTP(w, request())
			committed := w.Result()
			if len(committed.Cookies()) != 0 || committed.Header.Get("X-CSRF-Token") != "" || committed.Header.Get("Cache-Control") != "no-store" || committed.Header.Get("Content-Type") != "application/json" || committed.Header.Get("X-Content-Type-Options") != "nosniff" || owner.calls != 0 || owner.reads != 0 {
				t.Fatal("alternate response commit bypassed custody policy")
			}
		})
	}
}

func TestAnonymousPipelineInformationalResponsesNeverDeliverCustody(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%t", expired), func(t *testing.T) {
			c, owner, request := signinFixture(t)
			now := c.Now()
			commitAt := now.Add(time.Second)
			if expired {
				commitAt = now.Add(20 * time.Second)
			}
			c.Now = func() time.Time { return now }
			result := freshGuestResult(t, c)
			owner.result = &result
			h, err := anonymoushttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/anonymous", Middleware: identityhttp.Middleware{Name: "forward-hints", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					forward := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(write httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
						return func(status int) {
							now = commitAt
							write(http.StatusEarlyHints)
							write(status)
						}
					}})
					next.ServeHTTP(forward, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			var hints []http.Header
			w := streamingRecorder{ResponseRecorder: httptest.NewRecorder(), informational: &hints}
			bound.ServeHTTP(w, request())
			if owner.calls != 1 || len(hints) != 1 {
				t.Fatal("fixture did not forward an informational response after native completion")
			}
			if len(hints[0].Values("Set-Cookie")) != 0 || hints[0].Get("X-CSRF-Token") != "" {
				t.Fatal("informational response disclosed pending owner credentials")
			}
			if expired {
				if w.Code != 503 || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("X-CSRF-Token") != "" {
					t.Fatal("expired final response disclosed custody")
				}
			} else if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Header.Get("X-CSRF-Token") == "" {
				t.Fatal("informational response prevented live final delivery")
			}
		})
	}
}

func TestAnonymousPipelineImplicitCompletionNeverRenewsClosedContext(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%t", expired), func(t *testing.T) {
			c, owner, request := signinFixture(t)
			now := c.Now()
			commitAt := now.Add(time.Second)
			if expired {
				commitAt = now.Add(20 * time.Second)
			}
			c.Now = func() time.Time { return now }
			result := freshGuestResult(t, c)
			owner.result = &result
			h, err := anonymoushttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/anonymous", Middleware: identityhttp.Middleware{Name: "capture-output", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					capture := httpsnoop.Wrap(w, httpsnoop.Hooks{
						WriteHeader: func(httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc { return func(int) {} },
						Write: func(httpsnoop.WriteFunc) httpsnoop.WriteFunc {
							return func(body []byte) (int, error) { return len(body), nil }
						},
					})
					next.ServeHTTP(capture, r)
					now = commitAt
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			bound.ServeHTTP(w, request())
			if owner.calls != 1 {
				t.Fatal("fixture did not finish native work before implicit completion")
			}
			// Returning from the owner pipeline closes its bounded context even
			// before wall-clock expiry. Dropped output cannot renew that custody.
			if w.Code != 503 || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("X-CSRF-Token") != "" {
				t.Fatal("implicit completion renewed native credential delivery")
			}
		})
	}
}
