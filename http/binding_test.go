package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestOperationMiddlewareBindingPreservesOwnedStagesAndSnapshots(t *testing.T) {
	var trace []string
	hook := func(name string, phase identityhttp.MiddlewarePhase, order uint32) identityhttp.MiddlewareDescriptor {
		return identityhttp.MiddlewareDescriptor{Owner: "extension", Middleware: identityhttp.Middleware{Name: name, Phase: phase, Order: order, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, name)
				if value, ok := identityhttp.PipelineValue[int](r); phase != identityhttp.MiddlewareBeforeAuth && (!ok || value != 42) {
					t.Error("binding lost the actual authenticated state")
				}
				next.ServeHTTP(w, r)
			})
		}}}
	}
	c := identityhttp.OperationPipelineConfig[int]{MaximumDuration: time.Second,
		Middleware:   []identityhttp.MiddlewareDescriptor{hook("owner-hook", identityhttp.MiddlewareAfterAuth, 20)},
		Decode:       func(*http.Request) (int, error) { trace = append(trace, "decode"); return 0, nil },
		Authenticate: func(*http.Request, int) (int, error) { trace = append(trace, "auth"); return 42, nil },
		Admit:        func(*http.Request, int) error { trace = append(trace, "admit"); return nil },
		Handle: func(w http.ResponseWriter, _ *http.Request, _ int) {
			trace = append(trace, "handle")
			w.WriteHeader(204)
		},
		Reject: func(w http.ResponseWriter, _ *http.Request, _ error) {
			t.Error("unexpected rejection")
			w.WriteHeader(503)
		},
	}
	original, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	added := []identityhttp.MiddlewareDescriptor{hook("router-hook", identityhttp.MiddlewareAfterAuth, 10)}
	bound, err := identityhttp.WithOperationMiddleware(original, added)
	if err != nil {
		t.Fatal(err)
	}
	// Neither the source config nor a later selection can rewrite a frozen binding.
	c.Middleware[0].Middleware.Name = "mutated"
	added[0].Middleware.Handler = nil
	for _, tc := range []struct {
		h    http.Handler
		want []string
	}{
		{original, []string{"decode", "auth", "owner-hook", "admit", "handle"}},
		{bound, []string{"decode", "auth", "router-hook", "owner-hook", "admit", "handle"}},
	} {
		trace = nil
		w := httptest.NewRecorder()
		tc.h.ServeHTTP(w, httptest.NewRequest("GET", "https://tenant.example/test", nil))
		if w.Code != 204 || !reflect.DeepEqual(trace, tc.want) {
			t.Fatalf("trace=%v status=%d", trace, w.Code)
		}
	}
}

func TestOperationMiddlewareBindingRejectsOpaqueAndConflictingHandlers(t *testing.T) {
	var factories int
	hook := identityhttp.MiddlewareDescriptor{Owner: "extension", Middleware: identityhttp.Middleware{Name: "same", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(next http.Handler) http.Handler { factories++; return next }}}
	c := identityhttp.OperationPipelineConfig[int]{MaximumDuration: time.Second, Middleware: []identityhttp.MiddlewareDescriptor{hook},
		Decode: func(*http.Request) (int, error) { return 0, nil }, Authenticate: func(*http.Request, int) (int, error) { return 0, nil },
		Admit: func(*http.Request, int) error { return nil }, Handle: func(http.ResponseWriter, *http.Request, int) {}, Reject: func(http.ResponseWriter, *http.Request, error) {},
	}
	original, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	factories = 0
	if h, err := identityhttp.WithOperationMiddleware(original, []identityhttp.MiddlewareDescriptor{hook}); err == nil || h != nil || factories != 0 {
		t.Fatal("conflicting binding constructed wrappers")
	}
	for _, h := range []http.Handler{nil, http.HandlerFunc(nil), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})} {
		if bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{hook}); err == nil || bound != nil || factories != 0 {
			t.Fatal("opaque handler pretended to expose owned phases")
		}
	}
	if bound, err := identityhttp.WithOperationMiddleware(original, nil); err != nil || bound != original {
		t.Fatal("empty selection changed handler ownership")
	}
}
