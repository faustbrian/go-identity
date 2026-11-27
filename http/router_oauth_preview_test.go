package identityhttp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestRouterOAuthPreviewDeniesLateSessionDelivery(t *testing.T) {
	for _, mode := range []string{"handler deadline", "caller cancellation"} {
		t.Run(mode, func(t *testing.T) {
			policy := routerPolicy()
			policy.HandlerTimeout = 5 * time.Millisecond
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			preview := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "caller cancellation" {
					cancel()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(time.Second):
					t.Error("preview did not receive the shared router deadline or cancellation")
					return
				}
				w.Header().Set("Set-Cookie", "session=late; Secure; HttpOnly")
				w.Header().Set("X-CSRF-Token", "late")
				w.WriteHeader(http.StatusNoContent)
			})
			h, _, err := identityhttp.NewRouterWithOAuthPreview(policy, nil, preview)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, corsRequest(http.MethodPost, identityhttp.OAuthPreviewRelayPath, "https://preview.example").WithContext(ctx))
			res := w.Result()
			defer res.Body.Close()
			if calls != 1 || res.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("late preview success was not denied: calls=%d status=%d", calls, res.StatusCode)
			}
			if len(res.Cookies()) != 0 || res.Header.Get("X-CSRF-Token") != "" {
				t.Fatal("canceled preview delivered credentials", res.Header)
			}
			assertCORSGrants(t, res.Header, "", "", "")
		})
	}
}

func TestRouterOAuthPreviewEnforcesUnknownLengthBodyCap(t *testing.T) {
	policy := routerPolicy()
	maximum := int(policy.Network.Limits.MaximumBodyBytes)
	for _, size := range []int{maximum, maximum + 1} {
		t.Run(map[bool]string{true: "overflow", false: "exact limit"}[size > maximum], func(t *testing.T) {
			calls := 0
			preview := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				data, err := io.ReadAll(r.Body)
				if len(data) != maximum {
					t.Errorf("preview read %d bytes; want shared cap %d", len(data), maximum)
				}
				var overflow *http.MaxBytesError
				if size > maximum && !errors.As(err, &overflow) || size == maximum && err != nil {
					t.Errorf("unexpected bounded body result: %v", err)
				}
				w.Header().Set("Set-Cookie", "session=bounded; Secure; HttpOnly")
				w.WriteHeader(http.StatusNoContent)
			})
			h, _, err := identityhttp.NewRouterWithOAuthPreview(policy, nil, preview)
			if err != nil {
				t.Fatal(err)
			}
			body := &countedBody{Reader: strings.NewReader(strings.Repeat("x", size))}
			r := corsRequest(http.MethodPost, identityhttp.OAuthPreviewRelayPath, "https://preview.example")
			r.Body, r.ContentLength = body, -1
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			res := w.Result()
			defer res.Body.Close()
			wantStatus := http.StatusNoContent
			if size > maximum {
				wantStatus = http.StatusBadRequest
				if len(res.Cookies()) != 0 {
					t.Fatal("overflow preview delivered a session")
				}
			}
			if calls != 1 || res.StatusCode != wantStatus || body.closes != 0 {
				t.Fatalf("shared body custody lost: calls=%d status=%d closes=%d", calls, res.StatusCode, body.closes)
			}
		})
	}
}

func TestRouterOAuthPreviewIsExactFeatureOwnedAndOutsideCORSMetadata(t *testing.T) {
	normalCalls, previewCalls := 0, 0
	op := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		normalCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	policy := routerPolicy()
	policy.CORS = []identityhttp.CORSRoutePolicy{{Method: op.Route.Method, Path: op.Route.Path,
		Credentials: identityhttp.CORSCookieCredentials, Origins: []identityhttp.Origin{"https://client.example"}}}
	_, baseline, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal(err)
	}
	preview := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		previewCalls++
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h, document, err := identityhttp.NewRouterWithOAuthPreview(policy, []identityhttp.OperationDescriptor{op}, preview)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseline.JSON(), document.JSON()) || len(document.Operations()) != len(baseline.Operations()) {
		t.Fatal("browser-only preview changed the selected OpenAPI contract")
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions, http.MethodHead, http.MethodDelete} {
		r := corsRequest(method, identityhttp.OAuthPreviewRelayPath, "https://preview.example")
		if method == http.MethodOptions {
			r.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		wantStatus := http.StatusNoContent
		if method != http.MethodGet && method != http.MethodPost {
			wantStatus = http.StatusMethodNotAllowed
			if w.Header().Get("Allow") != "GET, POST" {
				t.Fatalf("%s did not receive the feature-owned method rejection", method)
			}
		}
		if w.Code != wantStatus {
			t.Fatalf("%s preview: got %d want %d", method, w.Code, wantStatus)
		}
		assertCORSGrants(t, w.Result().Header, "", "", "")
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("preview bypassed shared response custody", w.Header())
		}
	}
	for _, path := range []string{identityhttp.OAuthPreviewRelayPath + "/", "/OAuth2/preview/complete", "/v1" + identityhttp.OAuthPreviewRelayPath} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest(http.MethodGet, path, ""))
		if w.Code != http.StatusNotFound {
			t.Fatalf("preview alias admitted %q: %d", path, w.Code)
		}
	}
	if previewCalls != 5 || normalCalls != 0 {
		t.Fatalf("unexpected dispatch: preview=%d normal=%d", previewCalls, normalCalls)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest(op.Route.Method, op.Route.Path, "https://client.example"))
	if w.Code != http.StatusAccepted || normalCalls != 1 || previewCalls != 5 {
		t.Fatal("preview selection changed normal operation dispatch")
	}
	assertCORSGrants(t, w.Result().Header, "https://client.example", "true", "")
}
