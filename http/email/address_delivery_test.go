package emailhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/felixge/httpsnoop"
)

func TestAddressDeliveryChecksBufferedMiddlewareUnwind(t *testing.T) {
	for _, mode := range []string{"fresh", "expired", "cancel", "operation-deadline", "status", "mutated", "stream-expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fresh := true
			var delivery *addressDelivery
			pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[struct{}]{
				MaximumDuration: 50 * time.Millisecond,
				Decode:          func(*http.Request) (struct{}, error) { return struct{}{}, nil },
				Authenticate:    func(*http.Request, struct{}) (struct{}, error) { return struct{}{}, nil },
				Admit:           func(*http.Request, struct{}) error { return nil },
				Reject:          func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(503) },
				Handle: func(w http.ResponseWriter, r *http.Request, _ struct{}) {
					delivery, _ = r.Context().Value(addressDeliveryKey{}).(*addressDelivery)
					body := []byte(`{"canonical":"private@example.test"}`)
					defer clear(body)
					writeAddressJSON(w, r, body, func() bool { return fresh })
				},
				Middleware: []identityhttp.MiddlewareDescriptor{{Owner: "extension/test", Middleware: identityhttp.Middleware{
					Name: "buffer", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1,
					Handler: func(next http.Handler) http.Handler {
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							buffer := httptest.NewRecorder()
							next.ServeHTTP(buffer, r)
							if mode == "expired" || mode == "stream-expired" {
								fresh = false
							}
							if mode == "cancel" {
								cancel()
							}
							if mode == "operation-deadline" {
								<-r.Context().Done()
								if ctx.Err() != nil || !fresh {
									t.Fatal("owned deadline fixture changed parent or session authority")
								}
							}
							if mode == "status" {
								buffer.Code = 503
							}
							if mode == "mutated" {
								buffer.Body.WriteString(`,"extra":"personal"`)
							}
							w.Header().Set("Content-Length", "999")
							w.WriteHeader(buffer.Code)
							if mode == "stream-expired" {
								_, _ = io.Copy(w, buffer.Body)
							} else {
								_, _ = w.Write(buffer.Body.Bytes())
							}
						})
					},
				}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			h := &confirmationPipeline{pipeline: &addressPipeline{pipeline: pipeline}}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "https://app.example/v1/email/address-list", nil).WithContext(ctx)
			h.ServeHTTP(w, r)
			if mode == "fresh" {
				if w.Code != 200 || w.Body.String() != `{"canonical":"private@example.test"}` {
					t.Fatal("fresh buffered response lost", w.Code)
				}
			} else if w.Body.String() != `{"error":"unavailable"}` || strings.Contains(w.Body.String(), "private@example.test") {
				t.Fatal("buffered personal body crossed final delivery boundary", mode, w.Code)
			}
			if (mode == "expired" || mode == "cancel" || mode == "operation-deadline" || mode == "stream-expired") && w.Code != 503 {
				t.Fatal("expired buffered response retained success status", mode, w.Code)
			}
			if w.Header().Get("Content-Length") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("buffered response changed disclosure headers")
			}
			if delivery == nil || delivery.body != nil || delivery.fresh != nil {
				t.Fatal("delivery custody retained after middleware returned")
			}
		})
	}
}

func TestAddressDeliveryNeverDisclosesPersonalBodyAfterExpiryStatusOrMutation(t *testing.T) {
	for _, mode := range []string{"fresh", "expired", "panic", "cancel", "status", "mutated", "stream"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h := &confirmationPipeline{pipeline: &addressPipeline{pipeline: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := []byte(`{"canonical":"private@example.test"}`)
				defer clear(body)
				fresh := true
				writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
					WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
						return func(status int) {
							if mode == "expired" {
								fresh = false
							}
							if mode == "cancel" {
								cancel()
							}
							if mode == "status" {
								status = 503
							}
							next(status)
						}
					},
					Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
						return func(data []byte) (int, error) {
							if mode == "mutated" {
								data[2] = 'x'
							}
							if mode == "stream" {
								_, err := io.Copy(w, strings.NewReader(string(data)))
								return len(data), err
							}
							return next(data)
						}
					},
				})
				w.Header()["set-cookie"] = []string{"injected=forbidden"}
				w.Header().Set("Content-Length", "999")
				writeAddressJSON(writer, r, body, func() bool {
					if mode == "panic" {
						panic("synthetic clock failure")
					}
					return fresh
				})
			})}}
			r := httptest.NewRequest(http.MethodGet, "https://app.example/v1/email/address-list", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			visible := mode == "fresh" || mode == "stream"
			if strings.Contains(w.Body.String(), "private@example.test") != visible || len(w.Result().Cookies()) != 0 || w.Header().Get("Content-Length") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("address body crossed final delivery boundary", mode, w.Code)
			}
			if !visible && w.Body.String() != `{"error":"unavailable"}` {
				t.Fatal("failed delivery did not withhold snapshot")
			}
		})
	}
}
