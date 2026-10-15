package mfahttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	primitive "github.com/faustbrian/go-password/v2"
)

type secretReaderOnly struct{ io.Reader }
type secretReaderFromRecorder struct{ *httptest.ResponseRecorder }

func (w secretReaderFromRecorder) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{w.ResponseRecorder}, r)
}

type secretStreamingWriter struct{ http.ResponseWriter }

func (w secretStreamingWriter) Write(data []byte) (int, error) {
	n, err := io.Copy(w.ResponseWriter, secretReaderOnly{bytes.NewReader(data)})
	return int(n), err
}

func TestEnrollmentSecretsRespectFinalCommit(t *testing.T) {
	for _, profile := range []string{"uri", "recovery-codes"} {
		for _, mode := range []string{"success", "stream-success", "delay", "cancel", "changed-status", "stream-delay", "stream-cancel", "stream-changed-status"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				var h http.Handler
				var r *http.Request
				var advance func()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				m := []identityhttp.MiddlewareDescriptor{{Owner: "identity/mfa", Middleware: identityhttp.Middleware{Name: "secret-final-commit", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
						wrapped := commitWriter{ResponseWriter: w}
						if strings.HasSuffix(mode, "changed-status") {
							wrapped.status = 503
						} else if strings.HasSuffix(mode, "delay") {
							wrapped.before = advance
						} else if strings.HasSuffix(mode, "cancel") {
							wrapped.before = cancel
						}
						if strings.HasPrefix(mode, "stream-") {
							wrapped.ResponseWriter = secretStreamingWriter{w}
						}
						next.ServeHTTP(wrapped, request)
					})
				}}}}
				var err error
				if profile == "uri" {
					c, _, _, clock, request := uriFixture(t)
					r = request
					advance = func() { clock.now = clock.now.Add(time.Hour) }
					h, err = NewURIHandlerWithMiddleware(c, m)
				} else {
					c, owner, _, clock, request := enableFixture(t)
					first, _ := primitive.NewSecret([]byte("SYNTHETIC-RECOVERY-ONE"))
					second, _ := primitive.NewSecret([]byte("SYNTHETIC-RECOVERY-TWO"))
					owner.result.RecoveryMaterial = mfa.RevealOnceCodes{Codes: []primitive.Secret{first, second}}
					r = request
					advance = func() { clock.now = clock.now.Add(time.Hour) }
					h, err = NewEnableHandlerWithMiddleware(c, m)
				}
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(secretReaderFromRecorder{w}, r.WithContext(ctx))
				body := w.Body.String()
				if strings.HasSuffix(mode, "success") {
					if w.Code != 200 || !strings.Contains(body, "SYNTHETIC") {
						t.Fatal("fresh owned secret delivery failed", w.Code)
					}
					return
				}
				if strings.Contains(body, "SYNTHETIC") || strings.Contains(body, `"uri"`) || strings.Contains(body, `"recoveryCodes"`) || w.Code == 200 {
					t.Fatal("invalid final commitment disclosed enrollment secret", w.Code)
				}
			})
		}
	}
}
