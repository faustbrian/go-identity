package otphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/felixge/httpsnoop"
)

type signinAttempt struct {
	out          SigninResponse
	attempted    bool
	cookie, csrf string
	ctx          context.Context
}
type signinAttemptKey struct{}

// SigninState retains opaque request-local pre-auth custody, not a user
// principal or reusable authority. Only the native consuming owner may issue
// a session. Do not retain this value beyond its request; middleware can observe
// detached credential-free attempt metadata but cannot replace private input.
type SigninState struct {
	facts      identityhttp.NetworkFacts
	request    otp.SigninRequest
	identifier string
	attempt    *signinAttempt
}

// Attempt returns detached original metadata. True means Handle entered, not
// that execution committed or credentials reached the browser. Known outcomes
// survive failure; unknown remains unknown. Recovery conveys no authority.
func (s SigninState) Attempt() (SigninResponse, bool) {
	if s.attempt == nil {
		return SigninResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Recovery != nil {
		copy := *out.Recovery
		out.Recovery = &copy
	}
	return out, s.attempt.attempted
}

// Format prevents private source, code or credential traversal.
func (SigninState) Format(s fmt.State, _ rune) { io.WriteString(s, "otphttp.SigninState(redacted)") }

// MarshalJSON denies implicit request-state export.
func (SigninState) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit request-state export.
func (SigninState) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// LogValue redacts request-state diagnostics.
func (SigninState) LogValue() slog.Value { return slog.StringValue("otphttp.SigninState(redacted)") }

func signinAttemptFor(r *http.Request) *signinAttempt {
	if r != nil {
		if a, ok := r.Context().Value(signinAttemptKey{}).(*signinAttempt); ok {
			return a
		}
	}
	return &signinAttempt{out: SigninResponse{CommitOutcome: "none"}}
}

type signinFailure struct {
	status int
	code   string
	retry  time.Duration
}

func (f signinFailure) Error() string { return "identity.http.otp.signin." + f.code }
func signinRateError(out identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return signinFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
	}
	if err != nil || !out.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}

func signinResponse(w http.ResponseWriter, a *signinAttempt, status int, code string) {
	a.out.Error = code
	data, err := json.Marshal(a.out)
	if err != nil {
		a.cookie, a.csrf = "", ""
		status = 503
		data = []byte(`{"error":"unavailable"}`)
	}
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}

// Response ownership surrounds the pipeline even after router rebinding;
// rebuilding from caller configuration would lose frozen owner/cookie custody.
type signinPipeline struct{ pipeline http.Handler }

func (p *signinPipeline) WithOperationMiddleware(middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	bound, err := identityhttp.WithOperationMiddleware(p.pipeline, middleware)
	if err != nil {
		return nil, err
	}
	return &signinPipeline{pipeline: bound}, nil
}
func (p *signinPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &signinAttempt{out: SigninResponse{CommitOutcome: "none"}}
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), signinAttemptKey{}, a))
	}
	var committed bool
	var deliveredCookie, deliveredCSRF string
	protect := func() {
		// Header maps admit noncanonical spellings. Only this owner can deliver
		// the freshly committed tuple; hooks cannot forge either credential.
		// This fixed JSON profile has no response trailers. Go publishes magic
		// Trailer: fields after handler return, including middleware unwind.
		for name := range w.Header() {
			if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		cookie, csrf := deliveredCookie, deliveredCSRF
		if !committed && a.out.SignedIn && a.ctx != nil && a.ctx.Err() == nil {
			cookie, csrf = a.cookie, a.csrf
		}
		if cookie != "" && csrf != "" {
			w.Header().Set("Set-Cookie", cookie)
			w.Header().Set("X-CSRF-Token", csrf)
		}
	}
	commit := func() {
		protect()
		if !committed {
			deliveredCookie = w.Header().Get("Set-Cookie")
			deliveredCSRF = w.Header().Get("X-CSRF-Token")
			committed = true
		}
	}
	protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) {
				if status >= 200 {
					commit()
				} else {
					protect()
				}
				next(status)
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(body []byte) (int, error) { commit(); return next(body) }
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { commit(); next() } },
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(body io.Reader) (int64, error) { commit(); return next(body) }
		},
	})
	defer protect()
	p.pipeline.ServeHTTP(writer, r)
}
