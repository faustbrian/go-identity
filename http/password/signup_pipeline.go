package passwordhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

type signupAttempt struct {
	secret    primitive.Secret
	out       SignupResponse
	attempted bool
}
type signupAttemptKey struct{}

// SignupState is immutable request-local custody, not principal authority.
// Hooks must not retain it beyond synchronous execution.
type SignupState struct {
	facts      identityhttp.NetworkFacts
	request    password.SignupRequest
	device     session.BrowserDevice
	identifier string
	attempt    *signupAttempt
}

// Attempt returns detached safe metadata. True means native Signup was entered,
// not commitment or permission to retry or disclose account identity.
func (s SignupState) Attempt() (SignupResponse, bool) {
	if s.attempt == nil {
		return SignupResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Recovery != nil {
		copy := *out.Recovery
		out.Recovery = &copy
	}
	return out, s.attempt.attempted
}

// Format redacts original input/key custody.
func (SignupState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.SignupState(redacted)")
}

// MarshalJSON denies implicit state export.
func (SignupState) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit state export.
func (SignupState) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (SignupState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.SignupState(redacted)")
}
func signupAttemptFor(r *http.Request) *signupAttempt {
	if r != nil {
		if a, ok := r.Context().Value(signupAttemptKey{}).(*signupAttempt); ok {
			return a
		}
	}
	return &signupAttempt{out: SignupResponse{CommitOutcome: "none"}}
}
func writeSignupResponse(w http.ResponseWriter, status int, out SignupResponse) {
	data, err := json.Marshal(out)
	if err != nil {
		w.WriteHeader(503)
		return
	}
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}

type signupPipeline struct{ pipeline http.Handler }

func (p *signupPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &signupPipeline{h}, nil
}
func (p *signupPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &signupAttempt{out: SignupResponse{CommitOutcome: "none"}}
	defer func() { a.secret.Destroy() }()
	r = r.WithContext(context.WithValue(r.Context(), signupAttemptKey{}, a))
	servePasswordPipeline(w, r, p.pipeline)
}
