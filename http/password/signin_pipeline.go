package passwordhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

type signinAttempt struct {
	secret       primitive.Secret
	out          SigninResponse
	attempted    bool
	cookie, csrf string
	ctx          context.Context
}
type signinAttemptKey struct{}

// SigninState retains immutable request-local original custody, not a user
// principal or reusable authority. Do not retain it beyond synchronous hooks.
type SigninState struct {
	facts      identityhttp.NetworkFacts
	request    password.SigninRequest
	device     session.BrowserDevice
	identifier string
	attempt    *signinAttempt
}

// Attempt returns detached safe metadata; true means native Handle entered,
// not commitment or credential delivery. Recovery never grants permission.
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

// Format redacts private request custody.
func (SigninState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.SigninState(redacted)")
}

// MarshalJSON denies implicit state export.
func (SigninState) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit state export.
func (SigninState) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (SigninState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.SigninState(redacted)")
}

func signinAttemptFor(r *http.Request) *signinAttempt {
	if r != nil {
		if a, ok := r.Context().Value(signinAttemptKey{}).(*signinAttempt); ok {
			return a
		}
	}
	return &signinAttempt{out: SigninResponse{CommitOutcome: "none"}}
}
func signinRateError(out identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return failure{status: 429, code: "rate_limited", retry: out.RetryAfter}
	}
	if err != nil || !out.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}
func signinOutcome(out identity.CommitOutcome) string {
	switch out {
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	}
	return "unknown"
}
func writeSigninResponse(w http.ResponseWriter, status int, out SigninResponse) {
	data, err := json.Marshal(out)
	if err != nil {
		w.WriteHeader(503)
		return
	}
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}

type signinPipeline struct{ pipeline http.Handler }

func (p *signinPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &signinPipeline{pipeline: h}, nil
}
func (p *signinPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &signinAttempt{out: SigninResponse{CommitOutcome: "none"}}
	defer func() { a.secret.Destroy() }()
	r = r.WithContext(context.WithValue(r.Context(), signinAttemptKey{}, a))
	servePasswordPipelineWithDelivery(w, r, p.pipeline, func() (string, string) {
		if a.out.SignedIn && a.ctx != nil && a.ctx.Err() == nil {
			return a.cookie, a.csrf
		}
		return "", ""
	})
}
