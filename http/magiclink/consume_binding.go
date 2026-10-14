package magiclinkhttp

import (
	"context"
	"io"
	"net/http"
	"strings"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/felixge/httpsnoop"
)

// Consuming output has one owner. Freeze only its exact fresh tuple at final
// commitment; protect informational responses and middleware unwind separately.
type consumePipeline struct{ pipeline http.Handler }

func (p *consumePipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, e := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if e != nil {
		return nil, e
	}
	return &consumePipeline{pipeline: h}, nil
}
func (p *consumePipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &consumeAttempt{out: ConsumeResponse{CommitOutcome: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), consumeKey{}, a))
	defer func() {
		_ = a.proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		_ = a.child.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		a.challenge = ""
	}()
	var committed, committing bool
	var deliveredCookie, deliveredCSRF string
	var deliveredChallenge string
	protect := func() {
		for name := range w.Header() {
			if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Location") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		cookie, csrf := deliveredCookie, deliveredCSRF
		challenge := deliveredChallenge
		if !committed && committing && a.out.SignedIn && a.ctx != nil && a.ctx.Err() == nil {
			cookie, csrf = a.cookie, a.csrf
		}
		if !committed && committing && a.out.ChallengeRequired && a.ctx != nil && a.ctx.Err() == nil {
			challenge = a.challenge
		}
		if cookie != "" && csrf != "" {
			w.Header().Set("Set-Cookie", cookie)
			w.Header().Set("X-CSRF-Token", csrf)
		}
		if challenge != "" && cookie == "" && csrf == "" {
			w.Header().Set("X-MFA-Token", challenge)
		}
	}
	commit := func(status int) {
		if !committed && (a.out.SignedIn || a.out.ChallengeRequired) && (status != http.StatusOK || a.ctx == nil || a.ctx.Err() != nil || a.deliveryFresh == nil || !a.deliveryFresh()) {
			a.cookie, a.csrf = "", ""
			a.challenge = ""
			a.out.ChallengeRequired = false
			a.out.ChallengeID, a.out.ChallengeMethod, a.out.ChallengeExpiresAt = "", "", ""
			a.out.SignedIn = false
			a.out.SessionID = ""
			a.out.Error = "unavailable"
		}
		committing = true
		protect()
		committing = false
		if !committed {
			deliveredCookie = w.Header().Get("Set-Cookie")
			deliveredCSRF = w.Header().Get("X-CSRF-Token")
			deliveredChallenge = w.Header().Get("X-MFA-Token")
			committed = true
		}
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) {
			if status >= 200 {
				commit(status)
				if status == http.StatusOK && !a.out.SignedIn && a.out.Error == "unavailable" {
					status = http.StatusServiceUnavailable
				}
			} else {
				protect()
			}
			next(status)
		}
	}, Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(body []byte) (int, error) { commit(http.StatusOK); return next(body) }
	}, Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { commit(http.StatusOK); next() } }, ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
		return func(body io.Reader) (int64, error) { commit(http.StatusOK); return next(body) }
	}})
	p.pipeline.ServeHTTP(writer, r)
}
