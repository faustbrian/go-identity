package anonymoushttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	identityhttp "github.com/faustbrian/go-identity/http"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// Atomic rate backend is a deliberate transport-boundary double; actual
// PostgreSQL shared admission and domain effects belong to the native journey.
type secretBackend struct {
	ratelimit.StrictBackend
	calls int
}

func (*secretBackend) Name() string { return "guest-secret-test" }
func (b *secretBackend) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded shared admission")
	}
	b.calls++
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, item := range r.Requests {
		out.Decisions[i] = ratelimit.Decision{Allowed: true, Remaining: item.Policy.Limit() - item.Cost, Limit: item.Policy.Limit(), Reset: item.Now.Add(item.Policy.Period()), Reason: ratelimit.ReasonAllowed}
	}
	return out, nil
}

type deletionOwner struct {
	anonymous.Deleter
	reads, calls int
	request      anonymous.DeletionRequest
	result       anonymous.DeletionResult
	err          error
}

func (s *deletionOwner) DeletionRateSource(ctx context.Context, r anonymous.DeletionRequest) (identity.UserID, error) {
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		panic("unbounded/invalid guest possession")
	}
	s.reads++
	return "guest-user", nil
}
func (s *deletionOwner) Delete(ctx context.Context, r anonymous.DeletionRequest) (anonymous.DeletionResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded deletion")
	}
	s.calls++
	s.request = r
	return s.result, s.err
}

func deletionFixture(t *testing.T) (anonymoushttp.DeletionConfig, *deletionOwner, *secretBackend, func() *http.Request) {
	t.Helper()
	base, _, request := signinFixture(t)
	backend := &secretBackend{}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "guest-secret", Key: [32]byte{1}, Now: base.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	owner := &deletionOwner{result: anonymous.DeletionResult{Outcome: identity.CommitOutcomeCommitted, Recovery: identity.RecoveryQuery{CommandID: id, TenantID: "tenant-a", UserID: "guest-user", ActorID: "guest-user", ActorKind: authorization.SubjectUser, OperationID: "identity.anonymous.delete", RecordID: "guest-user"}}}
	c := anonymoushttp.DeletionConfig{Network: base.Network, Service: owner, Rate: rate, Cookie: base.SessionCookie, Origin: base.Origin, Device: base.Device, Now: base.Now, MaximumDuration: base.MaximumDuration}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := csrf.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return c, owner, backend, func() *http.Request {
		r := replaceBody(request(), `{"expectedVersion":1,"reason":"self-request"}`)
		r.URL.Path = "/v1/anonymous/delete"
		r.RequestURI = r.URL.RequestURI()
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, cookie := range cookies {
			if cookie.Name == "__Host-identity_flow" {
				cookie.Name = "__Host-identity_guest"
			}
			r.AddCookie(cookie)
		}
		r.Header.Set("X-CSRF-Token", wire)
		return r
	}
}

func TestDeletionRequiresOriginalGuestKeyCSRFAndClosedIntent(t *testing.T) {
	for _, mode := range []string{"valid", "replay", "unknown", "missing-key", "duplicate-key", "missing-csrf", "duplicate-csrf", "body-csrf", "selected-user", "zero-version", "oversize-reason", "wrong-origin", "missing-guest", "duplicate-guest", "authorization"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, rate, request := deletionFixture(t)
			r := request()
			want := 400
			switch mode {
			case "valid":
				want = 200
			case "replay":
				owner.result.Replayed = true
				want = 200
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
				owner.err = identity.UnknownCommitError{CommandID: owner.result.Recovery.CommandID}
				want = 503
			case "missing-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "original-guest-attempt")
			case "missing-csrf":
				r.Header.Del("X-CSRF-Token")
				want = 403
			case "duplicate-csrf":
				r.Header.Add("X-CSRF-Token", r.Header.Get("X-CSRF-Token"))
				// The shared envelope rejects duplicate sensitive headers as
				// malformed before origin/token admission; no owner is reached.
			case "body-csrf":
				r = replaceBody(r, `{"expectedVersion":1,"reason":"self-request","csrf_token":"forbidden"}`)
			case "selected-user":
				r = replaceBody(r, `{"expectedVersion":1,"reason":"self-request","userID":"selected"}`)
			case "zero-version":
				r = replaceBody(r, `{"expectedVersion":0,"reason":"self-request"}`)
			case "oversize-reason":
				r = replaceBody(r, `{"expectedVersion":1,"reason":"`+strings.Repeat("x", 65)+`"}`)
			case "wrong-origin":
				r.Header.Set("Origin", "https://other.example")
				want = 403
			case "missing-guest":
				r.Header.Set("Cookie", r.Cookies()[1].String())
			case "duplicate-guest":
				r.AddCookie(r.Cookies()[0])
			case "authorization":
				r.Header.Set("Authorization", "Bearer forbidden")
			}
			h, err := anonymoushttp.NewDeletionHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("wrong deletion response: status=%d", w.Code)
			}
			if mode == "valid" || mode == "replay" || mode == "unknown" {
				var out anonymoushttp.DeletionResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Recovery == nil || out.CommandID != owner.result.Recovery.CommandID || out.Deleted != (want == 200) || owner.reads != 1 || owner.calls != 1 || rate.calls != 1 || owner.request.IdempotencyKey == (identity.IdempotencyKey{}) {
					t.Fatal("deletion lost original custody/outcome or repeated work")
				}
				if want == 200 {
					cookies := w.Result().Cookies()
					if len(cookies) != 1 || cookies[0].Name != "__Host-identity_guest" || cookies[0].MaxAge >= 0 || cookies[0].Value != "" {
						t.Fatal("confirmed self-deletion did not clear only the guest cookie")
					}
				} else if w.Header().Get("Set-Cookie") != "" {
					t.Fatal("unknown deletion cleared original possession")
				}
			} else if owner.calls != 0 || owner.reads != 0 || rate.calls != 0 || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("invalid deletion entered native work or cleared custody")
			}
		})
	}
}

func TestDeletionBindsActualMiddlewareBeforeNativePossession(t *testing.T) {
	c, owner, rate, request := deletionFixture(t)
	h, err := anonymoushttp.NewDeletionHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/anonymous", Middleware: identityhttp.Middleware{Name: "deny-before-possession", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(418) })
	}}}})
	if err != nil {
		t.Fatal("deletion has no real middleware binding", err)
	}
	w := httptest.NewRecorder()
	bound.ServeHTTP(w, request())
	if w.Code != 418 || owner.calls != 0 || owner.reads != 0 || rate.calls != 0 {
		t.Fatal("middleware did not enclose real deletion admission")
	}
}
