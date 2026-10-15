// Package passwordhttp provides opt-in password transport without importing
// concrete adapters into the base HTTP module.
package passwordhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	"github.com/felixge/httpsnoop"
)

// ChangeConfig freezes an explicit credential profile. Select exactly the
// matching BearerChange or CookieChange native workflow port. Sessions, Proofs
// and that workflow must share the same native authority; all are borrowed,
// concurrency-safe and must honor bounded contexts. Proofs reads the original
// completed signed verification, not a consumer-created proof or store.
// The native change workflow independently validates and consumes that proof
// with protected mutation and current session/CSRF effects in one transaction.
// Rate is shared across routes, never created per request. Cookie is mandatory
// in cookie mode; bearer mode rejects TrustedOrigins and ignores ambient cookies.
// Cookie mode requires exact origins and denies Referer fallback. PolicyRevision
// is trusted positive startup policy. Now is a prompt concurrency-safe clock;
// MaximumDuration is 1ms..30s and never extends an inbound deadline.
type ChangeConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Proofs          auth.ReauthenticationSource
	BearerChange    password.ChangeService
	CookieChange    password.CookieChangeService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Transport       session.CredentialKind
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime owners and network configuration.
func (ChangeConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.ChangeConfig(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (ChangeConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit text export.
func (ChangeConfig) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns only a fixed marker.
func (ChangeConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ChangeConfig(redacted)")
}

// ChangeResponse is credential-free command metadata. Changed and successor
// fields require an error-free known commit. A committed outcome with an error
// is still not successful HTTP delivery; none is not proof of rollback.
// Recovery is an original scope locator, never authority or automatic retry.
type ChangeResponse struct {
	Changed              bool                    `json:"changed"`
	CommandID            identity.CommandID      `json:"commandID,omitempty"`
	CommitOutcome        string                  `json:"commitOutcome"`
	CredentialVersion    uint64                  `json:"credentialVersion,omitempty"`
	AuthorityInvalidated bool                    `json:"authorityInvalidated,omitempty"`
	Recovery             *identity.RecoveryQuery `json:"recovery,omitempty"`
	Error                string                  `json:"error,omitempty"`
}

// MarshalJSON projects recovery metadata into this transport's closed wire
// contract. Kernel recovery queries remain Go lookup inputs, not wire schemas;
// unrelated anonymous/account-link fields cannot enter password responses.
func (r ChangeResponse) MarshalJSON() ([]byte, error) {
	type plain ChangeResponse
	type recovery struct {
		CommandID   identity.CommandID        `json:"commandID"`
		TenantID    identity.TenantID         `json:"tenantID"`
		UserID      identity.UserID           `json:"userID"`
		ActorID     identity.ActorID          `json:"actorID"`
		ActorKind   authorization.SubjectKind `json:"actorKind"`
		OperationID string                    `json:"operationID"`
		RecordID    string                    `json:"recordID"`
	}
	var scope *recovery
	if q := r.Recovery; q != nil {
		scope = &recovery{q.CommandID, q.TenantID, q.UserID, q.ActorID, q.ActorKind, q.OperationID, q.RecordID}
	}
	return json.Marshal(struct {
		plain
		Recovery *recovery `json:"recovery,omitempty"`
	}{plain(r), scope})
}

type changeAttempt struct {
	secret    primitive.Secret
	out       ChangeResponse
	attempted bool
}
type changeKey struct{}

// ChangeState retains private request-local original custody. It grants no
// reusable authority and must not be retained beyond the synchronous request.
type ChangeState struct {
	facts      identityhttp.NetworkFacts
	bearer     auth.BearerCredential
	credential session.Credential
	key        identity.IdempotencyKey
	csrf       session.CSRFToken
	proofID    auth.ProofID
	read       session.GetResult
	user       identity.UserID
	attempt    *changeAttempt
}

// Principal returns detached metadata from the preliminary session owner read,
// not permission to mutate or evidence of credential-specific freshness.
func (s ChangeState) Principal() (identity.TenantID, identity.UserID, bool) {
	return s.facts.TenantID(), s.user, s.user != ""
}

// Attempt returns a detached original command observation. True means the
// native change workflow was invoked, not that its transaction or HTTP delivery
// succeeded. Preliminary session or proof failures leave it false.
func (s ChangeState) Attempt() (ChangeResponse, bool) {
	if s.attempt == nil {
		return ChangeResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Recovery != nil {
		copy := *out.Recovery
		out.Recovery = &copy
	}
	return out, s.attempt.attempted
}

// Format prevents traversal of credential/proof/password custody.
func (ChangeState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.ChangeState(redacted)")
}

// MarshalJSON denies implicit request-state export.
func (ChangeState) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit text export.
func (ChangeState) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (ChangeState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ChangeState(redacted)")
}

type failure struct {
	status int
	code   string
	retry  time.Duration
}

func (f failure) Error() string { return "identity.http.password.change." + f.code }

// NewChangeHandler constructs only POST /v1/password/change without registering
// routes or metadata. Closed JSON requires proofID and newPassword. The original
// proofID comes from completed password verification; no caller-selected proof
// projection, user, tenant, revoke policy or replacement command is accepted.
// Exactly one Idempotency-Key header supplies the sole opaque request key.
// Cookie mode rejects Authorization and requires exact Origin/X-CSRF-Token;
// bearer mode requires strict Authorization and rejects CSRF alternatives.
// All error paths emit no cookies or credentials. Secrets are destroyed when
// the request ends, including short-circuit/panic paths. This handler alone is
// not full password feature/OpenAPI, composed SQL or browser qualification.
func NewChangeHandler(c ChangeConfig) (http.Handler, error) {
	return NewChangeHandlerWithMiddleware(c, nil)
}

// NewChangeHandlerWithMiddleware binds real decode, session read, atomic rate
// admission and single native mutation phases. Original validity is rechecked
// after hooks without refresh. Native workflow retains current primary proof,
// risk, authorization and CSRF responsibility; no private transaction is added.
// Hooks receive redacted typed state and detached headers that still require
// secret-safe handling. After-handler observes attempts, not presumed commits.
func NewChangeHandlerWithMiddleware(c ChangeConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || nilOwner(c.Proofs) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	if c.Transport == session.CredentialCookie {
		if nilOwner(c.CookieChange) || !nilOwner(c.BearerChange) {
			return nil, identityhttp.ErrInvalidInput
		}
	} else if c.Transport != session.CredentialBearer || nilOwner(c.BearerChange) || !nilOwner(c.CookieChange) || len(c.TrustedOrigins) != 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	var csrf *identityhttp.CSRFDecoder
	cookieName := ""
	if c.Transport == session.CredentialCookie {
		cookie, err := c.Cookie.DeletionAttributes()
		if err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		cookieName = cookie.Name
		origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
		if err != nil {
			return nil, err
		}
		csrf, err = identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origin, FormField: "csrf_token"})
		if err != nil {
			return nil, err
		}
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		f := failure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		var specific failure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		a := attemptFor(r)
		a.out.Changed = false
		a.out.CredentialVersion = 0
		a.out.AuthorityInvalidated = false
		a.out.Error = f.code
		writeResponse(w, f.status, a.out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[ChangeState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (ChangeState, error) {
			s := ChangeState{attempt: attemptFor(r)}
			if r.URL.Path != "/v1/password/change" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.key = key
			if c.Transport == session.CredentialCookie {
				if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.bearer, present, err = decoder.CookieBearer(r, cookieName, identityhttp.HeaderRequired)
				if err != nil || !present {
					return s, identityhttp.ErrInvalidInput
				}
				s.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
				if err != nil {
					return s, failure{status: 403, code: "origin_or_csrf_denied"}
				}
			} else {
				for name := range r.Header {
					if strings.EqualFold(name, "X-CSRF-Token") {
						return s, identityhttp.ErrInvalidInput
					}
				}
				s.bearer, present, err = decoder.Bearer(r, identityhttp.HeaderRequired)
				if err != nil || !present {
					return s, identityhttp.ErrInvalidInput
				}
			}
			token, err := session.ParseToken(s.bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(c.Transport, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 2 {
				return s, identityhttp.ErrInvalidInput
			}
			var id, value string
			for name, dst := range map[string]*string{"proofID": &id, "newPassword": &value} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			if !visible(id, 22, 128) || len(value) == 0 || len(value) > 1<<20 {
				return s, identityhttp.ErrInvalidInput
			}
			s.proofID = auth.ProofID(id)
			raw := []byte(value)
			secret, err := primitive.NewSecret(raw)
			clear(raw)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.attempt.secret = secret
			return s, nil
		},
		Authenticate: func(r *http.Request, s ChangeState) (ChangeState, error) {
			read, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !read.Authenticated {
				return s, failure{status: 401, code: "denied"}
			}
			if read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			b, err := read.Session.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() {
				return s, identityhttp.ErrUnavailable
			}
			s.read = read
			s.user = b.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s ChangeState) error {
			out, err := c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.password.change", UserID: s.user, IdempotencyKey: s.key})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return failure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || s.read.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s ChangeState) {
			if s.read.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if r.Context().Err() != nil || err != nil && !errors.Is(err, auth.ErrInvalidProof) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil || record.Proof.Proof.ID != s.proofID || record.Proof.Proof.Tenant != string(s.facts.TenantID()) || record.Proof.Proof.Subject != string(s.user) {
				reject(w, r, failure{status: 403, code: "denied"})
				return
			}
			if r.Context().Err() != nil || s.read.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.user)}, Tenant: authorization.TenantID(s.facts.TenantID()), Action: "identity.password.change", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.change"}}}
			request := password.ChangeRequest{TenantID: s.facts.TenantID(), Session: s.bearer, Proof: record.Proof, Password: s.attempt.secret, Caller: caller, Network: s.facts.ClientIP().String(), IdempotencyKey: s.key}
			s.attempt.attempted = true
			var result password.ChangeResult
			if c.Transport == session.CredentialCookie {
				result, err = c.CookieChange.Change(r.Context(), password.CookieChangeRequest{Request: request, CSRFToken: s.csrf})
			} else {
				result, err = c.BearerChange.Change(r.Context(), request)
			}
			if !projectResult(s, result) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil || r.Context().Err() != nil {
				f := failure{status: 503, code: "unavailable"}
				if r.Context().Err() == nil {
					var denied identity.ForbiddenError
					var conflict identity.ConflictError
					var busy identity.InProgressError
					switch {
					case errors.As(err, &denied):
						f = failure{status: 403, code: "denied"}
					case errors.As(err, &conflict):
						f = failure{status: 409, code: "conflict"}
					case errors.As(err, &busy):
						f = failure{status: 409, code: "in_progress", retry: busy.RetryAfter}
					}
				}
				reject(w, r, f)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.CredentialVersion == 0 || !result.AuthorityInvalidated {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			s.attempt.out.Changed = true
			s.attempt.out.CredentialVersion = result.CredentialVersion
			s.attempt.out.AuthorityInvalidated = true
			writeResponse(w, 200, s.attempt.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &changePipeline{pipeline: pipeline}, nil
}

func nilOwner(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func visible(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
func attemptFor(r *http.Request) *changeAttempt {
	if r != nil {
		if a, ok := r.Context().Value(changeKey{}).(*changeAttempt); ok {
			return a
		}
	}
	return &changeAttempt{out: ChangeResponse{CommitOutcome: "none"}}
}
func writeResponse(w http.ResponseWriter, status int, out ChangeResponse) {
	data, err := json.Marshal(out)
	if err != nil {
		w.WriteHeader(503)
		return
	}
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}
func projectResult(s ChangeState, r password.ChangeResult) bool {
	name := "none"
	switch r.Outcome {
	case identity.CommitOutcomeInvalid:
	case identity.CommitOutcomeNotCommitted:
		name = "not_committed"
	case identity.CommitOutcomeCommitted:
		name = "committed"
	case identity.CommitOutcomeUnknown:
		name = "unknown"
	case identity.CommitOutcomeConflict:
		name = "conflict"
	case identity.CommitOutcomeInProgress:
		name = "in_progress"
	default:
		return false
	}
	// A native prepared-key conflict precedes command creation. Never invent
	// a recovery identity for that observation; actual command outcomes need one.
	requiresCommand := r.Outcome != identity.CommitOutcomeInvalid && r.Outcome != identity.CommitOutcomeConflict
	if requiresCommand && !visible(string(r.CommandID), 1, 128) || r.CommandID != "" && !visible(string(r.CommandID), 1, 128) {
		return false
	}
	s.attempt.out.CommandID = r.CommandID
	s.attempt.out.CommitOutcome = name
	if r.CommandID != "" {
		b, err := s.read.Session.Bindings()
		if err != nil {
			return false
		}
		s.attempt.out.Recovery = &identity.RecoveryQuery{CommandID: r.CommandID, TenantID: s.facts.TenantID(), UserID: s.user, ActorID: identity.ActorID(s.user), ActorKind: authorization.SubjectUser, OperationID: "identity.password.change", RecordID: b.Authentication.CredentialID}
	}
	return true
}

type changePipeline struct{ pipeline http.Handler }

func (p *changePipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, e := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if e != nil {
		return nil, e
	}
	return &changePipeline{pipeline: h}, nil
}
func (p *changePipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &changeAttempt{out: ChangeResponse{CommitOutcome: "none"}}
	defer func() { a.secret.Destroy() }()
	r = r.WithContext(context.WithValue(r.Context(), changeKey{}, a))
	servePasswordPipeline(w, r, p.pipeline)
}

// Both password handlers enforce the same denial of cookie/CSRF/trailer output
// across owner responses and trusted middleware short circuits.
func servePasswordPipeline(w http.ResponseWriter, r *http.Request, pipeline http.Handler) {
	servePasswordPipelineWithDelivery(w, r, pipeline, func() (string, string) { return "", "" })
}

// Only the native signin result may supply fresh credentials. Once headers
// commit, their original tuple is frozen; middleware unwind cannot add or replace
// it. Other password operations retain their unconditional output denial.
func servePasswordPipelineWithDelivery(w http.ResponseWriter, r *http.Request, pipeline http.Handler, delivery func() (string, string)) {
	servePasswordPipelineWithCustody(w, r, pipeline, func() (string, string, string) { cookie, csrf := delivery(); return cookie, csrf, "" }, nil)
}

// Password credential output has one commitment owner. Challenge custody is
// disjoint from session/CSRF custody; informational output and middleware
// unwinding cannot inject or replace either frozen tuple.
func servePasswordPipelineWithCustody(w http.ResponseWriter, r *http.Request, pipeline http.Handler, delivery func() (string, string, string), beforeCommit func(int) int) {
	var committed bool
	var committing bool
	var deliveredCookie, deliveredCSRF, deliveredChallenge string
	protect := func() {
		for name := range w.Header() {
			if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		cookie, csrf := deliveredCookie, deliveredCSRF
		challenge := deliveredChallenge
		if !committed && committing {
			cookie, csrf, challenge = delivery()
		}
		if cookie != "" && csrf != "" && challenge == "" {
			w.Header().Set("Set-Cookie", cookie)
			w.Header().Set("X-CSRF-Token", csrf)
		}
		if challenge != "" && cookie == "" && csrf == "" {
			w.Header().Set("X-MFA-Token", challenge)
		}
	}
	commit := func(status int) int {
		if !committed && beforeCommit != nil {
			status = beforeCommit(status)
		}
		committing = true
		protect()
		committing = false
		if !committed {
			deliveredCookie, deliveredCSRF = w.Header().Get("Set-Cookie"), w.Header().Get("X-CSRF-Token")
			deliveredChallenge = w.Header().Get("X-MFA-Token")
			committed = true
		}
		return status
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) {
			if status >= 200 {
				status = commit(status)
			} else {
				protect()
			}
			next(status)
		}
	}, Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(b []byte) (int, error) { commit(http.StatusOK); return next(b) }
	}, Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { commit(http.StatusOK); next() } }, ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
		return func(b io.Reader) (int64, error) { commit(http.StatusOK); return next(b) }
	}})
	pipeline.ServeHTTP(writer, r)
}
