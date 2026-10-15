package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// SignOutConfig selects the same immutable transport/network/rate profile as
// GetConfig. Exactly the selected CookieSignOut or BearerSignOut is required;
// compose it with the same primary SessionService and cookie policy. Cookie
// mode requires 1..128 exact trusted HTTPS origins and denies Referer fallback.
// Bearer mode rejects TrustedOrigins rather than silently using cookie policy.
// Services are borrowed, concurrency-safe and must outlive requests; no IO or
// resource ownership is transferred at construction.
type SignOutConfig struct {
	GetConfig
	CookieSignOut  *session.CookieSignOutService
	BearerSignOut  *session.SignOutService
	TrustedOrigins []identityhttp.Origin
}

// SignOutRecovery is the original durable command's exact scope locator, not
// authorization or renewed authentication. Query the owned recovery service
// under current result-access policy before retrying an ambiguous operation.
// These fields never contain credentials, digests, proof or CSRF material.
type SignOutRecovery struct {
	CommandID       identity.CommandID        `json:"commandID"`
	TenantID        identity.TenantID         `json:"tenantID"`
	UserID          identity.UserID           `json:"userID,omitempty"`
	AnonymousFlowID string                    `json:"anonymousFlowID,omitempty"`
	ActorID         identity.ActorID          `json:"actorID"`
	ActorKind       authorization.SubjectKind `json:"actorKind"`
	OperationID     string                    `json:"operationID"`
	RecordID        string                    `json:"recordID,omitempty"`
	LinkMode        identity.AccountLinkMode  `json:"linkMode,omitempty"`
}

// SignOutResponse is the explicit credential-free success/error projection.
// CommitOutcome is none, not_committed, committed, unknown, conflict or
// in_progress. none means no authoritative command observation, not rollback.
// A committed observation accompanied by an error does not clear transport.
// ClearBearer instructs the caller to discard only its presented bearer after
// success; cookie removal is conveyed only by the exact Set-Cookie tuple.
// CommandID is generated once per admitted call and never replaced or retried.
type SignOutResponse struct {
	SignedOut     bool               `json:"signedOut"`
	ClearBearer   bool               `json:"clearBearer"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	Recovery      *SignOutRecovery   `json:"recovery,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// NewSignOutHandler constructs only POST /v1/session/signout. Bodies are strict
// JSON {} or URL-encoded empty fields/one csrf_token; JSON CSRF uses exactly one
// X-CSRF-Token header. Query parameters and Idempotency-Key are forbidden. Token
// absence reaches the domain owner: absent/inactive logout succeeds, but active
// cookie logout requires exact primary transaction-bound CSRF. Present empty,
// duplicate, malformed or mixed channels always deny. Bearer rejects CSRF input
// and ignores ambient cookies, never falling back or deleting their transport.
// Exact HTTPS host determines tenant. rate.safe admission precedes mutation;
// subject discovery is a primary read, not preauthentication database limiting.
// Only committed error-free or absent/inactive success clears transport. Errors
// preserve original command/outcome/recovery without automatic retries. Status
// codes are 200 success, 400 malformed, 403 denial, 404 path, 405 method, 421 host,
// 429 rate, 409 conflict/in-progress and 503 unavailable/ambiguous/canceled.
// Responses are no-store/nosniff JSON. Whole-request deadlines never extend the
// inbound deadline. No goroutines, stores, transactions or journals are added;
// the server retains bounded body/read/write cleanup. This is not full feature,
// OpenAPI, native HTTP/browser or release qualification.
func NewSignOutHandler(c SignOutConfig) (http.Handler, error) {
	return NewSignOutHandlerWithMiddleware(c, nil)
}

type signOutAttempt struct {
	out       SignOutResponse
	attempted bool
	cookie    string
}
type signOutAttemptKey struct{}

// SignOutState is opaque request-local owner state. Principal describes the
// original preliminary subject read, not reusable authorization. The protected
// signout service still revalidates primary authority and atomically checks CSRF.
// The owner alone updates attempted result state; no hook can change it. Zero is
// unauthenticated and unattempted. State must not be retained beyond a request.
type SignOutState struct {
	read    GetState
	csrf    session.CSRFToken
	attempt *signOutAttempt
}

// Principal returns detached metadata from the preliminary session owner read.
// It is neither fresh-login evidence nor authority for a future operation.
func (s SignOutState) Principal() (Principal, bool) { return s.read.Principal() }

// Attempt returns a detached copy of the original operation's response state.
// The boolean means Handle entered, not that a transaction committed. Before
// Handle it is false; a true result may have outcome none/unknown or an error.
// After-handler observes normally returned attempts; cancellation/panic can
// suppress that phase. Recovery is a locator, never a retry or access grant.
func (s SignOutState) Attempt() (SignOutResponse, bool) {
	if s.attempt == nil {
		return SignOutResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Recovery != nil {
		recovery := *out.Recovery
		out.Recovery = &recovery
	}
	return out, s.attempt.attempted
}

// Format redacts private credential, CSRF and historical owner custody.
func (SignOutState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "sessionhttp.SignOutState(redacted)")
}

// MarshalJSON rejects implicit export of request-local owner custody.
func (SignOutState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text/map-key export of request-local state.
func (SignOutState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSignOutHandlerWithMiddleware preserves NewSignOutHandler's security and
// recovery contract with real typed hook phases. Decode owns original network,
// origin, body and credential acquisition; Authenticate performs preliminary
// subject discovery once; Admit debits safe-route limits once; Handle delegates
// primary revalidation and transactional CSRF/mutation to the same domain owner.
// Original preliminary validity is checked after hooks, never renewed by them.
// After-handler observes the actual attempted outcome, not assumed success.
// Trusted hooks retain original credential-bearing detached headers: do not
// log, serialize or retain them. Typed state is opaque/redacted; its getters
// expose only credential-free detached metadata. Hooks own bounded JSON denial
// bodies; no hook can clear cookies without confirmed owner success. Shared
// response policy preserves no-store/nosniff/JSON even on short circuits.
func NewSignOutHandlerWithMiddleware(c SignOutConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if _, err := NewGetHandler(c.GetConfig); err != nil {
		return nil, err
	}
	if c.Transport == session.CredentialCookie {
		if !c.CookieSignOut.Configured() || c.BearerSignOut != nil {
			return nil, identityhttp.ErrInvalidInput
		}
	} else if !c.BearerSignOut.Configured() || c.CookieSignOut != nil || len(c.TrustedOrigins) != 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	network, _ := identityhttp.NewNetworkResolver(c.Network)
	decoder, _ := identityhttp.NewRequestDecoder(c.Network.Limits)
	cookie, _ := c.Cookie.DeletionAttributes()
	var origins *identityhttp.OriginGuard
	if c.Transport == session.CredentialCookie {
		var err error
		origins, err = identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
		if err != nil {
			return nil, err
		}
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		attempt := &signOutAttempt{out: SignOutResponse{CommitOutcome: "none"}}
		if r != nil {
			if owned, ok := r.Context().Value(signOutAttemptKey{}).(*signOutAttempt); ok {
				attempt = owned
			}
		}
		attempt.cookie = ""
		attempt.out.SignedOut, attempt.out.ClearBearer = false, false
		failure := getFailure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			failure = getFailure{status: 400, code: "invalid_request"}
		}
		var specific getFailure
		if errors.As(err, &specific) {
			failure = specific
		}
		if failure.allow != "" {
			w.Header().Set("Allow", failure.allow)
		}
		if failure.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((failure.retry+time.Second-1)/time.Second), 10))
		}
		sendSignOut(w, attempt, failure.status, failure.code)
	}
	handler, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SignOutState]{
		MaximumDuration: c.MaximumDuration,
		Middleware:      middleware,
		Reject:          reject,
		Decode: func(r *http.Request) (SignOutState, error) {
			state := SignOutState{attempt: r.Context().Value(signOutAttemptKey{}).(*signOutAttempt)}
			if r.URL.Path != "/v1/session/signout" || r.URL.EscapedPath() != "/v1/session/signout" {
				return state, getFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return state, getFailure{status: 405, code: "method_not_allowed", allow: http.MethodPost}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return state, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				var invalid identityhttp.DecodeError
				if errors.As(err, &invalid) {
					return state, getFailure{status: 421, code: "misdirected_request"}
				}
				return state, identityhttp.ErrUnavailable
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return state, getFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return state, identityhttp.ErrInvalidInput
			}
			if origins != nil {
				if _, err := origins.Check(r); err != nil {
					return state, getFailure{status: 403, code: "origin_denied"}
				}
			}
			csrf, err := logoutInput(decoder, r, c.Transport)
			if err != nil {
				if r.Context().Err() != nil {
					return state, identityhttp.ErrUnavailable
				}
				return state, identityhttp.ErrInvalidInput
			}
			requirement := identityhttp.HeaderForbidden
			if c.Transport == session.CredentialBearer {
				requirement = identityhttp.HeaderOptional
			}
			bearer, present, err := decoder.Bearer(r, requirement)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			wire := ""
			if c.Transport == session.CredentialCookie {
				cookieBearer, found, cookieErr := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderOptional)
				err = cookieErr
				if found {
					wire = cookieBearer.Token()
				}
			} else if present {
				wire = bearer.Token()
			}
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			state.read.facts, state.csrf = facts, csrf
			if wire != "" {
				token, err := session.ParseToken(wire)
				if err != nil {
					return state, identityhttp.ErrInvalidInput
				}
				state.read.credential, _ = session.NewCredential(c.Transport, token)
				state.read.present = true
			}
			return state, nil
		},
		Authenticate: func(r *http.Request, state SignOutState) (SignOutState, error) {
			var err error
			state.read, err = authenticateSession(c.GetConfig, r, state.read)
			return state, err
		},
		Admit: func(r *http.Request, state SignOutState) error {
			admitted, err := c.Rate.Admit(r.Context(), state.read.facts, "identity.session.signout", state.read.principal.UserID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return getFailure{status: 429, code: "rate_limited", retry: admitted.RetryAfter}
			}
			if err != nil || !admitted.Allowed || r.Context().Err() != nil || (state.read.result.Authenticated && state.read.result.ValidateAt(c.Now()) != nil) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state SignOutState) {
			state.attempt.attempted = true
			if state.read.result.Authenticated && state.read.result.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out := &state.attempt.out
			send := func(status int, code string) { sendSignOut(w, state.attempt, status, code) }
			id, err := identity.NewCommandID()
			if err != nil {
				send(503, "unavailable")
				return
			}
			out.CommandID = id
			request := session.SignOutRequest{TenantID: state.read.facts.TenantID(), CommandID: id, CorrelationID: string(id), Transport: c.Transport, Credential: state.read.credential}
			ctx := r.Context()
			var result session.SignOutResult
			if c.Transport == session.CredentialCookie {
				result, err = c.CookieSignOut.SignOut(ctx, request, state.csrf)
			} else {
				result, err = c.BearerSignOut.SignOut(ctx, request)
			}
			out.CommitOutcome = logoutOutcome(result.CommitOutcome)
			if q := result.Recovery; q.CommandID != "" {
				out.Recovery = &SignOutRecovery{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, RecordID: q.RecordID, LinkMode: q.LinkMode}
			}
			if err != nil || ctx.Err() != nil || !result.SignedOut || result.CommandID != id {
				var forbidden identity.ForbiddenError
				switch {
				case errors.Is(err, session.ErrCSRFDenied), errors.Is(err, session.ErrUnauthenticated), errors.As(err, &forbidden):
					send(403, "denied")
				case result.CommitOutcome == identity.CommitOutcomeConflict:
					send(409, "conflict")
				case result.CommitOutcome == identity.CommitOutcomeInProgress:
					w.Header().Set("Retry-After", strconv.FormatInt(int64((result.RetryAfter+time.Second-1)/time.Second), 10))
					send(409, "in_progress")
				default:
					send(503, "unavailable")
				}
				return
			}
			if c.Transport == session.CredentialCookie {
				if !result.ClearCookie || result.ClearBearer || result.Cookie.String() != cookie.String() {
					send(503, "unavailable")
					return
				}
				state.attempt.cookie = cookie.String()
			} else {
				if !result.ClearBearer || result.ClearCookie {
					send(503, "unavailable")
					return
				}
				out.ClearBearer = true
			}
			out.SignedOut = true
			send(200, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: handler, serve: func(handler http.Handler, w http.ResponseWriter, r *http.Request) {
		attempt := &signOutAttempt{out: SignOutResponse{CommitOutcome: "none"}}
		if r != nil {
			r = r.WithContext(context.WithValue(r.Context(), signOutAttemptKey{}, attempt))
		}
		serveSessionResponse(handler, w, r, func() string { return attempt.cookie })
	}}, nil
}

func sendSignOut(w http.ResponseWriter, attempt *signOutAttempt, status int, code string) {
	attempt.out.Error = code
	body, err := json.Marshal(attempt.out)
	if err != nil {
		attempt.cookie = ""
		response(w, 503, `{"error":"unavailable"}`)
		return
	}
	response(w, status, string(body))
}

// Optional syntax is workflow-specific: absence is not CSRF admission. Only the
// domain owner can distinguish inactive success from an active protected call.
// Base codecs still own media, framing, raw/decoded bounds and duplicate fields.
func logoutInput(d *identityhttp.RequestDecoder, r *http.Request, mode session.CredentialKind) (session.CSRFToken, error) {
	wire := ""
	found := false
	for name, values := range r.Header {
		if strings.EqualFold(name, "X-CSRF-Token") {
			if found || len(values) != 1 || values[0] == "" {
				return session.CSRFToken{}, identityhttp.DecodeError{}
			}
			wire, found = values[0], true
		}
	}
	// Try the owning strict codec for the selected media, without reading the
	// body twice. Its complete Content-Type validation remains authoritative.
	jsonBody := false
	for name, values := range r.Header {
		if strings.EqualFold(name, "Content-Type") && len(values) == 1 {
			jsonBody = strings.HasPrefix(strings.ToLower(values[0]), "application/json")
		}
	}
	if jsonBody {
		if _, err := identityhttp.DecodeJSON[struct{}](d, r); err != nil {
			return session.CSRFToken{}, err
		}
	} else {
		fields, err := d.Form(r)
		if err != nil {
			return session.CSRFToken{}, err
		}
		for name, values := range fields {
			if name != "csrf_token" || found || mode != session.CredentialCookie || len(values) != 1 || values[0] == "" {
				return session.CSRFToken{}, identityhttp.DecodeError{}
			}
			wire, found = values[0], true
		}
	}
	if !found {
		return session.CSRFToken{}, nil
	}
	if mode != session.CredentialCookie {
		return session.CSRFToken{}, identityhttp.DecodeError{}
	}
	token, err := session.ParseCSRFToken(wire)
	if err != nil {
		return session.CSRFToken{}, identityhttp.DecodeError{}
	}
	return token, nil
}

func logoutOutcome(outcome identity.CommitOutcome) string {
	switch outcome {
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	default:
		return "none"
	}
}
