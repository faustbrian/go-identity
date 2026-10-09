// Package sessionhttp supplies explicitly selected session HTTP integrations.
// Base identity/http does not import this module or any optional session owner.
package sessionhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

// GetConfig explicitly selects one transport and immutable network policy.
// Sessions and Rate must be valid owner-constructed, concurrency-safe services;
// they remain borrowed and must outlive requests. Share Rate across all routes,
// never construct it per request. Cookie must be valid even in bearer mode.
// Now is a trusted prompt concurrency-safe clock. MaximumDuration is 1ms..30s;
// earlier inbound deadlines win. Construction copies network configuration.
type GetConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Rate            *identityhttp.SafeRateLimiter
	Transport       session.CredentialKind
	Cookie          session.CookiePolicy
	Now             func() time.Time
	MaximumDuration time.Duration
}

// GetResponse is the explicit credential-free read projection. It conveys no
// reusable authentication authority. Unauthenticated responses omit all subject
// and session fields. Sensitive extension/enrichment data is not implicit.
type GetResponse struct {
	Authenticated     bool       `json:"authenticated"`
	Principal         *Principal `json:"principal,omitempty"`
	Session           *Session   `json:"session,omitempty"`
	NeedsRefresh      bool       `json:"needsRefresh"`
	RefreshEligibleAt *time.Time `json:"refreshEligibleAt,omitempty"`
}

// Principal identifies only the admitted owner and exact host-mapped tenant.
// It is response metadata, not an authorization proof.
type Principal struct {
	TenantID identity.TenantID `json:"tenantID"`
	UserID   identity.UserID   `json:"userID"`
}

// Session exposes stable public read metadata, never lookup/CSRF digests,
// authority vectors, credential IDs, historical proofs or bearer material.
type Session struct {
	ID                string    `json:"id"`
	IssuedAt          time.Time `json:"issuedAt"`
	LastActivityAt    time.Time `json:"lastActivityAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	AbsoluteExpiresAt time.Time `json:"absoluteExpiresAt"`
}

// NewGetHandler constructs only GET /v1/session/get, without registration or IO.
// It validates the request envelope, exact HTTPS tenant host, non-keyed empty
// request and explicitly selected credential channel before owner access.
// Cookie mode rejects Authorization; bearer mode ignores ambient cookies and
// never falls back. All decisions use canonical rate.safe admission. Positive
// owner custody is checked again after rate work, preserving original expiry.
// Success is 200 authenticated metadata or enumeration-safe unauthenticated;
// malformed input is 400, wrong host/realm 421, wrong path 404/method 405,
// rate denial 429 with Retry-After, operational/cancellation failure 503.
// Every response is no-store, nosniff JSON and never emits Set-Cookie. No read
// updates activity, rotates credentials, refreshes authority or starts work in
// a goroutine. The server retains body/connection cleanup and bounded writes.
// This handler alone is not full feature/router/OpenAPI or browser qualification.
func NewGetHandler(c GetConfig) (http.Handler, error) {
	return NewGetHandlerWithMiddleware(c, nil)
}

// GetState is an immutable request-local session-read snapshot. Its private
// credential and owner result remain inaccessible to middleware. Zero is
// unauthenticated. Copies never renew the owner's original validity evidence.
// Obtain it only through identityhttp.PipelineValue[GetState] during a trusted
// synchronous after-auth or later hook; it is not an authorization proof.
type GetState struct {
	facts      identityhttp.NetworkFacts
	credential session.Credential
	present    bool
	result     session.GetResult
	principal  Principal
}

// Principal returns detached credential-free metadata from the actual session
// owner. The boolean is false for absent/unknown/inactive credentials. Metadata
// must not be retained or reused as authentication or authorization authority.
func (s GetState) Principal() (Principal, bool) {
	return s.principal, s.result.Authenticated
}

// Format redacts private credential, network and historical owner custody.
func (GetState) Format(s fmt.State, _ rune) { io.WriteString(s, "sessionhttp.GetState(redacted)") }

// MarshalJSON rejects implicit export of the request-local owner snapshot.
func (GetState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text/map-key export of the owner snapshot.
func (GetState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type getFailure struct {
	status int
	code   string
	allow  string
	retry  time.Duration
}

func (e getFailure) Error() string { return "sessionhttp: " + e.code }

// NewGetHandlerWithMiddleware preserves NewGetHandler's transport and security
// contract while exposing real typed execution boundaries. Decode acquires
// original network/credential input, Authenticate performs the single owner
// read, Admit applies the single safe-route admission, and Handle rechecks the
// original owner validity after before-handler hooks before serializing.
// Middleware follows identityhttp.NewOperationPipeline's trusted synchronous
// ownership rules. Its typed GetState discloses no credential material; detached
// request headers still contain original credentials and must never be logged
// or retained. Hooks have no readable body. After-handler observes attempts,
// not transaction commits.
// Read response protections also cover hook short circuits: no-store/nosniff
// JSON media type and no Set-Cookie. Hooks own their bounded JSON denial body.
// Constructor validation performs no owner reads or rate admission.
func NewGetHandlerWithMiddleware(c GetConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	decode, err := newSessionReadDecoder(c, "/v1/session/get")
	if err != nil {
		return nil, err
	}
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
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
		response(w, failure.status, `{"error":"`+failure.code+`"}`)
	}
	handler, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[GetState]{
		MaximumDuration: c.MaximumDuration,
		Middleware:      middleware,
		Reject:          reject,
		Decode:          decode,
		Authenticate: func(r *http.Request, state GetState) (GetState, error) {
			return authenticateSession(c, r, state)
		},
		Admit: func(r *http.Request, state GetState) error {
			admitted, err := c.Rate.Admit(r.Context(), state.facts, "identity.session.get", state.principal.UserID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return getFailure{status: 429, code: "rate_limited", retry: admitted.RetryAfter}
			}
			if err != nil || !admitted.Allowed || r.Context().Err() != nil || (state.result.Authenticated && state.result.ValidateAt(c.Now()) != nil) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state GetState) {
			out := GetResponse{}
			if state.result.Authenticated {
				if state.result.ValidateAt(c.Now()) != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				spec, err := state.result.Session.Bindings()
				if err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				lifetime, err := state.result.Session.Lifetime(c.Now())
				if err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				eligible := state.result.RefreshEligibleAt.UTC()
				principal := state.principal
				out = GetResponse{Authenticated: true, Principal: &principal, Session: &Session{ID: spec.SessionID, IssuedAt: spec.IssuedAt.UTC(), LastActivityAt: spec.LastActivityAt.UTC(), ExpiresAt: lifetime.ExpiresAt.UTC(), AbsoluteExpiresAt: lifetime.AbsoluteExpiresAt.UTC()}, NeedsRefresh: state.result.NeedsRefresh, RefreshEligibleAt: &eligible}
			}
			body, err := json.Marshal(out)
			if err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response(w, 200, string(body))
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: handler, serve: func(handler http.Handler, w http.ResponseWriter, r *http.Request) {
		serveSessionResponse(handler, w, r, func() string { return "" })
	}}, nil
}

// Session reads and protected metadata acquire exactly the same original
// transport custody; only the fixed endpoint path and response differ.
func newSessionReadDecoder(c GetConfig, path string) (func(*http.Request) (GetState, error), error) {
	if !c.Sessions.Configured() || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || (c.Transport != session.CredentialCookie && c.Transport != session.CredentialBearer) {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
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
	return func(r *http.Request) (GetState, error) {
		var state GetState
		if r.URL.Path != path || r.URL.EscapedPath() != path {
			return state, getFailure{status: 404, code: "not_found"}
		}
		if r.Method != http.MethodGet {
			return state, getFailure{status: 405, code: "method_not_allowed", allow: http.MethodGet}
		}
		if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.Trailer) != 0 {
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
		requirement := identityhttp.HeaderForbidden
		if c.Transport == session.CredentialBearer {
			requirement = identityhttp.HeaderOptional
		}
		bearer, present, err := decoder.Bearer(r, requirement)
		if err != nil {
			return state, identityhttp.ErrInvalidInput
		}
		wire := ""
		if c.Transport == session.CredentialBearer {
			if present {
				wire = bearer.Token()
			}
		} else {
			cookieBearer, found, cookieErr := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderOptional)
			err = cookieErr
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			if found {
				wire = cookieBearer.Token()
			}
		}
		state.facts = facts
		if wire != "" {
			token, parseErr := session.ParseToken(wire)
			if parseErr != nil {
				return state, identityhttp.ErrInvalidInput
			}
			state.credential, _ = session.NewCredential(c.Transport, token)
			state.present = true
		}
		return state, nil
	}, nil
}

func authenticateSession(c GetConfig, r *http.Request, state GetState) (GetState, error) {
	if state.present {
		var err error
		state.result, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: state.facts.TenantID(), Credential: state.credential})
		if err != nil {
			return state, identityhttp.ErrUnavailable
		}
	}
	if state.result.Authenticated {
		if state.result.ValidateAt(c.Now()) != nil {
			return state, identityhttp.ErrUnavailable
		}
		spec, err := state.result.Session.Bindings()
		if err != nil || spec.TenantID != state.facts.TenantID() {
			return state, identityhttp.ErrUnavailable
		}
		state.principal = Principal{TenantID: spec.TenantID, UserID: spec.UserID}
	}
	return state, nil
}

// allowedCookie is private request-local owner output, never a request header or
// hook-supplied value. GET supplies empty; logout permits only its owned exact
// deletion tuple after confirmed successful completion.
func serveSessionResponse(handler http.Handler, w http.ResponseWriter, r *http.Request, allowedCookie func() string) {
	protect := func() {
		// Header maps permit noncanonical keys. Remove every spelling before
		// establishing the single reviewed policy at the actual commit edge.
		for name := range w.Header() {
			if strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") || strings.EqualFold(name, "Set-Cookie") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if cookie := allowedCookie(); cookie != "" {
			w.Header().Set("Set-Cookie", cookie)
		}
	}
	protect()
	// Preserve the underlying writer's optional interfaces, including flush
	// and ReaderFrom commit paths, without transferring response ownership.
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) { protect(); next(status) }
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(body []byte) (int, error) { protect(); return next(body) }
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { protect(); next() } },
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(body io.Reader) (int64, error) { protect(); return next(body) }
		},
	})
	defer protect()
	handler.ServeHTTP(writer, r)
}

func response(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(body + "\n"))
}
