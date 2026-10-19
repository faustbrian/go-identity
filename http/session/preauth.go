package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// PreAuthService is the borrowed original-flow owner seam. The selected
// reference PreAuthService satisfies it without importing reference or stores.
// Implementations must retain native startup/tenant/shutdown admission, own
// entropy and authoritative execution, and honor bounded contexts. Issue runs
// one unchanged preparation; unknown outcomes never authorize another Prepare.
type PreAuthService interface {
	Prepare(context.Context, session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error)
	Issue(context.Context, session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error)
}

// PreAuthIdentifierBinder binds an explicitly selected original target before
// preparation. The borrowed concurrency-safe owner canonicalizes the bounded
// raw identifier under its fixed policy and deployment key; it must not look up
// accounts, authenticate, mutate state, or accept a client-supplied digest.
// Calls occur after shared IP admission, outside database work, with a bounded
// context. Return InvalidInputError for invalid input; other errors or a zero
// binding fail unavailable. Do not log or retain raw identifiers. The reference
// composition supplies the concrete phone binder; base HTTP imports no workflow.
type PreAuthIdentifierBinder interface {
	BindPreAuthIdentifier(context.Context, identity.TenantID, string) ([32]byte, error)
}

// PreAuthConfig freezes one explicit browser initiation profile. Network is
// copied; Service and Rate are borrowed concurrency-safe owners. Share Rate
// across requests. Origin, Action, callback and policy are deployment choices,
// never client input; they must match the selected issuer exactly. Empty callback
// disables redirects. Cookie must be __Host-identity_flow with Lax/Strict policy.
// Lifetime resolves remember once for the eventual session, not the fixed
// five-minute flow. Now is a prompt trusted concurrency-safe clock;
// MaximumDuration is 1ms..30s and never extends an inbound deadline.
type PreAuthConfig struct {
	Network                       identityhttp.NetworkConfig
	Service                       PreAuthService
	Rate                          *identityhttp.AuthRateLimiter
	Cookie                        session.CookiePolicy
	Lifetime                      session.LifetimeConfig
	Origin                        identityhttp.Origin
	Action, CallbackURL, PolicyID string
	PolicyVersion                 uint64
	Now                           func() time.Time
	MaximumDuration               time.Duration
	// IdentifierBinder optionally requires a target for the base profile.
	// Omission preserves the closed remember-only legacy request contract.
	IdentifierBinder PreAuthIdentifierBinder
	// Methods optionally enables exact named login-method selection. Omission
	// keeps the original profile and closed remember-only request contract.
	// Profiles share Network, Origin, Rate, Cookie, Lifetime and device custody;
	// each borrowed owner must enforce its own fixed original intent. The slice
	// is copied at construction. No method, action or policy is auto-registered.
	Methods []PreAuthMethod
}

// PreAuthMethod binds a public selection name to one trusted original-flow
// owner. Name is 1..32 lowercase ASCII letters, digits or hyphens. Service is
// borrowed, bounded and concurrency-safe. Action, callback and policy are
// fixed deployment values, never request overrides. One to sixteen distinct
// names may be selected; omitted method retains PreAuthConfig's base profile.
type PreAuthMethod struct {
	Name                          string
	Service                       PreAuthService
	Action, CallbackURL, PolicyID string
	PolicyVersion                 uint64
	// IdentifierBinder requires identifier only when this exact method is
	// selected. Phone/password initiation requires this owner; other methods
	// retain their explicitly unbound compatibility profile when it is nil.
	IdentifierBinder PreAuthIdentifierBinder
}

// Format hides borrowed service and trusted deployment bindings.
func (PreAuthMethod) Format(s fmt.State, _ rune) {
	io.WriteString(s, "sessionhttp.PreAuthMethod(redacted)")
}

// MarshalJSON rejects implicit deployment custody export.
func (PreAuthMethod) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit deployment custody export.
func (PreAuthMethod) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format prevents traversal of borrowed service and deployment configuration.
func (PreAuthConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "sessionhttp.PreAuthConfig(redacted)")
}

// MarshalJSON rejects implicit runtime composition export.
func (PreAuthConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit deployment configuration export.
func (PreAuthConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// PreAuthResponse exposes only the original credential-free command/flow
// locator and timeline. It is neither a user session nor active authority.
// CommitOutcome none means no authoritative observation, not rollback. A known
// commitment can survive failed delivery. Retain the original locator for native
// outcome-only recovery; it grants no lookup permission and never renews a flow.
// Issued is true only when this response delivers the original secure cookie.
type PreAuthResponse struct {
	Issued        bool                          `json:"issued"`
	CommandID     identity.CommandID            `json:"commandID,omitempty"`
	FlowID        identity.PreAuthTransactionID `json:"flowID,omitempty"`
	IssuedAt      time.Time                     `json:"issuedAt"`
	ExpiresAt     time.Time                     `json:"expiresAt"`
	CommitOutcome string                        `json:"commitOutcome"`
	Error         string                        `json:"error,omitempty"`
}

type preAuthAttempt struct {
	out          PreAuthResponse
	attempted    bool
	cookie       string
	deviceCookie string
	ctx          context.Context
}
type preAuthAttemptKey struct{}

// PreAuthState is opaque request-local public-flow state. It authenticates no
// user and cannot expose prepared nonce, digest or bearer to middleware.
// Do not retain it beyond the request. Zero has no attempted issuance.
type PreAuthState struct {
	facts    identityhttp.NetworkFacts
	remember session.RememberPolicy
	attempt  *preAuthAttempt
	device   session.BrowserDevice
	profile  PreAuthMethod
	// Closure custody prevents enclosing diagnostic wrappers from traversing
	// the raw target while transport middleware observes the opaque state.
	identifier func() string
}

// Attempt returns detached safe metadata. True means Handle entered, not that
// native execution committed or a cookie reached the browser.
func (s PreAuthState) Attempt() (PreAuthResponse, bool) {
	if s.attempt == nil {
		return PreAuthResponse{CommitOutcome: "none"}, false
	}
	return s.attempt.out, s.attempt.attempted
}

// Format prevents traversal of private request-local custody.
func (PreAuthState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "sessionhttp.PreAuthState(redacted)")
}

// MarshalJSON rejects implicit request-local export.
func (PreAuthState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit request-local text export.
func (PreAuthState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewPreAuthHandler constructs only POST /v1/session/preauth-issue, with no
// registration or IO. Without Methods or IdentifierBinder, strict JSON accepts
// only optional boolean remember;
// absence selects configured default and null is invalid. Query, trailers,
// Idempotency-Key and Authorization are forbidden. Ambient cookies confer no
// authority and are ignored: a deliberate fresh start creates an independent
// flow. Exact HTTPS tenant host and configured Origin precede IP-only rate.auth,
// command generation, Prepare and Issue. There is no automatic retry.
// Only a fresh exact error-free native commitment emits its secure flow cookie;
// replay, outage, cancellation, mismatched state and ambiguity emit none.
// Responses are no-store/nosniff JSON: 200 issued, 400 malformed, 403 origin,
// 404 path, 405 method, 421 host, 429 rate, 409 conflict/in-progress, 503 unavailable.
// Native recovery stays outcome-only. Handler alone does not advertise a feature,
// satisfy browser/reference journeys or establish full release qualification.
// Explicit Methods additionally accepts an optional exact string method. It
// selects a frozen deployment profile; omission retains the base profile.
// Unknown names or malformed selection deny before rate debit or owner work.
// Explicit IdentifierBinder profiles additionally require bounded identifier;
// unbound profiles forbid it. Binding runs after IP admission before Prepare.
func NewPreAuthHandler(c PreAuthConfig) (http.Handler, error) {
	return NewPreAuthHandlerWithMiddleware(c, nil)
}

// NewPreAuthHandlerWithMiddleware retains the same security contract with
// real typed pipeline phases. Authenticate is explicitly public/no-user; Admit
// owns the original-flow rate debit, and Handle owns the single issuance attempt.
// Hooks cannot manufacture cookie output or inspect the preparation. Detached
// request headers remain potentially sensitive and must not be logged/retained.
func NewPreAuthHandlerWithMiddleware(c PreAuthConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newPreAuthHandler(c, middleware, nil)
}

// NewPreAuthHandlerWithBrowserDevice explicitly selects a server-random,
// non-authenticating browser correlation cookie alongside original flow
// issuance. Absent custody is issued only after IP admission; valid custody
// keeps its original expiry and is never redelivered. Malformed, duplicated,
// expired or tenant/origin-mismatched custody denies before owner preparation.
// Both new cookies are withheld on failure, replay, ambiguity or cancellation.
// Device configuration is validated and copied without IO. Clearing or copying
// the cookie can evade/share correlation; independent IP/identifier controls
// remain necessary. Existing flow-only constructors are unchanged.
func NewPreAuthHandlerWithBrowserDevice(c PreAuthConfig, devices session.BrowserDeviceConfig) (http.Handler, error) {
	return NewPreAuthHandlerWithBrowserDeviceAndMiddleware(c, devices, nil)
}

// NewPreAuthHandlerWithBrowserDeviceAndMiddleware retains real typed phases and
// protected dual-cookie ownership. Hooks cannot inspect or forge device custody.
func NewPreAuthHandlerWithBrowserDeviceAndMiddleware(c PreAuthConfig, devices session.BrowserDeviceConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	codec, err := session.NewBrowserDeviceCodec(devices)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	return newPreAuthHandler(c, middleware, codec)
}

func newPreAuthHandler(c PreAuthConfig, middleware []identityhttp.MiddlewareDescriptor, devices *session.BrowserDeviceCodec) (http.Handler, error) {
	if preAuthNil(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil || cookie.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie.MaxAge = 0
	cookie.Expires = time.Time{}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := PreAuthMethod{Service: c.Service, Action: c.Action, CallbackURL: c.CallbackURL, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, IdentifierBinder: c.IdentifierBinder}
	validProfile := func(p PreAuthMethod) bool {
		if p.IdentifierBinder != nil && preAuthNil(p.IdentifierBinder) || p.Action == "identity.phone.password-signin" && preAuthNil(p.IdentifierBinder) {
			return false
		}
		_, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Intent: session.PreAuthIntent{TenantID: "configuration", Action: p.Action, Origin: string(c.Origin), CallbackURL: p.CallbackURL, PolicyID: p.PolicyID, PolicyVersion: p.PolicyVersion, Nonce: [32]byte{1}, Remember: remember}, IssuedAt: stamp, ExpiresAt: stamp.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Version: 1})
		return err == nil && !preAuthNil(p.Service) && (p.CallbackURL == "" || strings.HasPrefix(p.CallbackURL, "https://"))
	}
	if !validProfile(base) || len(c.Methods) > 16 {
		return nil, identityhttp.ErrInvalidInput
	}
	profiles := make(map[string]PreAuthMethod, len(c.Methods))
	for _, p := range c.Methods {
		if len(p.Name) < 1 || len(p.Name) > 32 || !validProfile(p) {
			return nil, identityhttp.ErrInvalidInput
		}
		for _, ch := range p.Name {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return nil, identityhttp.ErrInvalidInput
			}
		}
		if _, exists := profiles[p.Name]; exists {
			return nil, identityhttp.ErrInvalidInput
		}
		profiles[p.Name] = p
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := &preAuthAttempt{out: PreAuthResponse{CommitOutcome: "none"}}
		if r != nil {
			if owned, ok := r.Context().Value(preAuthAttemptKey{}).(*preAuthAttempt); ok {
				a = owned
			}
		}
		a.cookie = ""
		a.deviceCookie = ""
		a.out.Issued = false
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
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(failure.retry, time.Hour)+time.Second-1)/time.Second), 10))
		}
		sendPreAuth(w, a, failure.status, failure.code)
	}
	handler, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[PreAuthState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (PreAuthState, error) {
			s := PreAuthState{attempt: r.Context().Value(preAuthAttemptKey{}).(*preAuthAttempt), profile: base}
			if r.URL.Path != "/v1/session/preauth-issue" || r.URL.EscapedPath() != "/v1/session/preauth-issue" {
				return s, getFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, getFailure{status: 405, code: "method_not_allowed", allow: http.MethodPost}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return s, getFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return s, getFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := origin.Check(r); err != nil {
				return s, getFailure{status: 403, code: "origin_denied"}
			}
			input, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				if r.Context().Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return s, identityhttp.ErrUnavailable
				}
				return s, identityhttp.ErrInvalidInput
			}
			choice := session.RememberDefault
			// Select the fixed profile before interpreting dependent fields;
			// JSON member/map iteration order cannot change target admission.
			if raw, present := input["method"]; present {
				var method string
				if len(profiles) == 0 || json.Unmarshal(raw, &method) != nil {
					return s, identityhttp.ErrInvalidInput
				}
				profile, ok := profiles[method]
				if !ok {
					return s, identityhttp.ErrInvalidInput
				}
				s.profile = profile
			}
			for name, raw := range input {
				if name == "method" {
					continue
				}
				if name == "identifier" {
					var identifier string
					if preAuthNil(s.profile.IdentifierBinder) || json.Unmarshal(raw, &identifier) != nil || len(identifier) == 0 || len(identifier) > 1024 {
						return s, identityhttp.ErrInvalidInput
					}
					s.identifier = func() string { return identifier }
					continue
				}
				if name != "remember" {
					return s, identityhttp.ErrInvalidInput
				}
				switch string(raw) {
				case "true":
					choice = session.PersistentSession
				case "false":
					choice = session.BrowserSession
				default:
					return s, identityhttp.ErrInvalidInput
				}
			}
			if !preAuthNil(s.profile.IdentifierBinder) && s.identifier == nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.remember, err = session.ResolveRememberPolicy(choice, c.Lifetime)
			s.facts = facts
			if err == nil && devices != nil {
				bearer, found, e := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderOptional)
				if e != nil {
					return s, identityhttp.ErrInvalidInput
				}
				if found {
					s.device, e = devices.Resolve(r.Context(), c.Now(), facts.TenantID(), string(c.Origin), bearer.Token())
					if e != nil {
						return s, identityhttp.ErrInvalidInput
					}
				}
			}
			return s, err
		},
		Authenticate: func(_ *http.Request, s PreAuthState) (PreAuthState, error) { return s, nil },
		Admit: func(r *http.Request, s PreAuthState) error {
			out, err := c.Rate.AdmitOriginalFlow(r.Context(), s.facts)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return getFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s PreAuthState) {
			a := s.attempt
			profile := s.profile
			a.attempted = true
			a.ctx = r.Context()
			var identifierBinding [32]byte
			if !preAuthNil(profile.IdentifierBinder) {
				var err error
				identifierBinding, err = profile.IdentifierBinder.BindPreAuthIdentifier(r.Context(), s.facts.TenantID(), s.identifier())
				if err != nil || identifierBinding == ([32]byte{}) || r.Context().Err() != nil {
					var invalid identity.InvalidInputError
					if errors.As(err, &invalid) && r.Context().Err() == nil {
						reject(w, r, identityhttp.ErrInvalidInput)
					} else {
						reject(w, r, identityhttp.ErrUnavailable)
					}
					return
				}
			}
			if devices != nil {
				if s.device.DeviceID() == "" {
					device, err := devices.Issue(r.Context(), c.Now(), s.facts.TenantID(), string(c.Origin))
					if err != nil {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
					a.deviceCookie = device.CookieHeader()
				} else if !c.Now().Before(s.device.ExpiresAt()) {
					reject(w, r, identityhttp.ErrInvalidInput)
					return
				}
			}
			id, err := identity.NewCommandID()
			if err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommandID = id
			p, err := profile.Service.Prepare(r.Context(), session.PreAuthPrepareInput{CommandID: id, TenantID: s.facts.TenantID(), CorrelationID: string(id), Remember: s.remember, IdentifierBinding: identifierBinding})
			if err != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			command, ok := p.Command()
			spec, e := command.Record.Bindings()
			i := spec.Binding.Intent
			if !ok || e != nil || command.CommandID != id || command.CorrelationID != string(id) || i.TenantID != s.facts.TenantID() || i.Action != profile.Action || i.Origin != string(c.Origin) || i.CallbackURL != profile.CallbackURL || i.PolicyID != profile.PolicyID || i.PolicyVersion != profile.PolicyVersion || i.Remember != s.remember || i.IdentifierBinding != identifierBinding || spec.Version != 1 || spec.Binding.ExpiresAt.Sub(spec.Binding.IssuedAt) != 5*time.Minute || command.Record.Check(c.Now(), spec.Binding, spec.Cookie) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.FlowID = spec.Binding.ID
			a.out.IssuedAt = spec.Binding.IssuedAt
			a.out.ExpiresAt = spec.Binding.ExpiresAt
			a.out.CommitOutcome = "unknown"
			out, err := profile.Service.Issue(r.Context(), p)
			if out.CommandID == id {
				a.out.CommitOutcome = logoutOutcome(out.CommitOutcome)
			}
			if err != nil || out.CommandID != id || r.Context().Err() != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
				if out.CommandID == id && out.CommitOutcome == identity.CommitOutcomeConflict {
					reject(w, r, getFailure{status: 409, code: "conflict"})
				} else if out.CommandID == id && out.CommitOutcome == identity.CommitOutcomeInProgress {
					reject(w, r, getFailure{status: 409, code: "in_progress", retry: out.RetryAfter})
				} else {
					reject(w, r, identityhttp.ErrUnavailable)
				}
				return
			}
			observed, e := out.Flow.Bindings()
			now := c.Now()
			remaining := spec.Binding.ExpiresAt.Sub(now) / time.Second
			actual := out.Cookie
			// Compare attributes before String: net/http silently drops invalid
			// domains and unsupported attribute values rather than rejecting.
			if e != nil || observed != spec || command.Record.Check(now, spec.Binding, spec.Cookie) != nil || remaining < 1 || actual.Value != "" || actual.MaxAge < 1 || actual.MaxAge > 300 || actual.Expires.IsZero() || actual.Expires.After(spec.Binding.ExpiresAt) || !actual.Expires.After(now) || actual.Raw != "" || actual.RawExpires != "" || len(actual.Unparsed) != 0 || actual.Name != cookie.Name || actual.Domain != cookie.Domain || actual.Path != cookie.Path || actual.Secure != cookie.Secure || actual.HttpOnly != cookie.HttpOnly || actual.SameSite != cookie.SameSite || actual.Partitioned || actual.Quoted {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out.Cookie.MaxAge = int(min(int64(out.Cookie.MaxAge), int64(remaining)))
			wire, err := out.Token.Reveal()
			if err != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if _, err = session.ParseToken(wire); err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out.Cookie.Value = wire
			a.cookie = out.Cookie.String()
			a.out.Issued = true
			sendPreAuth(w, a, 200, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: handler, serve: func(h http.Handler, w http.ResponseWriter, r *http.Request) {
		a := &preAuthAttempt{out: PreAuthResponse{CommitOutcome: "none"}}
		if r != nil {
			r = r.WithContext(context.WithValue(r.Context(), preAuthAttemptKey{}, a))
		}
		serveSessionCookies(h, w, r, func() []string {
			if a.ctx != nil && a.ctx.Err() != nil {
				return nil
			}
			if !a.out.Issued {
				return nil
			}
			return []string{a.cookie, a.deviceCookie}
		})
	}}, nil
}

func sendPreAuth(w http.ResponseWriter, a *preAuthAttempt, status int, code string) {
	a.out.Error = code
	body, err := json.Marshal(a.out)
	if err != nil {
		a.cookie = ""
		a.deviceCookie = ""
		response(w, 503, `{"error":"unavailable"}`)
		return
	}
	response(w, status, string(body))
}

// Reflection here only rejects typed-nil borrowed owners; it never selects or
// wires implementations, invokes methods or discovers domain behavior.
func preAuthNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
