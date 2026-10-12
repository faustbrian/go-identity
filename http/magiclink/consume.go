package magiclinkhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/magiclink"
	"github.com/faustbrian/go-identity/session"
)

// ConsumeService borrows one native consuming owner and its purpose-bound
// original-source reader. Source performs no use reservation or issuance;
// Consume independently rechecks authority and owns atomic one-use/session work.
type ConsumeService interface {
	Consume(context.Context, magiclink.ConsumeRequest) (magiclink.ConsumeResult, error)
	ConsumeRateSource(context.Context, magiclink.ConsumeRequest) (identity.UserID, string, time.Duration, error)
}

// ConsumeConfig selects explicit browser consumption, never scanner GET login.
// Service, Rate and prompt Now are concurrent-safe borrowed owners that outlive
// calls. CallbackURL is the exact original allowlisted HTTPS destination, not
// a redirect. Audience and SessionCookie must match the native issuer. The
// original __Host-identity_flow and signed __Host-identity_device cookies are
// required. Device matches initialization's correlation policy, not MFA trust.
// MaximumDuration is 1ms..30s;
// inbound deadlines win. Construction performs no IO or session generation.
type ConsumeConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ConsumeService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	CallbackURL     string
	SessionCookie   session.CookiePolicy
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
	// MFAContinuation explicitly permits a native challenge-only arm. Its child
	// proof is delivered once in X-MFA-Token, never a session cookie or JSON.
	MFAContinuation bool
	// ProofLimits matches the selected native issuer's bounded parsing profile.
	// Zero preserves capability.DefaultLimits. Parsing grants no authority; the
	// native owner still verifies exact signed scope and its own retained limits.
	ProofLimits capability.Limits
}

// ConsumeResponse carries original outcome and historical session ID, never a
// proof, bearer, CSRF secret or subject. SignedIn means this invocation delivered
// new committed credentials; a known commit may remain with SignedIn false.
type ConsumeResponse struct {
	SignedIn           bool               `json:"signedIn"`
	CommitOutcome      string             `json:"commitOutcome"`
	CommandID          identity.CommandID `json:"commandID,omitempty"`
	SessionID          string             `json:"sessionID,omitempty"`
	Error              string             `json:"error,omitempty"`
	ChallengeRequired  bool               `json:"challengeRequired,omitempty"`
	ChallengeID        identity.CommandID `json:"challengeID,omitempty"`
	ChallengeMethod    string             `json:"challengeMethod,omitempty"`
	ChallengeExpiresAt string             `json:"challengeExpiresAt,omitempty"`
}
type consumeKey struct{}
type consumeAttempt struct {
	out           ConsumeResponse
	proof         capability.Proof
	cookie, csrf  string
	challenge     string
	child         capability.Proof
	ctx           context.Context
	deliveryFresh func() bool
}
type consumeState struct {
	facts   identityhttp.NetworkFacts
	request magiclink.ConsumeRequest
	token   string
	rate    identityhttp.ChallengeVerificationRateRequest
}

func consumption(r *http.Request) *consumeAttempt {
	return r.Context().Value(consumeKey{}).(*consumeAttempt)
}

// NewConsumeHandler selects POST /v1/magic-link/consume. Closed JSON requires
// original commandID, preAuthID, token and callbackURL. No Idempotency-Key,
// Authorization, query, redirect or automatic retry/recovery is supported.
// Only an exact fresh commit delivers the native bearer in its secure cookie
// and synchronizer in X-CSRF-Token; failures, replay and ambiguity emit neither.
func NewConsumeHandler(c ConsumeConfig) (http.Handler, error) {
	return NewConsumeHandlerWithMiddleware(c, nil)
}

// NewConsumeHandlerWithMiddleware binds the actual decode, IP/source, challenge
// and consuming phases. Hooks cannot replace private input or credential output.
func NewConsumeHandlerWithMiddleware(c ConsumeConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.ProofLimits == (capability.Limits{}) {
		c.ProofLimits = capability.DefaultLimits()
	}
	if _, err := capability.ParseProof("", c.ProofLimits); errors.Is(err, capability.ErrInvalidConfiguration) {
		return nil, identityhttp.ErrInvalidInput
	}
	if c.Service == nil || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || !bounded(c.Audience, 256) {
		return nil, identityhttp.ErrInvalidInput
	}
	u, e := url.Parse(c.CallbackURL)
	if e != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(c.CallbackURL, "#") || !bounded(c.CallbackURL, 2048) {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, e := c.SessionCookie.DeletionAttributes()
	if e != nil || cookie.Name == "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	network, e := identityhttp.NewNetworkResolver(c.Network)
	if e != nil {
		return nil, e
	}
	decoder, e := identityhttp.NewRequestDecoder(c.Network.Limits)
	if e != nil {
		return nil, e
	}
	devices, e := session.NewBrowserDeviceCodec(c.Device)
	if e != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	origin, e := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if e != nil {
		return nil, e
	}
	caller := func(tenant identity.TenantID, flow identity.PreAuthTransactionID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.magic-link.consume", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow)}}}
	}
	if caller("configuration", "configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, e error) {
		a := consumption(r)
		a.cookie, a.csrf = "", ""
		a.challenge = ""
		a.out.ChallengeRequired = false
		a.out.ChallengeID, a.out.ChallengeMethod, a.out.ChallengeExpiresAt = "", "", ""
		a.out.SignedIn = false
		a.out.SessionID = ""
		f := failure{status: 503, code: "unavailable"}
		if errors.Is(e, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		var specific failure
		if errors.As(e, &specific) {
			f = specific
		}
		var superseded magiclink.SupersededError
		if r.Context().Err() == nil && errors.As(e, &superseded) {
			f = failure{status: http.StatusConflict, code: "superseded"}
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		a.out.Error = f.code
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(a.out)
	}
	p, e := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[consumeState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (consumeState, error) {
			var s consumeState
			if r.URL.Path != "/v1/magic-link/consume" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, e := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			facts, e := network.Resolve(r)
			if e != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, failure{status: 403, code: "https_required"}
			}
			if _, e = origin.Check(r); e != nil {
				return s, failure{status: 403, code: "origin_denied"}
			}
			cookie, present, e := decoder.CookieBearer(r, "__Host-identity_flow", identityhttp.HeaderRequired)
			if e != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			deviceCookie, devicePresent, e := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if e != nil || !devicePresent {
				return s, identityhttp.ErrInvalidInput
			}
			device, e := devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), deviceCookie.Token())
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, e := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if e != nil || len(body) != 4 {
				return s, identityhttp.ErrInvalidInput
			}
			var command, flow, callback, token string
			for name, dst := range map[string]*string{"commandID": &command, "preAuthID": &flow, "callbackURL": &callback, "token": &token} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			id, e := identity.ParseCommandID(command)
			if e != nil || callback != c.CallbackURL || !bounded(token, 4096) {
				return s, identityhttp.ErrInvalidInput
			}
			preAuth, e := identity.ParsePreAuthTransactionID(flow)
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			s.token = token
			s.request = magiclink.ConsumeRequest{TenantID: facts.TenantID(), CommandID: id, PreAuthID: preAuth, Callback: callback, Cookie: cookie, Origin: string(c.Origin), Network: facts.ClientIP().String(), Device: device.DeviceID(), Caller: caller(facts.TenantID(), preAuth)}
			return s, nil
		},
		Authenticate: func(r *http.Request, s consumeState) (consumeState, error) {
			if e := rateError(c.Rate.AdmitIP(r.Context(), s.facts)); e != nil {
				return s, e
			}
			proof, e := capability.ParseProof(s.token, c.ProofLimits)
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			consumption(r).proof = proof
			s.request.Token = proof
			s.token = ""
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			user, challenge, lifetime, e := c.Service.ConsumeRateSource(r.Context(), s.request)
			if r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			if e != nil {
				return s, e
			}
			s.rate = identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.magic-link.consume", UserID: user, ChallengeID: challenge, ChallengeLifetime: lifetime}
			return s, nil
		},
		Admit: func(r *http.Request, s consumeState) error {
			return rateError(c.Rate.AdmitChallenge(r.Context(), s.facts, s.rate))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s consumeState) {
			a := consumption(r)
			a.ctx = r.Context()
			a.out.CommandID = s.request.CommandID
			a.out.CommitOutcome = "unknown"
			result, e := c.Service.Consume(r.Context(), s.request)
			a.child = result.Challenge.Proof
			if result.Session.CommandID == s.request.CommandID && result.Outcome == result.Session.CommitOutcome {
				a.out.CommitOutcome = outcome(result.Outcome)
			}
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if e != nil {
				reject(w, r, e)
				return
			}
			if result.Session.CommandID != s.request.CommandID || result.Outcome != result.Session.CommitOutcome {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted {
				f := failure{status: 503, code: "unavailable"}
				switch result.Outcome {
				case identity.CommitOutcomeConflict:
					f = failure{status: 409, code: "conflict"}
				case identity.CommitOutcomeInProgress:
					f = failure{status: 409, code: "in_progress", retry: result.Session.RetryAfter}
				case identity.CommitOutcomeNotCommitted:
					f = failure{status: 403, code: "denied"}
				}
				reject(w, r, f)
				return
			}
			if result.Session.Replayed {
				reject(w, r, failure{status: 409, code: "replay"})
				return
			}
			if result.State == auth.SignInStateChallengeRequired {
				challenge := result.Challenge
				now := c.Now()
				if !c.MFAContinuation || challenge.ID == s.request.CommandID || challenge.Method != "totp" || now.IsZero() || !now.Before(challenge.ExpiresAt) || challenge.ExpiresAt.After(now.Add(5*time.Minute)) || result.Session.Session != (session.Session{}) || result.Session.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) || !reflect.ValueOf(result.Session.Cookie).IsZero() {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				if _, err := identity.ParseCommandID(string(challenge.ID)); err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				if err := challenge.Proof.Transfer(r.Context(), func(_ context.Context, wire []byte) error {
					if len(wire) < 32 || len(wire) > 4096 || strings.ContainsAny(string(wire), "\r\n") {
						return identityhttp.ErrUnavailable
					}
					a.challenge = string(wire)
					return nil
				}); err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				a.deliveryFresh = func() (fresh bool) {
					defer func() {
						if recover() != nil {
							fresh = false
						}
					}()
					at := c.Now()
					return !at.IsZero() && !at.Before(now) && at.Before(challenge.ExpiresAt)
				}
				a.out.ChallengeRequired, a.out.ChallengeID = true, challenge.ID
				a.out.ChallengeMethod, a.out.ChallengeExpiresAt = challenge.Method, challenge.ExpiresAt.UTC().Format(time.RFC3339Nano)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(a.out)
				return
			}
			if result.State != auth.SignInStateAuthenticated {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Challenge != (magiclink.MFAChallengeResult{}) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			cookie, csrf, sessionID, e := consumeDelivery(c, s, result)
			if e != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.cookie, a.csrf = cookie, csrf
			a.deliveryFresh = func() (fresh bool) {
				// A middleware may delay the first response write after revelation.
				// Recheck the original bounds without issuing or refreshing anything.
				defer func() {
					if recover() != nil {
						fresh = false
					}
				}()
				spec, err := result.Session.Session.Bindings()
				meta, metaErr := result.Session.Session.MagicLinkAuthentication().Bindings()
				now := c.Now()
				if err != nil || metaErr != nil || now.IsZero() || now.Before(spec.IssuedAt) || now.Before(meta.AuthenticatedAt) || !now.Before(meta.ValidUntil) {
					return false
				}
				_, err = spec.Remember.Evaluate(now, spec.IssuedAt, spec.LastActivityAt, meta.AuthenticatedAt)
				return err == nil
			}
			a.out.SignedIn = true
			a.out.SessionID = sessionID
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(a.out)
		},
	})
	if e != nil {
		return nil, e
	}
	return &consumePipeline{pipeline: p}, nil
}

func consumeDelivery(c ConsumeConfig, s consumeState, out magiclink.ConsumeResult) (string, string, string, error) {
	deny := func() (string, string, string, error) { return "", "", "", identityhttp.ErrUnavailable }
	spec, e := out.Session.Session.Bindings()
	now := c.Now()
	if e != nil || now.IsZero() || spec.TenantID != s.request.TenantID || spec.UserID != s.rate.UserID || spec.Audience != c.Audience || spec.Authentication.Kind != session.AuthenticationMagicLink || spec.IssuedAt.After(now) || out.Session.Cookie.Value != "" {
		return deny()
	}
	meta, e := out.Session.Session.MagicLinkAuthentication().Bindings()
	csrfState, csrfErr := out.Session.Session.CSRFState().Bindings()
	if e != nil || meta.CommandID != s.request.CommandID || meta.CapabilityID != s.rate.ChallengeID || meta.AuthenticatedAt.After(now) || !now.Before(meta.ValidUntil) || csrfErr != nil || csrfState.Binding != (session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return deny()
	}
	if _, e = spec.Remember.Evaluate(now, spec.IssuedAt, spec.LastActivityAt, meta.AuthenticatedAt); e != nil {
		return deny()
	}
	attributes, e := c.SessionCookie.Attributes(spec.Remember, now, spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
	issued := out.Session.Cookie
	if e != nil || issued.Name != attributes.Name || issued.Path != attributes.Path || issued.Domain != "" || !issued.Secure || !issued.HttpOnly || issued.SameSite != attributes.SameSite || issued.Partitioned || len(issued.Unparsed) != 0 || issued.Raw != "" || issued.RawExpires != "" || (attributes.MaxAge == 0 && (issued.MaxAge != 0 || !issued.Expires.IsZero())) || (attributes.MaxAge > 0 && (issued.MaxAge <= 0 || issued.Expires.IsZero() || issued.Expires.After(spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())))) {
		return deny()
	}
	csrf, e := out.CSRFToken.Reveal()
	if e != nil {
		return deny()
	}
	if _, e = session.ParseCSRFToken(csrf); e != nil {
		return deny()
	}
	wire, e := out.Session.Token.Reveal()
	if e != nil {
		return deny()
	}
	if _, e = session.ParseToken(wire); e != nil {
		return deny()
	}
	attributes.Value = wire
	return attributes.String(), csrf, string(spec.SessionID), nil
}
