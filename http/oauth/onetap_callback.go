package oauthhttp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

// OneTapCallbackHTTPInput borrows one original popup callback for a synchronous
// Complete call. Complete must not retain or mutate Credential.IDToken: this
// transport clears its owned bytes when the handler returns. FlowID is only a
// locator; native completion authenticates original browser and provider state.
type OneTapCallbackHTTPInput struct {
	FlowID     identity.PreAuthTransactionID
	FlowCookie auth.BearerCredential
	Callback   onetap.Callback
	Network    netip.Addr
	Device     string
}

// OneTapCallbackHTTPResult transfers original delivery custody only for a new
// exact native commit. Session.DeliveryValidUntil is the original exclusive
// cutoff, not a transport-generated lease. Historical/unknown outcomes cannot
// deliver either cookie. Native completion owns all durable admission/effects.
type OneTapCallbackHTTPResult struct {
	Session session.IssueResult
	CSRF    session.CSRFToken
}

// OneTapCallbackConfig selects one Google popup callback, not redirect, linking,
// signup or MFA. Complete is the borrowed concurrency-safe native completion
// owner and must honor the bounded context without retaining input. Provider,
// tenant, origin and audience are trusted configuration, never browser choices.
// Cookie policies and Device must match original issuance. Rate is the shared
// provider/IP owner; native completion owns counted risk and one-use authority.
// MaximumDuration is 1ms..30s. Now must be prompt and concurrency-safe.
type OneTapCallbackConfig struct {
	Network         identityhttp.NetworkConfig
	Provider        oauth.ProviderProfile
	Complete        func(context.Context, OneTapCallbackHTTPInput) (OneTapCallbackHTTPResult, error)
	Rate            *identityhttp.AuthRateLimiter
	Cookie          session.CookiePolicy
	FlowCookie      session.CookiePolicy
	Device          session.BrowserDeviceConfig
	CSRFCookie      session.CSRFCookiePolicy
	Origin          identityhttp.Origin
	TenantID        identity.TenantID
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed composition and original browser custody.
func (OneTapCallbackConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapCallbackConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime composition export.
func (OneTapCallbackConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText refuses implicit runtime composition export.
func (OneTapCallbackConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts the borrowed original callback.
func (OneTapCallbackHTTPInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapCallbackHTTPInput(redacted)"))
}

// MarshalJSON refuses implicit callback export.
func (OneTapCallbackHTTPInput) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit callback export.
func (OneTapCallbackHTTPInput) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts native delivery custody.
func (OneTapCallbackHTTPResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapCallbackHTTPResult(redacted)"))
}

// MarshalJSON refuses implicit native delivery export.
func (OneTapCallbackHTTPResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit native delivery export.
func (OneTapCallbackHTTPResult) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type oneTapCallbackState struct {
	facts  identityhttp.NetworkFacts
	input  OneTapCallbackHTTPInput
	device session.BrowserDevice
}

// NewOneTapCallbackFeature contributes only exact POST /v1/oauth/onetap-callback
// under identity/oauth/onetap. No other One Tap or OAuth profile is enabled.
func NewOneTapCallbackFeature(c OneTapCallbackConfig) (identityhttp.Feature, error) {
	h, err := NewOneTapCallbackHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = oneTapCallbackWire(c)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth/onetap", Operations: []identityhttp.OperationDescriptor{op}})
}

// NewOneTapCallbackHandler admits exact HTTPS tenant/Origin and original flow,
// signed device and matching Google double-submit cookie/body before Complete.
// It accepts only closed bounded JSON flowId, credential, g_csrf_token and an
// optional client_id confirming the configured value. Query, key, header-token
// and mode alternatives deny. Google verification and durable transaction work
// remain native; this handler never parses JWT claims or retries completion.
// Only fresh accepted cookie emission returns 200 {status:"signed_in"}; every
// nondelivery is redacted, no-store and fail-closed, without redirects/tokens.
func NewOneTapCallbackHandler(c OneTapCallbackConfig) (http.Handler, error) {
	if c.Complete == nil || !c.Rate.Configured() || c.Now == nil || c.TenantID == "" || c.Audience == "" || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Provider.ID != "google" || !c.Provider.GoogleAccounts || c.Provider.Version == 0 || c.Provider.Issuer != "https://accounts.google.com" || c.Provider.ClientID == "" || c.Provider.MaxTokenBytes < 1 || c.Provider.MaxTokenBytes > 1<<20 {
		return nil, identityhttp.ErrInvalidInput
	}
	c.Provider.Scopes, c.Provider.Algorithms = slices.Clone(c.Provider.Scopes), slices.Clone(c.Provider.Algorithms)
	authentication, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" || flow.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	deviceCookie, err := c.Device.Cookie.DeletionAttributes()
	if err != nil || deviceCookie.Name == flow.Name || deviceCookie.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	csrf, err := c.CSRFCookie.DeletionAttributes()
	names := []string{authentication.Name, flow.Name, deviceCookie.Name, csrf.Name, "g_csrf_token"}
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	for i, name := range names {
		for _, other := range names[i+1:] {
			if strings.EqualFold(name, other) {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
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
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[oneTapCallbackState]{MaximumDuration: c.MaximumDuration, Reject: oneTapCallbackReject,
		Decode: func(r *http.Request) (s oneTapCallbackState, err error) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/onetap-callback" || r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.TenantID() != c.TenantID || s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			if _, err := origins.CheckBound(r, c.Origin); err != nil {
				return s, identity.ForbiddenError{}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			bearer, _, err := decoder.CookieBearer(r, flow.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			device, _, err := decoder.CookieBearer(r, deviceCookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), c.TenantID, string(c.Origin), device.Token())
			if err != nil {
				return s, identity.ForbiddenError{}
			}
			googleCookie, err := oneTapCallbackGoogleCookie(r, flow.Name, deviceCookie.Name)
			if err != nil {
				return s, err
			}
			s.input, err = oneTapCallbackJSON(decoder, r, c.Provider, googleCookie)
			if err != nil {
				return s, err
			}
			r.Context().Value(oneTapCallbackKey{}).(*oneTapCallbackDelivery).credential = s.input.Callback.Credential.IDToken
			s.input.FlowCookie, s.input.Network, s.input.Device = bearer, s.facts.ClientIP(), s.device.DeviceID()
			s.input.Callback.Origin = string(c.Origin)
			return s, nil
		},
		Authenticate: func(_ *http.Request, s oneTapCallbackState) (oneTapCallbackState, error) { return s, nil },
		Admit: func(r *http.Request, s oneTapCallbackState) error {
			admitted, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, "identity.oauth.onetap-callback", c.Provider.ID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return providerRateFailure{retry: admitted.RetryAfter}
			}
			if err == nil && !admitted.Allowed {
				return identityhttp.ErrRateUnavailable
			}
			return err
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s oneTapCallbackState) {
			delivery := r.Context().Value(oneTapCallbackKey{}).(*oneTapCallbackDelivery)
			if delivery.committed {
				return
			}
			if !s.device.ExpiresAt().After(c.Now()) {
				oneTapCallbackReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out, err := c.Complete(r.Context(), s.input)
			if err != nil {
				oneTapCallbackReject(w, r, err)
				return
			}
			// The commit hook owns the final clock/context check and original
			// token transfer; middleware cannot renew this native delivery lease.
			delivery.emit = func() ([]string, error) {
				if r.Context().Err() != nil || !s.device.ExpiresAt().After(c.Now()) {
					return nil, identityhttp.ErrUnavailable
				}
				cookies, err := oneTapCallbackCookies(c, out)
				if err != nil || r.Context().Err() != nil {
					return nil, identityhttp.ErrUnavailable
				}
				return cookies, nil
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"status\":\"signed_in\"}\n"))
		},
	})
	if err != nil {
		return nil, err
	}
	return &oneTapCallbackHandler{pipeline: pipeline}, nil
}

func oneTapCallbackJSON(decoder *identityhttp.RequestDecoder, r *http.Request, p oauth.ProviderProfile, cookie string) (OneTapCallbackHTTPInput, error) {
	var in OneTapCallbackHTTPInput
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
	defer func() {
		for _, raw := range fields {
			clear(raw)
		}
	}()
	if err != nil {
		return in, identityhttp.ErrInvalidInput
	}
	for name := range fields {
		switch name {
		case "flowId", "credential", "g_csrf_token", "client_id":
		default:
			return in, identityhttp.ErrInvalidInput
		}
	}
	read := func(name string) (string, error) {
		var value string
		raw, ok := fields[name]
		if !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
			return "", identityhttp.ErrInvalidInput
		}
		return value, nil
	}
	flow, err := read("flowId")
	if err != nil {
		return in, err
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(flow)
	defer clear(decoded)
	if err != nil || len(decoded) != 16 || len(flow) != 22 || base64.RawURLEncoding.EncodeToString(decoded) != flow {
		return in, identityhttp.ErrInvalidInput
	}
	credential, err := read("credential")
	if err != nil || len(credential) == 0 || len(credential) > p.MaxTokenBytes {
		return in, identityhttp.ErrInvalidInput
	}
	csrf, err := read("g_csrf_token")
	if err != nil || !oneTapCallbackCSRFValue(csrf) {
		return in, identityhttp.ErrInvalidInput
	}
	if _, present := fields["client_id"]; present {
		client, err := read("client_id")
		if err != nil || client != p.ClientID {
			return in, identityhttp.ErrInvalidInput
		}
	}
	a, b := sha256.Sum256([]byte(cookie)), sha256.Sum256([]byte(csrf))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return in, identity.ForbiddenError{}
	}
	in.FlowID = identity.PreAuthTransactionID(flow)
	in.Callback = onetap.Callback{CSRFCookies: []string{cookie}, CSRFBody: []string{csrf}, Credential: oauth.GoogleCredential{IDToken: []byte(credential)}}
	return in, nil
}

func oneTapCallbackGoogleCookie(r *http.Request, flowName, deviceName string) (string, error) {
	// CookieBearer already validates the aggregate cookie envelope and every
	// sibling's cookie octets. Read raw parts so duplicate/quoted Google values
	// cannot disappear through net/http's permissive first-value parsing.
	value, found := "", false
	for name, lines := range r.Header {
		if strings.EqualFold(name, "Cookie") {
			for _, line := range lines {
				for _, part := range strings.Split(line, ";") {
					name, raw, _ := strings.Cut(strings.TrimLeft(part, " \t"), "=")
					if (strings.EqualFold(name, flowName) && name != flowName) || (strings.EqualFold(name, deviceName) && name != deviceName) || (strings.EqualFold(name, "g_csrf_token") && name != "g_csrf_token") {
						return "", identityhttp.ErrInvalidInput
					}
					if name != "g_csrf_token" {
						continue
					}
					if found || !oneTapCallbackCSRFValue(raw) {
						return "", identityhttp.ErrInvalidInput
					}
					value, found = raw, true
				}
			}
		}
	}
	if !found {
		return "", identityhttp.ErrInvalidInput
	}
	return value, nil
}

func oneTapCallbackCSRFValue(raw string) bool {
	// Match oauth/onetap's opaque RFC6265 cookie-octet policy. Google defines
	// no encoding; the 1KiB maximum is the existing native admission bound.
	if len(raw) == 0 || len(raw) > 1024 {
		return false
	}
	for i := range len(raw) {
		b := raw[i]
		if b < 0x21 || b > 0x7e || b == '"' || b == ',' || b == ';' || b == '\\' {
			return false
		}
	}
	return true
}

func oneTapCallbackReject(w http.ResponseWriter, _ *http.Request, cause error) {
	status, code := http.StatusServiceUnavailable, "unavailable"
	var invalid identity.InvalidInputError
	var forbidden identity.ForbiddenError
	var conflict identity.ConflictError
	var native *onetap.Error
	var limited providerRateFailure
	switch {
	case errors.As(cause, &limited):
		status, code = 429, "rate_limited"
		retry := min(max(limited.retry, time.Second), time.Hour)
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
	case errors.Is(cause, identityhttp.ErrInvalidInput), errors.As(cause, &invalid):
		status, code = 400, "invalid_request"
	case errors.As(cause, &forbidden):
		status, code = 403, "denied"
	case errors.As(cause, &conflict):
		status, code = 409, "conflict"
	case errors.As(cause, &native):
		switch native.Kind() {
		case onetap.InvalidInput:
			status, code = 400, "invalid_request"
		case onetap.Denied, onetap.InvalidProof:
			status, code = 403, "denied"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}

func oneTapCallbackCookies(c OneTapCallbackConfig, out OneTapCallbackHTTPResult) ([]string, error) {
	deny := func() ([]string, error) { return nil, identityhttp.ErrUnavailable }
	issued := out.Session
	now := c.Now()
	if issued.Replayed || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.CommandID == "" || !issued.DeliveryValidUntil.After(now) {
		return deny()
	}
	spec, err := issued.Session.Bindings()
	if err != nil || spec.TenantID != c.TenantID || spec.Audience != c.Audience || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || spec.Authentication.Proof.ID != auth.ProofID(issued.CommandID) {
		return deny()
	}
	if _, err := issued.Session.Lifetime(now); err != nil {
		return deny()
	}
	if spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(c.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: c.Audience, Now: now}) != nil {
		return deny()
	}
	csrfState, err := issued.Session.CSRFState().Bindings()
	if err != nil || csrfState.Binding != (session.CSRFBinding{TenantID: c.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return deny()
	}
	expires := spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())
	authentication, err := c.Cookie.Attributes(spec.Remember, now, expires)
	stored := issued.Cookie
	if err != nil || stored.Name != authentication.Name || stored.Path != authentication.Path || stored.Value != "" || stored.Domain != "" || !stored.Secure || !stored.HttpOnly || stored.SameSite != authentication.SameSite || stored.Partitioned || stored.Quoted || stored.RawExpires != "" || (authentication.MaxAge == 0 && (stored.MaxAge != 0 || !stored.Expires.IsZero())) || (authentication.MaxAge > 0 && (stored.MaxAge <= 0 || stored.Expires.IsZero() || stored.Expires.After(expires))) {
		return deny()
	}
	csrf, err := c.CSRFCookie.Attributes(spec.Remember, now, expires)
	if err != nil {
		return deny()
	}
	authentication.Value, err = issued.Token.Reveal()
	if err != nil {
		return deny()
	}
	if _, err := session.ParseToken(authentication.Value); err != nil {
		return deny()
	}
	csrf.Value, err = out.CSRF.Reveal()
	if err != nil {
		return deny()
	}
	if _, err := session.ParseCSRFToken(csrf.Value); err != nil {
		return deny()
	}
	return []string{authentication.String(), csrf.String()}, nil
}

type oneTapCallbackKey struct{}
type oneTapCallbackDelivery struct {
	credential []byte
	emit       func() ([]string, error)
	committed  bool
}
type oneTapCallbackHandler struct{ pipeline http.Handler }

func (h *oneTapCallbackHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	bound, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &oneTapCallbackHandler{pipeline: bound}, nil
}

func (h *oneTapCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	delivery := &oneTapCallbackDelivery{}
	defer func() { clear(delivery.credential) }()
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), oneTapCallbackKey{}, delivery))
	}
	var cookies []string
	refused, rendered := false, false
	protect := func() {
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(strings.ToLower(name), strings.ToLower(http.TrailerPrefix)) {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		for _, cookie := range cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
	}
	commit := func(status int) int {
		if !delivery.committed && status >= 200 {
			delivery.committed = true
			if status < 400 {
				var err error
				if status != 200 || delivery.emit == nil {
					err = identityhttp.ErrUnavailable
				} else {
					cookies, err = delivery.emit()
				}
				if err != nil {
					cookies = nil
					refused = true
					status = 503
					w.Header().Set("Content-Type", "application/json")
					w.Header().Del("Content-Length")
				}
			}
		}
		protect()
		return status
	}
	protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) { next(commit(status)) }
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(body []byte) (int, error) {
				if !delivery.committed {
					w.WriteHeader(commit(200))
				}
				protect()
				if refused {
					if !rendered {
						rendered = true
						if _, err := next([]byte("{\"error\":\"unavailable\"}\n")); err != nil {
							return 0, err
						}
					}
					return len(body), nil
				}
				return next(body)
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if !delivery.committed {
					w.WriteHeader(commit(200))
				}
				protect()
				next()
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(body io.Reader) (int64, error) {
				if !delivery.committed {
					w.WriteHeader(commit(200))
				}
				protect()
				if refused {
					if !rendered {
						rendered = true
						_, _ = w.Write([]byte("{\"error\":\"unavailable\"}\n"))
					}
					return 0, identityhttp.ErrUnavailable
				}
				return next(body)
			}
		},
	})
	h.pipeline.ServeHTTP(writer, r)
	protect()
}
