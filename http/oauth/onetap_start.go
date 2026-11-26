package oauthhttp

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

// OneTapStartHTTPResult transfers one synchronous native Start outcome. The
// composer maps the native receipt and Browser result without regenerating or
// revealing anything. Only a fresh committed invocation carries browser fields;
// replay, unknown commitment and recovery carry no delivery authority. Token
// copies retain the native issuer's single reveal permission. Never log fields.
type OneTapStartHTTPResult struct {
	CommandID               identity.CommandID
	Outcome                 identity.CommitOutcome
	Replayed                bool
	FlowID                  identity.PreAuthTransactionID
	ClientID, Nonce, Origin string
	ExpiresAt               time.Time
	Options                 onetap.BrowserStartOptions
	Cookie                  http.Cookie
	Token                   session.Token
}

// Format redacts native browser custody, including when enclosed in diagnostics.
func (OneTapStartHTTPResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapStartHTTPResult(redacted)"))
}

// MarshalJSON denies implicit export; the handler projects only named fields.
func (OneTapStartHTTPResult) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText denies implicit export of native browser custody.
func (OneTapStartHTTPResult) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// OneTapStartConfig opts into anonymous Google One Tap initiation only. Start
// and Rate are borrowed concurrency-safe owners and must honor cancellation.
// Start must return its original native command outcome and browser custody,
// never a reconstructed/reissued result. ProviderID and ClientID are trusted
// deployment bindings, not browser selectors. FlowCookie and Device use the
// same Lax host-cookie policy as neighboring social signin. Lifetime resolves
// Remember once; it does not change the native five-minute preauth expiry.
// MaximumDuration is 1ms..30s and earlier deadlines win. Now is prompt and
// concurrency-safe. Construction performs no IO and snapshots device policy.
type OneTapStartConfig struct {
	Network         identityhttp.NetworkConfig
	ProviderID      string
	ClientID        string
	Start           func(context.Context, onetap.BrowserStartRequest) (OneTapStartHTTPResult, error)
	Rate            *identityhttp.AuthRateLimiter
	FlowCookie      session.CookiePolicy
	Device          session.BrowserDeviceConfig
	Origin          identityhttp.Origin
	Lifetime        session.LifetimeConfig
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime configuration.
func (OneTapStartConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.OneTapStartConfig(redacted)"))
}

// MarshalJSON denies implicit runtime configuration export.
func (OneTapStartConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText denies implicit runtime configuration export.
func (OneTapStartConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// NewOneTapStartFeature exposes only the selected POST /v1/oauth/onetap-start
// operation and its matching wire contract. It enables no callback, redirect,
// provider UI, generic signin, linking or signup operation.
func NewOneTapStartFeature(c OneTapStartConfig) (identityhttp.Feature, error) {
	h, err := NewOneTapStartHandler(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-start", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: maximumOneTapStartResponse})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = wireOneTapStart(c)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/oauth/onetap", Operations: []identityhttp.OperationDescriptor{op}})
}

const maximumOneTapStartResponse = 16384

type oneTapStartState struct {
	facts   identityhttp.NetworkFacts
	device  session.BrowserDevice
	request onetap.BrowserStartRequest
}

// NewOneTapStartHandler requires exact HTTPS tenant/Origin, a signed existing
// device, one Idempotency-Key and closed bounded JSON choosing prompt XOR popup
// button plus optional remember. Flow cookies, CSRF alternates, client/provider
// configuration, hints and callbacks are not input. Shared provider/IP admission
// precedes one synchronous native Start. Only its fresh exact committed result
// can deliver a detached browser projection and original reveal-once flow cookie.
// There is no transport store, automatic retry, token redelivery or restart on
// lost acknowledgement. The server owns raw IO/write deadlines.
func NewOneTapStartHandler(c OneTapStartConfig) (http.Handler, error) {
	if c.Start == nil || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || !oneTapStartVisible(c.ProviderID, 128) || !oneTapStartVisible(c.ClientID, 1024) {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := identity.ParseIdentifierID(c.ProviderID); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" || flow.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
	}
	deviceCookie, err := c.Device.Cookie.DeletionAttributes()
	if err != nil || deviceCookie.SameSite != http.SameSiteLaxMode {
		return nil, identityhttp.ErrInvalidInput
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
	reject := func(w http.ResponseWriter, _ *http.Request, cause error) {
		status, code := http.StatusServiceUnavailable, "unavailable"
		var invalid identity.InvalidInputError
		var forbidden identity.ForbiddenError
		var conflict identity.ConflictError
		var limited providerRateFailure
		var native *onetap.Error
		switch {
		case errors.As(cause, &limited):
			status, code = http.StatusTooManyRequests, "rate_limited"
			retry := min(max(limited.retry, time.Second), time.Hour)
			w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		case errors.Is(cause, identityhttp.ErrInvalidInput), errors.As(cause, &invalid):
			status, code = http.StatusBadRequest, "invalid_request"
		case errors.As(cause, &forbidden):
			status, code = http.StatusForbidden, "denied"
		case errors.As(cause, &conflict):
			status, code = http.StatusConflict, "conflict"
		case errors.As(cause, &native):
			if native.Kind() == onetap.InvalidInput {
				status, code = http.StatusBadRequest, "invalid_request"
			} else if native.Kind() == onetap.Denied || native.Kind() == onetap.InvalidProof {
				status, code = http.StatusForbidden, "denied"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{code})
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[oneTapStartState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(r *http.Request) (s oneTapStartState, err error) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/onetap-start" || r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.Scheme() != "https" || s.facts.Origin() != string(c.Origin) {
				return s, identity.ForbiddenError{}
			}
			if _, err = origins.CheckBound(r, c.Origin); err != nil {
				return s, identity.ForbiddenError{}
			}
			for name := range r.Header {
				if strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			key, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			// A previous flow can still be in the browser after cancellation or
			// successful sign-in. It is not input or authority for a new Start.
			// Keep strict singleton framing, but do not retain the credential.
			if _, _, err = decoder.CookieBearer(r, flow.Name, identityhttp.HeaderOptional); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			device, _, err := decoder.CookieBearer(r, deviceCookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), s.facts.Origin(), device.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			options, remember, err := decodeOneTapStart(body, c.Lifetime)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.request, err = onetap.NewBrowserStartRequest(onetap.BrowserStartRequestSpec{TenantID: s.facts.TenantID(), Origin: s.facts.Origin(), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID(), Key: key, Options: options, Remember: remember})
			return s, err
		},
		Authenticate: func(r *http.Request, s oneTapStartState) (oneTapStartState, error) {
			out, err := c.Rate.AdmitProviderIP(r.Context(), s.facts, "identity.oauth.onetap-start", c.ProviderID)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return s, providerRateFailure{retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed {
				return s, identityhttp.ErrRateUnavailable
			}
			return s, nil
		},
		Admit: func(_ *http.Request, s oneTapStartState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s oneTapStartState) {
			delivery := r.Context().Value(oneTapStartDeliveryKey{}).(*oneTapStartDelivery)
			if delivery.committed {
				return
			}
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out, err := c.Start(r.Context(), s.request)
			if err != nil {
				reject(w, r, err)
				return
			}
			projection, err := oneTapStartProjection(c, s, out, c.Now())
			if err != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			body, err := json.Marshal(projection)
			if err != nil || len(body) > maximumOneTapStartResponse {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			delivery.out, delivery.body, delivery.ctx = out, body, r.Context()
			delivery.current = func() bool { _, err := oneTapStartProjection(c, s, out, c.Now()); return err == nil }
			delivery.now = c.Now
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		},
	})
	if err != nil {
		return nil, err
	}
	return &oneTapStartHandler{pipeline: pipeline}, nil
}

func oneTapStartVisible(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 33 || value[i] > 126 {
			return false
		}
	}
	return true
}

func decodeOneTapStart(body map[string]json.RawMessage, lifetime session.LifetimeConfig) (onetap.BrowserStartOptions, session.RememberPolicy, error) {
	deny := func() (onetap.BrowserStartOptions, session.RememberPolicy, error) {
		return onetap.BrowserStartOptions{}, session.RememberPolicy{}, identityhttp.ErrInvalidInput
	}
	if len(body) < 1 || len(body) > 2 {
		return deny()
	}
	var prompt onetap.OneTapPromptOptions
	var button onetap.OneTapButtonOptions
	choice := session.RememberDefault
	for name, raw := range body {
		if string(raw) == "null" {
			return deny()
		}
		switch name {
		case "remember":
			var persistent bool
			if json.Unmarshal(raw, &persistent) != nil {
				return deny()
			}
			choice = session.BrowserSession
			if persistent {
				choice = session.PersistentSession
			}
		case "prompt":
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 {
				return deny()
			}
			var context onetap.PromptContext
			var cancel bool
			if !oneTapStartField(fields, "context", &context) || !oneTapStartField(fields, "cancelOnTapOutside", &cancel) {
				return deny()
			}
			var err error
			prompt, err = onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: context, CancelOnTapOutside: cancel})
			if err != nil {
				return deny()
			}
		case "button":
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) < 3 || len(fields) > 4 {
				return deny()
			}
			var config onetap.OneTapButtonConfig
			if !oneTapStartField(fields, "type", &config.Type) || !oneTapStartField(fields, "theme", &config.Theme) || !oneTapStartField(fields, "size", &config.Size) {
				return deny()
			}
			if _, ok := fields["width"]; ok {
				if !oneTapStartField(fields, "width", &config.Width) {
					return deny()
				}
			} else if len(fields) != 3 {
				return deny()
			}
			var err error
			button, err = onetap.NewOneTapButtonOptions(config)
			if err != nil {
				return deny()
			}
		default:
			return deny()
		}
	}
	options, err := onetap.NewBrowserStartOptions(prompt, button)
	if err != nil {
		return deny()
	}
	remember, err := session.ResolveRememberPolicy(choice, lifetime)
	return options, remember, err
}

func oneTapStartField(fields map[string]json.RawMessage, name string, target any) bool {
	raw, ok := fields[name]
	return ok && string(raw) != "null" && json.Unmarshal(raw, target) == nil
}

type oneTapStartResponse struct {
	ClientID  string                        `json:"clientId"`
	Nonce     string                        `json:"nonce"`
	FlowID    identity.PreAuthTransactionID `json:"flowId"`
	ExpiresAt time.Time                     `json:"expiresAt"`
	Options   onetap.BrowserStartProjection `json:"options"`
}

func oneTapStartProjection(c OneTapStartConfig, s oneTapStartState, out OneTapStartHTTPResult, now time.Time) (oneTapStartResponse, error) {
	deny := func() (oneTapStartResponse, error) { return oneTapStartResponse{}, identityhttp.ErrUnavailable }
	if out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.ClientID != c.ClientID || out.Origin != string(c.Origin) || out.Token == (session.Token{}) || now.IsZero() || !s.device.ExpiresAt().After(now) || out.ExpiresAt.Sub(now) < time.Second || out.ExpiresAt.Sub(now) > 5*time.Minute {
		return deny()
	}
	if _, err := identity.ParseCommandID(string(out.CommandID)); err != nil {
		return deny()
	}
	if _, err := identity.ParsePreAuthTransactionID(string(out.FlowID)); err != nil {
		return deny()
	}
	if len(out.Nonce) != 43 {
		return deny()
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(out.Nonce)
	if err != nil || len(nonce) != 32 {
		return deny()
	}
	// session.PreAuthIntent forbids a zero nonce in native issuance as well.
	if [32]byte(nonce) == ([32]byte{}) {
		return deny()
	}
	request, err := s.request.Bindings()
	if err != nil || out.Options != request.Options {
		return deny()
	}
	options, err := out.Options.Projection()
	if err != nil {
		return deny()
	}
	expected, err := c.FlowCookie.DeletionAttributes()
	actual := out.Cookie
	// Native PreAuthIssuer owns the five-minute original expiry. net/http drops
	// malformed cookie attributes, so compare before assigning the sole bearer.
	if err != nil || actual.Value != "" || actual.Name != expected.Name || actual.Path != expected.Path || actual.Domain != "" || !actual.Secure || !actual.HttpOnly || actual.SameSite != expected.SameSite || actual.Partitioned || actual.Quoted || actual.Raw != "" || actual.RawExpires != "" || len(actual.Unparsed) != 0 || actual.MaxAge < 1 || actual.MaxAge > 300 || !actual.Expires.Equal(out.ExpiresAt) {
		return deny()
	}
	return oneTapStartResponse{ClientID: out.ClientID, Nonce: out.Nonce, FlowID: out.FlowID, ExpiresAt: out.ExpiresAt, Options: options}, nil
}

type oneTapStartDeliveryKey struct{}
type oneTapStartDelivery struct {
	out       OneTapStartHTTPResult
	body      []byte
	ctx       context.Context
	current   func() bool
	now       func() time.Time
	committed bool
}

func (*oneTapStartDelivery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.oneTapStartDelivery(redacted)"))
}

type oneTapStartHandler struct{ pipeline http.Handler }

func (h *oneTapStartHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	bound, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &oneTapStartHandler{pipeline: bound}, nil
}

func (h *oneTapStartHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	delivery := &oneTapStartDelivery{}
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), oneTapStartDeliveryKey{}, delivery))
	}
	refused, rendered := false, false
	cookie := ""
	protect := func() {
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(strings.ToLower(name), strings.ToLower(http.TrailerPrefix)) {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if cookie != "" && !refused {
			w.Header().Set("Set-Cookie", cookie)
		}
	}
	commit := func(status int) int {
		if !delivery.committed && status >= 200 {
			delivery.committed = true
			if len(delivery.body) != 0 {
				if status != http.StatusOK || delivery.ctx == nil || delivery.ctx.Err() != nil || delivery.current == nil || !delivery.current() {
					refused = true
				} else {
					actual := delivery.out.Cookie
					actual.MaxAge = min(actual.MaxAge, int(delivery.out.ExpiresAt.Sub(delivery.now())/time.Second))
					if actual.MaxAge < 1 {
						refused = true
					} else {
						value, err := delivery.out.Token.Reveal()
						if err != nil || delivery.ctx.Err() != nil {
							refused = true
						} else if _, err = session.ParseToken(value); err != nil {
							refused = true
						} else {
							actual.Value = value
							cookie = actual.String()
						}
					}
				}
				if refused {
					status = http.StatusServiceUnavailable
					w.Header().Set("Content-Type", "application/json")
					w.Header().Del("Content-Length")
				}
			}
		}
		protect()
		return status
	}
	write := func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(body []byte) (int, error) {
			if !delivery.committed {
				if len(delivery.body) != 0 && !bytes.Equal(body, delivery.body) {
					refused = true
				}
				status := http.StatusOK
				if refused {
					status = http.StatusServiceUnavailable
				}
				w.WriteHeader(commit(status))
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
	}
	protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(status int) { next(commit(status)) }
		},
		Write: write,
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				if !delivery.committed {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect()
				next()
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(reader io.Reader) (int64, error) {
				if !delivery.committed && len(delivery.body) != 0 {
					body, err := io.ReadAll(io.LimitReader(reader, maximumOneTapStartResponse+1))
					if err != nil {
						refused = true
					}
					count, writeErr := write(w.Write)(body)
					return int64(count), writeErr
				}
				if !delivery.committed {
					w.WriteHeader(commit(http.StatusOK))
				}
				protect()
				if refused {
					if !rendered {
						rendered = true
						_, _ = w.Write([]byte("{\"error\":\"unavailable\"}\n"))
					}
					return 0, identityhttp.ErrUnavailable
				}
				return next(reader)
			}
		},
	})
	h.pipeline.ServeHTTP(writer, r)
	protect()
}
