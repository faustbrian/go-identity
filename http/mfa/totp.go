// Package mfahttp provides opt-in standard-library transport for owned MFA
// workflows. Transport admission never substitutes for native factor policy.
package mfahttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// TOTPVerifyService borrows the same native completion and authenticated
// original-source owner. Source returns immutable issued subject/child/lifetime,
// never JSON-selected identity or permission to complete. Both calls are bounded
// and concurrent-safe; the owner outlives handler calls.
type TOTPVerifyService interface {
	TotpVerify(context.Context, mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error)
	TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
}

// TOTPVerifyConfig selects the initial magic-link/TOTP browser completion
// profile. Network, origin, callback, actor/revision, audience, device and session
// cookie match native issuance. Rate and Service are borrowed concurrent-safe
// owners. Now is prompt and concurrent-safe; MaximumDuration is1ms..30s, with
// earlier inbound deadlines winning. Construction performs no IO or issuance.
type TOTPVerifyConfig struct {
	// PasswordPrimary explicitly selects password-origin delivery. False retains
	// the existing magic-link profile; neither profile accepts the other's evidence.
	PasswordPrimary bool
	Network         identityhttp.NetworkConfig
	Service         TOTPVerifyService
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
}

// TOTPVerifyResponse is no-store outcome metadata. SignedIn means this response
// delivered new committed credentials; a historical commit is not new delivery.
// JSON never contains a code, proof, token, synchronizer or subject.
type TOTPVerifyResponse struct {
	SignedIn      bool               `json:"signedIn"`
	CommitOutcome string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	SessionID     string             `json:"sessionID,omitempty"`
	Error         string             `json:"error,omitempty"`
}

type rejection struct {
	status int
	code   string
	retry  time.Duration
}

func (r rejection) Error() string { return "mfahttp: request rejected" }

type attemptKey struct{}
type attempt struct {
	out          TOTPVerifyResponse
	proof        capability.Proof
	ctx          context.Context
	cookie, csrf string
	fresh        func() bool
}
type input struct {
	request mfa.TotpVerifyRequest
	facts   identityhttp.NetworkFacts
	rate    identityhttp.ChallengeVerificationRateRequest
	wire    string
}

func current(r *http.Request) *attempt { return r.Context().Value(attemptKey{}).(*attempt) }

// NewTOTPVerifyHandler selects POST /v1/mfa/totp-verify only. Original command,
// flow, child/factor IDs, proof, opaque code, callback and trust-device choice are
// closed JSON. Idempotency-Key, Authorization, query and redirects are forbidden.
// Native unsupported trusted-device requests deny, not silently degrade.
func NewTOTPVerifyHandler(c TOTPVerifyConfig) (http.Handler, error) {
	return NewTOTPVerifyHandlerWithMiddleware(c, nil)
}

// NewTOTPVerifyHandlerWithMiddleware binds actual decode, IP/source, challenge
// admission and native execution phases. Hooks cannot replace private input or
// credential output; final response commitment rechecks delivery freshness.
func NewTOTPVerifyHandlerWithMiddleware(c TOTPVerifyConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.Service == nil || reflect.ValueOf(c.Service).Kind() == reflect.Pointer && reflect.ValueOf(c.Service).IsNil() || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.Audience) == 0 || len(c.Audience) > 256 {
		return nil, identityhttp.ErrInvalidInput
	}
	u, err := url.Parse(c.CallbackURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(c.CallbackURL, "#") || len(c.CallbackURL) > 2048 {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil || cookie.Name == "__Host-identity_flow" || cookie.Name == "__Host-identity_device" {
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
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	caller := func(tenant identity.TenantID, child string) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(child)}}}
	}
	if caller("configuration", "configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := current(r)
		a.cookie, a.csrf = "", ""
		a.out.SignedIn = false
		a.out.SessionID = ""
		f := rejection{status: 503, code: "unavailable"}
		var specific rejection
		var denied identity.ForbiddenError
		var invalid identity.InvalidInputError
		switch {
		case errors.As(err, &specific):
			f = specific
		case errors.Is(err, identityhttp.ErrInvalidInput) || errors.As(err, &invalid):
			f = rejection{status: 400, code: "invalid_request"}
		case errors.As(err, &denied):
			f = rejection{status: 403, code: "denied"}
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
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[input]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (input, error) {
			var s input
			if r.URL.Path != "/v1/mfa/totp-verify" || r.URL.EscapedPath() != r.URL.Path {
				return s, rejection{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, rejection{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, rejection{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, rejection{status: 403, code: "https_required"}
			}
			if _, err = origin.Check(r); err != nil {
				return s, rejection{status: 403, code: "origin_denied"}
			}
			browser, present, err := decoder.CookieBearer(r, "__Host-identity_flow", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			deviceCookie, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			device, err := devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), deviceCookie.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 8 {
				return s, identityhttp.ErrInvalidInput
			}
			defer func() {
				for _, raw := range body {
					clear(raw)
				}
			}()
			var command, flow, child, factor, wire, code, callback string
			for name, dst := range map[string]*string{"commandID": &command, "preAuthID": &flow, "challengeID": &child, "factorID": &factor, "token": &wire, "code": &code, "callbackURL": &callback} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			var trust bool
			raw, ok := body["trustDevice"]
			if !ok || string(raw) == "null" || json.Unmarshal(raw, &trust) != nil || callback != c.CallbackURL {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParseCommandID(command)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			preauth, err := identity.ParsePreAuthTransactionID(flow)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseCommandID(child); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseCommandID(factor); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if len(wire) < 32 || len(wire) > 4096 {
				return s, identityhttp.ErrInvalidInput
			}
			opaque, err := auth.NewOneTimeCode(code)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, s.wire = facts, wire
			s.request = mfa.TotpVerifyRequest{TenantID: facts.TenantID(), CommandID: id, PreAuthID: preauth, ChallengeID: mfa.ChallengeID(child), FactorID: mfa.FactorID(factor), Code: opaque, TrustDevice: trust, Cookie: browser, Origin: string(c.Origin), Callback: callback, Network: facts.ClientIP().String(), Device: device.DeviceID(), Caller: caller(facts.TenantID(), child)}
			return s, nil
		},
		Authenticate: func(r *http.Request, s input) (input, error) {
			if err := rateError(c.Rate.AdmitIP(r.Context(), s.facts)); err != nil {
				return s, err
			}
			proof, err := capability.ParseProof(s.wire, capability.DefaultLimits())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			current(r).proof = proof
			s.request.Proof = proof
			s.wire = ""
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			user, child, lifetime, err := c.Service.TotpVerificationRateSource(r.Context(), s.request)
			if err != nil {
				return s, err
			}
			if r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.rate = identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.mfa.totp-verify", UserID: user, ChallengeID: child, ChallengeLifetime: lifetime}
			return s, nil
		},
		Admit: func(r *http.Request, s input) error {
			return rateError(c.Rate.AdmitChallenge(r.Context(), s.facts, s.rate))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s input) {
			a := current(r)
			a.ctx = r.Context()
			a.out.CommandID = s.request.CommandID
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.TotpVerify(r.Context(), s.request)
			if result.Session.CommandID == s.request.CommandID && result.Outcome == result.Session.CommitOutcome {
				a.out.CommitOutcome = outcome(result.Outcome)
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			if r.Context().Err() != nil || result.Session.CommandID != s.request.CommandID || result.Outcome != result.Session.CommitOutcome {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted {
				status, code := 503, "unavailable"
				switch result.Outcome {
				case identity.CommitOutcomeConflict:
					status, code = 409, "conflict"
				case identity.CommitOutcomeInProgress:
					status, code = 409, "in_progress"
				case identity.CommitOutcomeNotCommitted:
					status, code = 403, "denied"
				}
				reject(w, r, rejection{status: status, code: code, retry: result.Session.RetryAfter})
				return
			}
			if result.Session.Replayed {
				reject(w, r, rejection{status: 409, code: "replay"})
				return
			}
			cookie, csrf, id, fresh, err := deliver(c, s, result)
			if err != nil {
				reject(w, r, err)
				return
			}
			a.cookie, a.csrf, a.fresh = cookie, csrf, fresh
			a.out.SignedIn = true
			a.out.SessionID = id
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(a.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &responsePipeline{pipeline: pipeline}, nil
}

func rateError(result identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return rejection{status: 429, code: "rate_limited", retry: result.RetryAfter}
	}
	if err != nil || !result.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}
func outcome(o identity.CommitOutcome) string {
	switch o {
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	}
	return "unknown"
}

// Format redacts credential, owner and configuration state.
func (TOTPVerifyConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.TOTPVerifyConfig(redacted)"))
}

// MarshalJSON denies implicit configuration/credential export.
func (TOTPVerifyConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit export and map-key disclosure.
func (TOTPVerifyConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
