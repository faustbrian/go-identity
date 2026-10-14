package mfahttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	auth "github.com/faustbrian/go-authentication"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// URIService combines native disclosure with a read-only original-custody quota
// source. The source authenticates enrollment/session/CSRF, returns immutable
// enrollment lifetime and earliest original delivery deadline, and performs no
// factor-secret decryption, reservation, debit or reveal. These facts grant no
// mutation authority; TotpUri must independently fence current native owners.
type URIService interface {
	mfa.TOTPURIService
	TotpUriRateSource(context.Context, mfa.TotpUriRequest) (time.Duration, time.Time, error)
}

// URIConfig selects cookie-only pending-factor disclosure. Owners are borrowed,
// bounded and concurrency-safe, with one native authority. Rate is shared with
// other secret operations. Exact HTTPS origins, policy revision and prompt Now
// are trusted startup policy. MaximumDuration is 1ms..30s; caller deadlines win.
type URIConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         URIService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format prevents traversal of borrowed custody and configuration.
func (URIConfig) Format(s fmt.State, _ rune) { io.WriteString(s, "mfahttp.URIConfig(redacted)") }

// MarshalJSON denies implicit configuration export.
func (URIConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit text export.
func (URIConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue returns only a fixed marker.
func (URIConfig) LogValue() slog.Value { return slog.StringValue("mfahttp.URIConfig(redacted)") }

type uriState struct {
	enableState
	enrollment   mfa.EnrollmentID
	command      identity.CommandID
	origin       identityhttp.Origin
	request      mfa.TotpUriRequest
	until        time.Time
	lifetime     time.Duration
	confirmation mfa.TotpVerifyRequest
	code         auth.OneTimeCode
	purpose      auth.Purpose
}

func (uriState) Format(s fmt.State, _ rune)   { io.WriteString(s, "mfahttp.uriState(redacted)") }
func (uriState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (uriState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (uriState) LogValue() slog.Value         { return slog.StringValue("mfahttp.uriState(redacted)") }

// NewURIHandler owns POST /v1/mfa/totp-uri without registering it. Closed JSON
// requires canonical commandID and enrollmentID. Original cookie, Origin and
// X-CSRF-Token are required; Authorization and Idempotency-Key are forbidden.
// No successor command, factor secret, session or automatic retry is created.
// Only a fresh known commit can deliver the URI; all responses are no-store.
func NewURIHandler(c URIConfig) (http.Handler, error) { return NewURIHandlerWithMiddleware(c, nil) }

// NewURIHandlerWithMiddleware binds hooks to real decode, current session read,
// original source/quota admission and atomic native reveal phases. Waiting cannot
// reset original session evidence or extend the source's delivery deadline.
func NewURIHandlerWithMiddleware(c URIConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newPendingFactorHandler(c, nil, nil, m)
}

// Closed native profiles share cookie parsing and original validity only;
// neither can substitute for the other's source, rate policy or mutation owner.
func newPendingFactorHandler(c URIConfig, confirm *EnrollmentConfirmationConfig, active *ActiveStepUpConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || (confirm == nil && active == nil && (enableNil(c.Service) || !c.Rate.Configured())) || (confirm != nil && (active != nil || enableNil(confirm.Service) || !confirm.Rate.Configured())) || (active != nil && (enableNil(active.Service) || !active.Rate.Configured())) || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	verification := confirm != nil || active != nil
	var verifyRate *identityhttp.ChallengeVerificationRateLimiter
	if confirm != nil {
		verifyRate = confirm.Rate
	}
	if active != nil {
		verifyRate = active.Rate
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	writeFailure := func(w http.ResponseWriter, f enableFailure, observation map[string]any) {
		if observation == nil {
			observation = map[string]any{"commitOutcome": "none"}
		}
		if active != nil {
			observation["verified"] = false
		} else if confirm == nil {
			observation["disclosed"] = false
		} else {
			observation["activated"] = false
		}
		observation["error"] = f.code
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(observation)
	}
	classify := func(err error) enableFailure {
		f := enableFailure{status: 503, code: "unavailable"}
		var specific enableFailure
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var busy identity.InProgressError
		switch {
		case errors.As(err, &specific):
			return specific
		case errors.Is(err, identityhttp.ErrInvalidInput):
			f = enableFailure{status: 400, code: "invalid_request"}
		case errors.As(err, &denied):
			f = enableFailure{status: 403, code: "denied"}
		case errors.As(err, &conflict):
			f = enableFailure{status: 409, code: "conflict"}
		case errors.As(err, &busy):
			f = enableFailure{status: 409, code: "in_progress", retry: busy.RetryAfter}
		}
		return f
	}
	reject := func(w http.ResponseWriter, _ *http.Request, err error) { writeFailure(w, classify(err), nil) }
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[uriState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (uriState, error) {
			s := uriState{}
			path := "/v1/mfa/totp-uri"
			if verification {
				path = "/v1/mfa/totp-verify"
				variant := "enrollment"
				if active != nil {
					variant = "step-up"
				}
				count := 0
				for name, values := range r.Header {
					if strings.EqualFold(name, "X-MFA-Variant") {
						count++
						if len(values) != 1 || values[0] != variant {
							return s, identityhttp.ErrInvalidInput
						}
					}
				}
				if count != 1 {
					return s, identityhttp.ErrInvalidInput
				}
			}
			if r.URL.Path != path || r.URL.EscapedPath() != r.URL.Path {
				return s, enableFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, enableFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, enableFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var present bool
			s.bearer, present, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, enableFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			s.origin, err = origins.Check(r)
			if err != nil {
				return s, enableFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(s.bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			fields := 2
			factorField := "enrollmentID"
			if verification {
				fields = 3
				factorField = "factorID"
			}
			if active != nil {
				s.purpose = "identity.mfa.recovery-regenerate"
				if raw, ok := body["purpose"]; ok {
					fields++
					if len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, &s.purpose) != nil {
						return s, identityhttp.ErrInvalidInput
					}
				}
				if !slices.Contains(active.Purposes, s.purpose) {
					return s, identityhttp.ErrInvalidInput
				}
			}
			if err != nil || len(body) != fields {
				return s, identityhttp.ErrInvalidInput
			}
			var command, enrollment string
			for name, dst := range map[string]*string{"commandID": &command, factorField: &enrollment} {
				raw, ok := body[name]
				if !ok || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			s.command, err = identity.ParseCommandID(command)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParseCommandID(enrollment)
			if err != nil || id == s.command {
				return s, identityhttp.ErrInvalidInput
			}
			s.enrollment = mfa.EnrollmentID(id)
			if verification {
				var code string
				if raw, ok := body["code"]; !ok || json.Unmarshal(raw, &code) != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.code, err = auth.NewOneTimeCode(code)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s uriState) (uriState, error) {
			if verification {
				out, err := verifyRate.AdmitIP(r.Context(), s.facts)
				if errors.Is(err, identityhttp.ErrRateLimited) {
					return s, enableFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
				}
				if err != nil || !out.Allowed {
					return s, identityhttp.ErrUnavailable
				}
			}
			read, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !read.Authenticated {
				return s, enableFailure{status: 401, code: "denied"}
			}
			b, err := read.Session.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() || read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.read, s.user = read, b.UserID
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: "identity.mfa.totp-uri", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			s.request = mfa.TotpUriRequest{TenantID: b.TenantID, EnrollmentID: s.enrollment, CommandID: s.command, Session: s.bearer, CSRFToken: s.csrf, Caller: caller, Origin: string(s.origin), Network: s.facts.ClientIP().String()}
			var lifetime time.Duration
			var until time.Time
			if !verification {
				lifetime, until, err = c.Service.TotpUriRateSource(r.Context(), s.request)
			} else {
				caller.Request.Action = "identity.mfa.totp-verify"
				s.confirmation = mfa.TotpVerifyRequest{TenantID: b.TenantID, CommandID: s.command, FactorID: mfa.FactorID(s.enrollment), Code: s.code, Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: s.bearer, CSRFToken: s.csrf}, Caller: caller, Origin: string(s.origin), Network: s.facts.ClientIP().String()}
				if active != nil {
					s.confirmation.Enrollment = nil
					s.confirmation.StepUp = &mfa.TOTPAuthenticatedStepUp{Session: s.bearer, CSRFToken: s.csrf, Purpose: s.purpose}
					lifetime, until, err = active.Service.ActiveStepUpRateSource(r.Context(), s.confirmation)
				} else {
					lifetime, until, err = confirm.Service.EnrollmentConfirmationRateSource(r.Context(), s.confirmation)
				}
			}
			if err != nil {
				return s, err
			}
			if lifetime <= 0 || until.IsZero() || !c.Now().Before(until) || s.read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.until = until
			// Quota uses the authenticated original enrollment interval, never a
			// body-selected lifetime or remaining/renewed expiry.
			s.lifetime = lifetime
			return s, nil
		},
		Admit: func(r *http.Request, s uriState) error {
			var out identityhttp.AuthRateResult
			var err error
			if !verification {
				out, err = c.Rate.AdmitOriginalCommand(r.Context(), s.facts, identityhttp.OriginalCommandSecretRateRequest{OperationID: "identity.mfa.totp-uri", UserID: s.user, CommandID: s.command, ChallengeID: string(s.enrollment), ChallengeLifetime: s.lifetime})
			} else {
				out, err = verifyRate.AdmitChallenge(r.Context(), s.facts, identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.mfa.totp-verify", UserID: s.user, ChallengeID: string(s.enrollment), ChallengeLifetime: s.lifetime})
			}
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return enableFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s uriState) {
			if s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if active != nil {
				result, err := active.Service.TotpVerify(r.Context(), s.confirmation)
				observation := enableObservation(mfa.EnableResult{CommandID: s.command, Outcome: result.Outcome})
				if err != nil || r.Context().Err() != nil {
					writeFailure(w, classify(err), observation)
					return
				}
				proof := result.StepUpProof.Bindings()
				b, bindingErr := s.read.Session.Bindings()
				if result.Outcome != identity.CommitOutcomeCommitted || bindingErr != nil || proof.Proof.ID != auth.ProofID(s.command) || proof.Proof.Tenant != string(s.facts.TenantID()) || proof.Proof.Subject != string(s.user) || proof.Proof.Method != "totp" || proof.Proof.Assurance != auth.AssuranceMultiFactor || proof.Proof.Purpose != s.purpose || proof.Action != string(s.purpose) || proof.SessionID != b.SessionID || proof.SessionVersion != b.Version || !reflect.ValueOf(result.Session).IsZero() || result.CSRFToken != (session.CSRFToken{}) || !reflect.ValueOf(result.Enrollment).IsZero() || s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) || c.Now().Before(proof.Proof.IssuedAt) || !c.Now().Before(proof.Proof.ExpiresAt) {
					writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
					return
				}
				data, err := json.Marshal(map[string]any{"verified": true, "commitOutcome": "committed", "commandID": s.command, "proofID": proof.Proof.ID})
				if err != nil {
					writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
					return
				}
				defer clear(data)
				start := c.Now()
				observation["verified"] = false
				writeSecretJSON(w, r, data, observation, func() bool {
					at := c.Now()
					return !at.Before(start) && at.Before(s.until) && at.Before(proof.Proof.ExpiresAt) && s.read.ValidateAt(at) == nil
				})
				return
			}
			if confirm != nil {
				result, err := confirm.Service.TotpVerify(r.Context(), s.confirmation)
				observation := enableObservation(mfa.EnableResult{CommandID: s.command, Outcome: result.Outcome})
				if err != nil || r.Context().Err() != nil {
					writeFailure(w, classify(err), observation)
					return
				}
				if result.Outcome != identity.CommitOutcomeCommitted || result.Enrollment.ID != s.enrollment || result.Enrollment.FactorMethod != "totp" || result.Enrollment.Version == 0 || !reflect.ValueOf(result.Session).IsZero() || result.CSRFToken != (session.CSRFToken{}) || s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
					writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
					return
				}
				data, err := json.Marshal(map[string]any{"activated": true, "commitOutcome": "committed", "commandID": s.command, "factorID": s.enrollment, "version": result.Enrollment.Version})
				if err != nil {
					writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
					return
				}
				w.WriteHeader(200)
				w.Write(data)
				return
			}
			result, err := c.Service.TotpUri(r.Context(), s.request)
			observation := enableObservation(mfa.EnableResult{CommandID: s.command, Outcome: result.Outcome})
			if err != nil || r.Context().Err() != nil {
				writeFailure(w, classify(err), observation)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.URI.EnrollmentID != s.enrollment && result.URI.URI != "" || len(result.URI.URI) > 8192 {
				writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
				return
			}
			if result.URI.URI == "" {
				writeFailure(w, enableFailure{status: 409, code: "replay"}, observation)
				return
			}
			data, err := json.Marshal(map[string]any{"disclosed": true, "commitOutcome": "committed", "commandID": s.command, "enrollmentID": s.enrollment, "uri": result.URI.URI})
			if err != nil {
				writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
				return
			}
			defer clear(data)
			if r.Context().Err() != nil || s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
				writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
				return
			}
			start := c.Now()
			observation["disclosed"] = false
			writeSecretJSON(w, r, data, observation, func() bool {
				at := c.Now()
				return !at.Before(start) && s.read.ValidateAt(at) == nil && at.Before(s.until)
			})
		},
	})
	if err != nil {
		return nil, err
	}
	return &enablePipeline{pipeline: pipeline}, nil
}
