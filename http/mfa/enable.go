package mfahttp

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
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

// EnableConfig selects native cookie enrollment, without registering a route.
// Borrowed owners must share native authority and honor bounded contexts. Rate
// is shared across requests. Policy and exact HTTPS origins are startup inputs;
// clients cannot select a method, subject, proof projection or recovery count.
// Now must be prompt and concurrency-safe; MaximumDuration is 1ms..30s.
type EnableConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Proofs          auth.ReauthenticationSource
	Enrollment      mfa.EnrollmentService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	FactorPolicy    mfa.FactorPolicy
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format prevents diagnostic traversal of borrowed owners and policy.
func (EnableConfig) Format(s fmt.State, _ rune) { io.WriteString(s, "mfahttp.EnableConfig(redacted)") }

// MarshalJSON denies implicit configuration export.
func (EnableConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit text export.
func (EnableConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue returns only a fixed marker.
func (EnableConfig) LogValue() slog.Value { return slog.StringValue("mfahttp.EnableConfig(redacted)") }

type enableState struct {
	facts      identityhttp.NetworkFacts
	bearer     auth.BearerCredential
	credential session.Credential
	csrf       session.CSRFToken
	key        identity.IdempotencyKey
	proofID    auth.ProofID
	read       session.GetResult
	user       identity.UserID
}

func (enableState) Format(s fmt.State, _ rune)   { io.WriteString(s, "mfahttp.enableState(redacted)") }
func (enableState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (enableState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (enableState) LogValue() slog.Value         { return slog.StringValue("mfahttp.enableState(redacted)") }

type enableFailure struct {
	status      int
	code        string
	retry       time.Duration
	observation map[string]any
}

func (f enableFailure) Error() string { return "identity.http.mfa.enable." + f.code }

// NewEnableHandler owns POST /v1/mfa/enable. Closed JSON accepts only proofID;
// exactly one Idempotency-Key, session cookie, Origin and X-CSRF-Token are
// required. Authorization, query, trailers and alternate paths are rejected.
// Enable creates pending enrollment, not an active factor or a new session.
// Recovery codes are explicit first-known-commit output, never retry output.
func NewEnableHandler(c EnableConfig) (http.Handler, error) {
	return NewEnableHandlerWithMiddleware(c, nil)
}

// NewEnableHandlerWithMiddleware binds hooks to actual decode, original session
// read, shared rate admission and native mutation phases. Original validity is
// rechecked after waits; no cached evidence receives a new freshness window.
func NewEnableHandlerWithMiddleware(c EnableConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || enableNil(c.Proofs) || enableNil(c.Enrollment) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.FactorPolicy.Validate() != nil || c.FactorPolicy.Method != "totp" || c.FactorPolicy.RequireUserVerification || c.FactorPolicy.AllowTrustedDevice {
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
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
		f := enableFailure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			f = enableFailure{status: 400, code: "invalid_request"}
		}
		var specific enableFailure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		w.WriteHeader(f.status)
		out := f.observation
		if out == nil {
			out = map[string]any{"commitOutcome": "none"}
		}
		out["enabled"], out["active"], out["error"] = false, false, f.code
		_ = json.NewEncoder(w).Encode(out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[enableState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (enableState, error) {
			s := enableState{}
			if r.URL.Path != "/v1/mfa/enable" || r.URL.EscapedPath() != r.URL.Path {
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
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.key = key
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.bearer, present, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
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
			if err != nil || len(body) != 1 {
				return s, identityhttp.ErrInvalidInput
			}
			var id string
			raw, ok := body["proofID"]
			if !ok || json.Unmarshal(raw, &id) != nil || !enableText(id, 22, 128) {
				return s, identityhttp.ErrInvalidInput
			}
			s.proofID = auth.ProofID(id)
			return s, nil
		},
		Authenticate: func(r *http.Request, s enableState) (enableState, error) {
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
			s.read = read
			s.user = b.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s enableState) error {
			out, err := c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.mfa.enable", UserID: s.user, IdempotencyKey: s.key})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return enableFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || s.read.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s enableState) {
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
				reject(w, r, enableFailure{status: 403, code: "denied"})
				return
			}
			b, err := s.read.Session.Bindings()
			if err != nil || s.read.ValidateAt(c.Now()) != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.user)}, Tenant: authorization.TenantID(s.facts.TenantID()), Action: "identity.mfa.enable", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(s.user)}}}
			request := mfa.EnableRequest{TenantID: s.facts.TenantID(), FactorPolicy: c.FactorPolicy, PrimaryProof: b.Authentication.Proof, Reauthentication: record.Proof, Session: s.bearer, CSRFToken: s.csrf, IdempotencyKey: s.key, Caller: caller, Network: s.facts.ClientIP().String()}
			result, err := c.Enrollment.Enable(r.Context(), request)
			defer func() {
				for _, code := range result.RecoveryMaterial.Codes {
					code.Destroy()
				}
			}()
			// Observation is not success or authority. Preserve the original
			// command locator on ambiguous/error outcomes without projecting any
			// pending-factor or secret material into their response.
			resultReject := func(f enableFailure) {
				f.observation = enableObservation(result)
				reject(w, r, f)
			}
			if err != nil {
				var denied identity.ForbiddenError
				var conflict identity.ConflictError
				var busy identity.InProgressError
				switch {
				case errors.As(err, &denied):
					resultReject(enableFailure{status: 403, code: "denied"})
				case errors.As(err, &conflict):
					resultReject(enableFailure{status: 409, code: "conflict"})
				case errors.As(err, &busy):
					resultReject(enableFailure{status: 409, code: "in_progress", retry: busy.RetryAfter})
				default:
					resultReject(enableFailure{status: 503, code: "unavailable"})
				}
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || !enableText(string(result.CommandID), 1, 128) || !enableText(string(result.Enrollment.ID), 1, 128) || result.Enrollment.FactorMethod != "totp" || result.Enrollment.Version == 0 || result.Enrollment.ExpiresAt.IsZero() || len(result.RecoveryMaterial.Codes) != 0 && len(result.RecoveryMaterial.Codes) != int(c.FactorPolicy.RecoveryCodes) {
				resultReject(enableFailure{status: 503, code: "unavailable"})
				return
			}
			out := map[string]any{"enabled": true, "active": false, "commitOutcome": "committed", "commandID": result.CommandID, "enrollmentID": result.Enrollment.ID, "factorMethod": "totp", "expiresAt": result.Enrollment.ExpiresAt, "version": result.Enrollment.Version}
			data, err := json.Marshal(out)
			if err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			// Reserve the bounded worst-case quoted output before borrowing secrets,
			// so appends cannot leave superseded plaintext backing arrays behind.
			buffer := make([]byte, len(data), len(data)+len(result.RecoveryMaterial.Codes)*1540+32)
			copy(buffer, data)
			clear(data)
			data = buffer
			defer func() { clear(data[:cap(data)]) }()
			if len(result.RecoveryMaterial.Codes) > 0 {
				data = data[:len(data)-1]
				data = append(data, `,"recoveryCodes":[`...)
				for i, code := range result.RecoveryMaterial.Codes {
					if i > 0 {
						data = append(data, ',')
					}
					if code.Len() > 256 || code.Use(func(raw []byte) error {
						if !enableText(string(raw), 1, 256) {
							return identityhttp.ErrInvalidInput
						}
						data = strconv.AppendQuote(data, string(raw))
						return nil
					}) != nil {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
				}
				data = append(data, ']', '}')
			}
			if r.Context().Err() != nil || s.read.ValidateAt(c.Now()) != nil {
				resultReject(enableFailure{status: 503, code: "unavailable"})
				return
			}
			data = append(data, '\n')
			if len(result.RecoveryMaterial.Codes) == 0 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				return
			}
			start := c.Now()
			observation := enableObservation(result)
			observation["enabled"], observation["active"] = false, false
			writeSecretJSON(w, r, data, observation, func() bool {
				at := c.Now()
				return !at.Before(start) && at.Before(result.Enrollment.ExpiresAt) && s.read.ValidateAt(at) == nil
			})
		},
	})
	if err != nil {
		return nil, err
	}
	return &enablePipeline{pipeline: pipeline}, nil
}

func enableObservation(r mfa.EnableResult) map[string]any {
	name := "none"
	switch r.Outcome {
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
	}
	out := map[string]any{"commitOutcome": name}
	if name != "none" && enableText(string(r.CommandID), 1, 128) {
		out["commandID"] = r.CommandID
		// The native result may precede preparation recovery and omit factor
		// identity. Never invent the record scope required by RecoverEnable;
		// retry must retain the original request key and proof custody.
	}
	return out
}

func enableNil(v any) bool {
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
func enableText(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

type enablePipeline struct{ pipeline http.Handler }

func (p *enablePipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &enablePipeline{pipeline: h}, nil
}
func (p *enablePipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	custody := &secretCommit{}
	r = r.WithContext(context.WithValue(r.Context(), secretCommitKey{}, custody))
	protect := func() {
		for name := range w.Header() {
			if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Location") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) {
			protect()
			if custody.fresh != nil {
				w.Header().Del("Content-Length")
				if status >= 200 && status == http.StatusOK && !custody.valid(r) {
					status = http.StatusServiceUnavailable
				}
			}
			if status >= 200 && custody.status == 0 {
				custody.status = status
			}
			next(status)
		}
	}, Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(data []byte) (int, error) { protect(); return custody.write(r, data, next) }
	}, Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { protect(); next() } }, ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
		return func(reader io.Reader) (int64, error) {
			protect()
			return custody.readFrom(r, reader, w.Write, next)
		}
	}})
	p.pipeline.ServeHTTP(writer, r)
}
