package passwordhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// SignupService is the borrowed native signup/recovery owner with the frozen
// creation address parser exposed for initial rate input. Normalization reads
// no account or flow and grants no execution authority. Signup independently
// validates original custody and owns keyed atomic effects. Implementations
// must honor bounded contexts and concurrent calls; no transport store is used.
type SignupService interface {
	password.SignupService
	SignupRateSource(context.Context, password.SignupAddressInput) (string, error)
}

// SignupConfig selects the required-email-verification browser profile. It
// never issues a session; selecting an incompatible native result denies
// delivery without erasing known commitment. Match FieldSchema, origin,
// callback, lifetime and remember defaults to native startup/pre-auth policy.
// FieldSchema permits shape only; native field authorization remains mandatory.
// Service and Rate are borrowed concurrent-safe owners. Now is prompt and
// concurrent-safe. MaximumDuration is 1ms..30s; earlier deadlines win.
type SignupConfig struct {
	Network         identityhttp.NetworkConfig
	Service         SignupService
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	CallbackURL     string
	Lifetime        session.LifetimeConfig
	FlowCookie      session.CookiePolicy
	Device          session.BrowserDeviceConfig
	FieldSchema     identity.AttributeSchema
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime configuration.
func (SignupConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.SignupConfig(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (SignupConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit configuration export.
func (SignupConfig) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (SignupConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.SignupConfig(redacted)")
}

// SignupResponse is enumeration-safe original command metadata, never an
// account, address, password, retry key or session. VerificationRequired means
// selected policy, not account existence. Recovery grants no permission.
type SignupResponse struct {
	VerificationRequired bool               `json:"verificationRequired"`
	CommitOutcome        string             `json:"commitOutcome"`
	CommandID            identity.CommandID `json:"commandID,omitempty"`
	Recovery             *SignupRecovery    `json:"recovery,omitempty"`
	Replayed             bool               `json:"replayed"`
	Error                string             `json:"error,omitempty"`
}

// SignupRecovery carries password-free original correlation for direct native
// recovery. Neither it nor knowledge of a retry key authorizes disclosure.
type SignupRecovery struct {
	CommandID identity.CommandID            `json:"commandID"`
	TenantID  identity.TenantID             `json:"tenantID"`
	FlowID    identity.PreAuthTransactionID `json:"flowID"`
	ActorID   identity.ActorID              `json:"actorID"`
	ActorKind authorization.SubjectKind     `json:"actorKind"`
}

// NewSignupHandler selects POST /v1/password/signup with exact original flow
// and signed browser-device cookies, mapped HTTPS tenant/Origin and exactly one
// Idempotency-Key header. Closed JSON requires flowID, email, password and
// callbackURL; optional remember and allowedFields use the selected schema.
// Trusted IP admission precedes native normalization and identifier admission,
// then one keyed Signup call. No automatic retry, flow refresh, account lookup,
// bearer/cookie issuance or credential output occurs, including on replay.
func NewSignupHandler(c SignupConfig) (http.Handler, error) {
	return NewSignupHandlerWithMiddleware(c, nil)
}

// NewSignupHandlerWithMiddleware binds frozen typed owner phases. Hooks may
// observe safe attempt metadata, but cannot replace original input/key custody,
// manufacture credentials or retain request-local sensitive state.
func NewSignupHandlerWithMiddleware(c SignupConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSignupHandler(c, m, false)
}

func newSignupHandler(c SignupConfig, m []identityhttp.MiddlewareDescriptor, usernameProfile bool) (http.Handler, error) {
	action, route := "identity.password.signup", "/v1/password/signup"
	if usernameProfile {
		action, route = "identity.username.signup", "/v1/username/signup"
	}
	if nilOwner(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.FieldSchema.Validate() != nil || len(c.CallbackURL) > 2048 {
		return nil, identityhttp.ErrInvalidInput
	}
	if c.CallbackURL != "" {
		u, err := url.Parse(c.CallbackURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || strings.Contains(c.CallbackURL, "#") || !visible(c.CallbackURL, 1, 2048) {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	fields := signupInputFields(c.FieldSchema)
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
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err = session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID, correlation string) authorization.DecisionContext {
		return authorization.DecisionContext{CorrelationID: correlation, PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(tenant), Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(action)}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := signupAttemptFor(r)
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
		a.out.Error = f.code
		writeSignupResponse(w, f.status, a.out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SignupState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (SignupState, error) {
			s := SignupState{attempt: signupAttemptFor(r)}
			if r.URL.Path != route || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, failure{status: 403, code: "https_required"}
			}
			if _, err = origin.Check(r); err != nil {
				return s, failure{status: 403, code: "origin_denied"}
			}
			bearer, present, err := decoder.CookieBearer(r, flow.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			device, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), device.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range body {
				switch name {
				case "flowID", "email", "password", "callbackURL", "remember", "allowedFields":
				case "username":
					if !usernameProfile {
						return s, identityhttp.ErrInvalidInput
					}
				default:
					return s, identityhttp.ErrInvalidInput
				}
			}
			var flowID, address, value, callback string
			for name, dst := range map[string]*string{"flowID": &flowID, "email": &address, "password": &value, "callbackURL": &callback} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			var username string
			if usernameProfile {
				raw, ok := body["username"]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, &username) != nil || len(username) == 0 || len(username) > 128 {
					return s, identityhttp.ErrInvalidInput
				}
			}
			choice := session.RememberDefault
			if raw, ok := body["remember"]; ok {
				var v bool
				if string(raw) == "null" || json.Unmarshal(raw, &v) != nil {
					return s, identityhttp.ErrInvalidInput
				}
				choice = session.BrowserSession
				if v {
					choice = session.PersistentSession
				}
			}
			updates, err := decodeSignupFields(body["allowedFields"], fields)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParsePreAuthTransactionID(flowID)
			if err != nil || callback != c.CallbackURL || len(value) == 0 || len(value) > 1<<20 {
				return s, identityhttp.ErrInvalidInput
			}
			input := password.SignupAddressInput(address)
			if input.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			remember, err := session.ResolveRememberPolicy(choice, c.Lifetime)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			raw := []byte(value)
			secret, err := primitive.NewSecret(raw)
			clear(raw)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.attempt.secret = secret
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.request = password.SignupRequest{TenantID: facts.TenantID(), PreAuthID: id, Cookie: bearer, Email: input, Username: username, Password: secret, AllowedFields: updates, RememberPolicy: remember, Origin: string(c.Origin), CallbackURL: callback, Caller: caller(facts.TenantID(), string(correlation)), Network: facts.ClientIP().String(), Device: s.device.DeviceID(), IdempotencyKey: key}
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			return s, nil
		},
		Authenticate: func(r *http.Request, s SignupState) (SignupState, error) {
			if err := signinRateError(c.Rate.AdmitSignupIP(r.Context(), s.facts, action)); err != nil {
				return s, err
			}
			canonical, err := c.Service.SignupRateSource(r.Context(), s.request.Email)
			if err != nil || r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.identifier = canonical
			return s, nil
		},
		Admit: func(r *http.Request, s SignupState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return signinRateError(c.Rate.AdmitSignupIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: action, Identifier: s.identifier}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SignupState) {
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a := s.attempt
			a.attempted = true
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.Signup(r.Context(), s.request)
			if result.Validate() != nil {
				// Key correlation can reject changed intent before an original
				// recovery receipt is authorized. Classify the native conflict,
				// but never invent or project a command from the error value.
				var conflict identity.ConflictError
				if errors.As(err, &conflict) && r.Context().Err() == nil {
					reject(w, r, failure{status: 409, code: "conflict"})
					return
				}
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			q, flow, e := result.Recovery.Bindings()
			if e != nil || q.OperationID != action || flow != s.request.PreAuthID || q.TenantID != s.request.TenantID || q.UserID != "" || q.AnonymousFlowID != string(flow) || q.ActorID != c.ActorID || q.ActorKind != authorization.SubjectServiceAccount {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommandID = q.CommandID
			a.out.CommitOutcome = signinOutcome(result.Outcome)
			a.out.Replayed = result.Replayed
			a.out.Recovery = &SignupRecovery{q.CommandID, q.TenantID, flow, q.ActorID, q.ActorKind}
			if err != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			switch result.Outcome {
			case identity.CommitOutcomeConflict:
				reject(w, r, failure{status: 409, code: "conflict"})
				return
			case identity.CommitOutcomeInProgress:
				reject(w, r, failure{status: 409, code: "in_progress", retry: result.RetryAfter})
				return
			case identity.CommitOutcomeNotCommitted:
				reject(w, r, failure{status: 403, code: "denied"})
				return
			case identity.CommitOutcomeCommitted:
				if result.VerificationRequired && result.SubjectID == "" && result.SessionID == "" && result.Session.CommandID == "" {
					a.out.VerificationRequired = true
					writeSignupResponse(w, 200, a.out)
					return
				}
			}
			reject(w, r, identityhttp.ErrUnavailable)
		},
	})
	if err != nil {
		return nil, err
	}
	return &signupPipeline{pipeline}, nil
}

func signupInputFields(schema identity.AttributeSchema) map[string]identity.AttributeKind {
	fields := make(map[string]identity.AttributeKind)
	for _, f := range schema.Fields {
		if f.InputPermission == identity.FieldWrite || f.InputPermission == identity.FieldReadWrite {
			fields[f.Name] = f.Kind
		}
	}
	return fields
}

// Closed tagged values avoid floating point conversion and distinguish absent
// values from explicit false, zero, empty strings and allocated empty lists.
func decodeSignupFields(raw json.RawMessage, fields map[string]identity.AttributeKind) ([]identity.AttributeUpdate, error) {
	if raw == nil {
		return nil, nil
	}
	if string(raw) == "null" {
		return nil, identityhttp.ErrInvalidInput
	}
	var wire []map[string]json.RawMessage
	if json.Unmarshal(raw, &wire) != nil || len(wire) > 64 {
		return nil, identityhttp.ErrInvalidInput
	}
	out := make([]identity.AttributeUpdate, 0, len(wire))
	for _, item := range wire {
		var name string
		var kind identity.AttributeKind
		if len(item) != 3 || json.Unmarshal(item["name"], &name) != nil || json.Unmarshal(item["kind"], &kind) != nil || kind == "" || fields[name] != kind || item["value"] == nil || string(item["value"]) == "null" {
			return nil, identityhttp.ErrInvalidInput
		}
		v := identity.AttributeValue{Kind: kind, Scalar: identity.AttributeScalar{Kind: kind}}
		var err error
		switch kind {
		case identity.AttributeString:
			err = json.Unmarshal(item["value"], &v.Scalar.String)
		case identity.AttributeBool:
			err = json.Unmarshal(item["value"], &v.Scalar.Bool)
		case identity.AttributeInt64:
			err = json.Unmarshal(item["value"], &v.Scalar.Int64)
		case identity.AttributeTime:
			if len(item["value"]) > 66 {
				return nil, identityhttp.ErrInvalidInput
			}
			err = json.Unmarshal(item["value"], &v.Scalar.Time)
		case identity.AttributeStringList:
			var list []string
			err = json.Unmarshal(item["value"], &list)
			if len(list) > 64 {
				return nil, identityhttp.ErrInvalidInput
			}
			v.Scalar = identity.AttributeScalar{}
			v.List = make([]identity.AttributeScalar, len(list))
			for i, s := range list {
				v.List[i] = identity.AttributeScalar{Kind: identity.AttributeString, String: s}
			}
		default:
			err = identityhttp.ErrInvalidInput
		}
		if err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		out = append(out, identity.AttributeUpdate{Name: name, Value: v})
	}
	return out, nil
}
