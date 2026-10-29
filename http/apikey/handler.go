package apikeyhttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/felixge/httpsnoop"
)

const maximumResponseBytes = 131072

type createBody struct {
	OrganizationID apikey.OrganizationID `json:"organizationID,omitempty"`
	Name           string                `json:"name"`
	Permissions    *[]string             `json:"permissions"`
	ExpiresAt      time.Time             `json:"expiresAt"`
}
type mutationBody struct {
	KeyID           apikey.KeyID `json:"keyID"`
	ExpectedVersion uint64       `json:"expectedVersion"`
}
type input struct {
	action        string
	facts         identityhttp.NetworkFacts
	auth          apikey.Authentication
	key           identity.IdempotencyKey
	create        createBody
	mutation      mutationBody
	update        updateBody
	observed      session.GetResult
	actor         identity.UserID
	organizations bool
}

func (in *input) createRequest() apikey.CreateRequest {
	var permissions []string
	if in.create.Permissions != nil {
		permissions = *in.create.Permissions
	}
	return apikey.CreateRequest{Authentication: in.auth, IdempotencyKey: in.key, Name: in.create.Name, Permissions: permissions, ExpiresAt: in.create.ExpiresAt, Network: in.facts.ClientIP().String()}
}
func (in *input) rotation() apikey.Rotation {
	return apikey.Rotation{Authentication: in.auth, IdempotencyKey: in.key, KeyID: in.mutation.KeyID, ExpectedVersion: in.mutation.ExpectedVersion, Network: in.facts.ClientIP().String()}
}

type failure struct {
	status int
	code   string
	retry  time.Duration
}

func (f failure) Error() string { return "apikeyhttp: " + f.code }
func failureOf(err error) failure {
	f := failure{status: 503, code: "unavailable"}
	var specific failure
	var invalid identity.InvalidInputError
	var conflict identity.ConflictError
	var unauthorized identity.ForbiddenError
	switch {
	case errors.As(err, &specific):
		return specific
	case errors.Is(err, apikey.ErrInvalid), errors.Is(err, identityhttp.ErrInvalidInput), errors.As(err, &invalid):
		return failure{status: 400, code: "invalid_request"}
	case errors.Is(err, apikey.ErrDenied), errors.As(err, &unauthorized):
		return failure{status: 403, code: "forbidden"}
	case errors.As(err, &conflict):
		return failure{status: 409, code: "conflict"}
	}
	return f
}
func reject(w http.ResponseWriter, _ *http.Request, err error) {
	f := failureOf(err)
	if f.status == 405 {
		w.Header().Set("Allow", "POST")
	}
	if f.retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((f.retry+time.Second-1)/time.Second), 10))
	}
	writeJSON(w, f.status, struct {
		Error string `json:"error"`
	}{f.code})
}

func newHandler(c Config, action string, network *identityhttp.NetworkResolver, decoder *identityhttp.RequestDecoder, organizations bool) (http.Handler, error) {
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[*input]{MaximumDuration: c.MaximumDuration,
		Decode: func(r *http.Request) (*input, error) {
			if r == nil || r.URL == nil {
				return nil, identityhttp.ErrInvalidInput
			}
			path := "/v1/apikey/" + action
			if r.URL.Path != path || r.URL.RawPath != "" || r.URL.EscapedPath() != path {
				return nil, failure{status: 404, code: "not_found"}
			}
			if r.Method != "POST" {
				return nil, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery {
				return nil, identityhttp.ErrInvalidInput
			}
			key, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			bearer, _, err := decoder.Bearer(r, identityhttp.HeaderRequired)
			if err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(bearer.Token()); err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return nil, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return nil, identityhttp.ErrInvalidInput
			}
			in := &input{action: action, facts: facts, auth: apikey.Authentication{TenantID: facts.TenantID(), Bearer: bearer}, key: key, organizations: organizations}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			field := func(name string, target any) error {
				value, present := body[name]
				if !present || string(value) == "null" {
					return identityhttp.ErrInvalidInput
				}
				return json.Unmarshal(value, target)
			}
			if action == "create" {
				fields := 3
				if _, present := body["organizationID"]; present {
					if !organizations || field("organizationID", &in.create.OrganizationID) != nil || in.create.OrganizationID == "" {
						return nil, identityhttp.ErrInvalidInput
					}
					fields++
				}
				if len(body) != fields || field("name", &in.create.Name) != nil || field("permissions", &in.create.Permissions) != nil || field("expiresAt", &in.create.ExpiresAt) != nil || in.create.Permissions == nil {
					return nil, identityhttp.ErrInvalidInput
				}
				err = in.createRequest().Validate()
				if in.create.OrganizationID != "" {
					err = (apikey.OrganizationCreateRequest{CreateRequest: in.createRequest(), OrganizationID: in.create.OrganizationID}).Validate()
				}
			} else if action == "update" {
				fields := 4
				if _, present := body["organizationID"]; present {
					if !organizations || field("organizationID", &in.update.OrganizationID) != nil || in.update.OrganizationID == "" {
						return nil, identityhttp.ErrInvalidInput
					}
					fields++
				}
				if len(body) != fields || field("keyID", &in.mutation.KeyID) != nil || field("expectedVersion", &in.mutation.ExpectedVersion) != nil || field("name", &in.update.Name) != nil || field("permissions", &in.update.Permissions) != nil || in.update.Permissions == nil {
					return nil, identityhttp.ErrInvalidInput
				}
				err = in.updateRequest().Validate()
			} else {
				if len(body) != 2 || field("keyID", &in.mutation.KeyID) != nil || field("expectedVersion", &in.mutation.ExpectedVersion) != nil {
					return nil, identityhttp.ErrInvalidInput
				}
				err = in.rotation().Validate()
			}
			if err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			return in, nil
		},
		Authenticate: func(r *http.Request, in *input) (*input, error) {
			token, _ := session.ParseToken(in.auth.Bearer.Token())
			credential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return nil, identityhttp.ErrInvalidInput
			}
			observed, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: in.auth.TenantID, Credential: credential})
			if err != nil {
				return nil, identityhttp.ErrUnavailable
			}
			b, bindErr := observed.Session.Bindings()
			if !observed.Authenticated || observed.ValidateAt(c.Now()) != nil || bindErr != nil || b.TenantID != in.auth.TenantID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" || b.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || observed.Session.CSRFState() != (session.CSRFState{}) {
				return nil, failure{status: 403, code: "forbidden"}
			}
			in.observed, in.actor = observed, b.UserID
			return in, nil
		},
		Admit: func(r *http.Request, in *input) error {
			out, err := c.SecretRate.Admit(r.Context(), in.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.apikey." + action, UserID: in.actor, IdempotencyKey: in.key})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return failure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || in.observed.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, in *input) {
			if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if action == "update" {
				result, err := c.Updater.Update(r.Context(), in.updateRequest())
				writeUpdate(w, r, in, result, err, c.Now)
				return
			}
			if action == "delete" {
				result, err := c.Revoker.Revoke(r.Context(), apikey.Revocation(in.rotation()))
				if result.Binding == (identity.CommandBinding{}) {
					reject(w, r, nonNil(err, identityhttp.ErrUnavailable))
					return
				}
				status, out := projectReceipt(in, result, err)
				writeJSON(w, status, out)
				return
			}
			var result apikey.IssuanceResult
			var err error
			if action == "create" {
				if in.create.OrganizationID != "" {
					result, err = c.OrganizationCreator.CreateOrganization(r.Context(), apikey.OrganizationCreateRequest{CreateRequest: in.createRequest(), OrganizationID: in.create.OrganizationID})
				} else {
					result, err = c.Creator.Create(r.Context(), in.createRequest())
				}
			} else {
				result, err = c.Rotator.Rotate(r.Context(), in.rotation())
			}
			receipt, receiptErr := result.Receipt()
			if receiptErr != nil {
				reject(w, r, nonNil(err, identityhttp.ErrUnavailable))
				return
			}
			status, out := projectReceipt(in, receipt, err)
			if out.Committed {
				record, ok := result.Record()
				if !ok || record.ID != apikey.KeyID(receipt.Binding.RecordID) || !in.matchesOwner(record.Owner) || action == "rotate" && record.PreviousID != in.mutation.KeyID {
					writeJSON(w, 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"})
					return
				}
				out.Key = &keyView{ID: record.ID, Version: record.Version, Name: record.Name, Permissions: append([]string{}, record.Grant...), ExpiresAt: record.ExpiresAt}
				// A receipt is historical outcome, not renewed response authority.
				// Only invocation-local committed custody may disclose, once.
				if err == nil && r.Context().Err() == nil && in.observed.ValidateAt(c.Now()) == nil {
					secret, revealErr := result.Reveal()
					if revealErr == nil {
						out.Secret = secret
					}
				}
			}
			writeJSON(w, status, out)
		}, Reject: reject,
	})
	if err != nil {
		return nil, err
	}
	return &protectedHandler{pipeline: pipeline}, nil
}

func (in *input) matchesOwner(owner apikey.Owner) bool {
	o := owner.Spec()
	if o.TenantID != in.auth.TenantID {
		return false
	}
	if o.Kind == apikey.OwnerOrganization {
		return in.organizations && o.UserID == "" && o.OrganizationID != "" && (in.action != "create" || in.create.OrganizationID == o.OrganizationID)
	}
	return o.Kind == apikey.OwnerUser && o.UserID == in.actor && in.create.OrganizationID == ""
}

func nonNil(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

type keyView struct {
	ID          apikey.KeyID `json:"id"`
	Version     uint64       `json:"version"`
	Name        string       `json:"name"`
	Permissions []string     `json:"permissions"`
	ExpiresAt   time.Time    `json:"expiresAt"`
}
type recoveryScope struct {
	CommandID   identity.CommandID        `json:"commandID"`
	TenantID    identity.TenantID         `json:"tenantID"`
	UserID      identity.UserID           `json:"userID"`
	ActorID     identity.ActorID          `json:"actorID"`
	ActorKind   authorization.SubjectKind `json:"actorKind"`
	OperationID string                    `json:"operationID"`
	RecordID    string                    `json:"recordID"`
}
type commandResponse struct {
	Committed     bool               `json:"committed"`
	CommitOutcome string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	Recovery      *recoveryScope     `json:"recovery,omitempty"`
	Key           *keyView           `json:"key,omitempty"`
	Secret        string             `json:"secret,omitempty"`
	Error         string             `json:"error,omitempty"`
}

func projectReceipt(in *input, r identity.CommandResult, err error) (int, commandResponse) {
	if r.Binding == (identity.CommandBinding{}) {
		f := failureOf(nonNil(err, identityhttp.ErrUnavailable))
		return f.status, commandResponse{CommitOutcome: "none", Error: f.code}
	}
	b := r.Binding
	orgSchema := "apikey-" + in.action + "-organization-v1"
	if in.action == "delete" {
		orgSchema = "apikey-revoke-organization-v1"
	}
	if b.SchemaID == orgSchema && !in.organizations || in.action == "create" && (b.SchemaID == orgSchema) != (in.create.OrganizationID != "") || in.action == "update" && (b.SchemaID != "apikey-update-v1" && b.SchemaID != orgSchema || (b.SchemaID == orgSchema) != (in.update.OrganizationID != "")) {
		return 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"}
	}
	if r.Validate() != nil || b.TenantID != in.auth.TenantID || b.UserID != in.actor || b.ActorID != identity.ActorID(in.actor) || b.ActorKind != authorization.SubjectUser || b.OperationID != "identity.apikey."+in.action || b.AnonymousFlowID != "" || b.LinkMode != 0 || r.Feature == nil || r.Feature.Operation.Owner != "identity/apikey" || (in.action == "delete" || in.action == "update") && b.RecordID != string(in.mutation.KeyID) {
		return 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"}
	}
	if _, parseErr := apikey.ParseKeyID(b.RecordID); parseErr != nil {
		return 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"}
	}
	if in.action == "update" {
		op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		if r.Feature.Operation != op || b.ValidateFor(op) != nil {
			return 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"}
		}
	}
	if r.Outcome == identity.CommitOutcomeCommitted {
		// Native creation/rotation issues a distinct version1 credential;
		// revocation must advance the exact requested existing version.
		before := uint64(0)
		if in.action == "delete" || in.action == "update" {
			before = in.mutation.ExpectedVersion
		}
		if r.Feature.BeforeVersion != before || r.Feature.AfterVersion != before+1 {
			return 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"}
		}
	}
	out := commandResponse{CommandID: b.CommandID, Recovery: &recoveryScope{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}}
	status := 200
	if err != nil {
		f := failureOf(err)
		status, out.Error = f.status, f.code
	}
	switch r.Outcome {
	case identity.CommitOutcomeCommitted:
		out.Committed, out.CommitOutcome = true, "committed"
	case identity.CommitOutcomeNotCommitted:
		out.CommitOutcome = "not_committed"
		if err == nil {
			status, out.Error = 503, "unavailable"
		}
	case identity.CommitOutcomeConflict:
		status, out.CommitOutcome, out.Error = 409, "conflict", "conflict"
	case identity.CommitOutcomeInProgress:
		status, out.CommitOutcome, out.Error = 409, "in_progress", "in_progress"
	case identity.CommitOutcomeUnknown:
		status, out.CommitOutcome, out.Error = 503, "unknown", "unavailable"
	default:
		return 503, commandResponse{CommitOutcome: "unknown", Error: "unavailable"}
	}
	return status, out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > maximumResponseBytes {
		status, body = 503, []byte(`{"error":"unavailable"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

type protectedHandler struct{ pipeline http.Handler }

func (p *protectedHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &protectedHandler{pipeline: h}, nil
}
func (p *protectedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	protect := func() {
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(name, http.TrailerPrefix) {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) { protect(); next(status) }
	}, Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(body []byte) (int, error) { protect(); return next(body) }
	}, ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
		return func(reader io.Reader) (int64, error) { protect(); return next(reader) }
	}, Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { protect(); next() } }})
	p.pipeline.ServeHTTP(writer, r)
}
