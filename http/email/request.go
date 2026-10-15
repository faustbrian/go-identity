package emailhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// RequestConfig selects a cookie-authenticated self-service delivered-link
// request. Set exactly Verification/DeliveryRate or Change/SecretRate. Change
// additionally requires explicit NotifyCurrentAddress policy. Proofs reads the
// original signed password-verification record; the native service separately
// authenticates its signature, original cookie/CSRF possession and current
// transactional authority. Retain proof records through keyed input retention.
// Historical retry discovery precedes mutable session lookup: this transport
// never creates or renews a session lease. Native admission owns fresh work.
// Network, origin and positive policy revision are trusted startup input.
// All owners are borrowed, bounded and concurrent-safe. MaximumDuration is
// 1ms..30s; earlier cancellation wins. Construction performs no IO.
type RequestConfig struct {
	Network                   identityhttp.NetworkConfig
	Proofs                    auth.ReauthenticationSource
	Verification              email.VerificationSendService
	Change                    email.ChangeRequestService
	DeliveryRate              *identityhttp.AuthRateLimiter
	SecretRate                *identityhttp.KeyedSecretRateLimiter
	Cookie                    session.CookiePolicy
	Origin                    identityhttp.Origin
	CurrentAddressProofPolicy email.CurrentAddressProofPolicy
	PolicyRevision            authorization.Revision
	MaximumDuration           time.Duration
}

// RequestResponse is credential-free original request metadata. Queued means
// committed local intent, never sent, verified, primary-changed or signed in.
// Unknown is not rollback. It contains no mailbox, user, proof, session or
// replacement command. Native typed recovery is separate; no recovery route or
// automatic retry is enabled. Retry the exact original key/input after ambiguity.
type RequestResponse struct {
	Queued        bool               `json:"queued"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	DeliveryState string             `json:"deliveryState,omitempty"`
	Error         string             `json:"error,omitempty"`
}

type requestAttemptKey struct{}

func requestAttempt(r *http.Request) *RequestResponse {
	if r != nil {
		if out, ok := r.Context().Value(requestAttemptKey{}).(*RequestResponse); ok && out != nil {
			return out
		}
	}
	return &RequestResponse{CommitOutcome: "none"}
}

type requestState struct {
	facts       identityhttp.NetworkFacts
	primary     email.RequestPrimary
	proofID     auth.ProofID
	address     email.AddressInput
	addressID   identity.IdentifierID
	callback    url.URL
	key         identity.IdempotencyKey
	caller      authorization.DecisionContext
	user        identity.UserID
	destination string
}

// NewVerificationSendHandler selects POST /v1/email/verification-send. Add
// requires proofID/address/callback; pending resend additionally supplies exact
// addressID and may omit address. Exactly one cookie, Origin, X-CSRF-Token and
// Idempotency-Key are required. Identity/policy overrides, bearer alternatives,
// query/trailers and duplicate/unknown fields deny. The native source authenticates
// original possession before shared delivery admission and one native request.
func NewVerificationSendHandler(c RequestConfig) (http.Handler, error) {
	return newRequestHandler(c, nil, false)
}

// NewChangeRequestHandler selects POST /v1/email/change-request with closed
// proofID/newAddress/callback JSON and the same cookie/origin/key rules. It
// applies canonical keyed secret admission before the native pending request.
// Body-selected old-proof/session policies, primary swaps and auto-login deny.
func NewChangeRequestHandler(c RequestConfig) (http.Handler, error) {
	return newRequestHandler(c, nil, true)
}

func newRequestHandler(c RequestConfig, m []identityhttp.MiddlewareDescriptor, change bool) (http.Handler, error) {
	if nilService(c.Proofs) || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	action, path := "identity.email.verification-send", "/v1/email/verification-send"
	if change {
		action, path = "identity.email.change-request", "/v1/email/change-request"
		if nilService(c.Change) || !nilService(c.Verification) || !c.SecretRate.Configured() || c.DeliveryRate != nil || c.CurrentAddressProofPolicy != email.NotifyCurrentAddress {
			return nil, identityhttp.ErrInvalidInput
		}
	} else if nilService(c.Verification) || !nilService(c.Change) || !c.DeliveryRate.Configured() || c.SecretRate != nil || c.CurrentAddressProofPolicy != 0 {
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
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	asSend := func(s requestState) email.VerificationSendRequest {
		return email.VerificationSendRequest{TenantID: s.facts.TenantID(), Address: s.address, AddressID: s.addressID, Callback: s.callback, IdempotencyKey: s.key, Primary: s.primary, Caller: s.caller, Network: s.facts.ClientIP().String()}
	}
	asChange := func(s requestState) email.ChangeRequestRequest {
		return email.ChangeRequestRequest{TenantID: s.facts.TenantID(), NewAddress: s.address, Callback: s.callback, IdempotencyKey: s.key, Primary: s.primary, Caller: s.caller, Network: s.facts.ClientIP().String(), CurrentAddressProofPolicy: c.CurrentAddressProofPolicy}
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		out := requestAttempt(r)
		out.Queued = false
		out.DeliveryState = ""
		f := failure{503, "unavailable", 0}
		if errors.Is(err, identityhttp.ErrInvalidInput) || errors.Is(err, email.ErrInvalidVerification) {
			f = failure{400, "invalid_request", 0}
		}
		var specific failure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(f.retry, time.Hour)+time.Second-1)/time.Second), 10))
		}
		out.Error = f.code
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[requestState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (s requestState, err error) {
			if r.URL.Path != path || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{404, "not_found", 0}
			}
			if r.Method != http.MethodPost {
				return s, failure{405, "method_not_allowed", 0}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{421, "misdirected_request", 0}
			}
			if facts.Scheme() != "https" {
				return s, failure{403, "https_required", 0}
			}
			s.facts = facts
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			token, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(token.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.primary.Session = token
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.key = key
			s.primary.CSRFToken, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{403, "origin_or_csrf_denied", 0}
			}
			fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var id, address, callback, target string
			addressField := "address"
			if change {
				addressField = "newAddress"
			}
			for name := range fields {
				if name != "proofID" && name != "callback" && name != addressField && (change || name != "addressID") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			if !readString(fields, "proofID", &id) || !readString(fields, "callback", &callback) || len(callback) > 2048 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseCommandID(id); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.proofID = auth.ProofID(id)
			if _, ok := fields["addressID"]; ok {
				if change || !readString(fields, "addressID", &target) {
					return s, identityhttp.ErrInvalidInput
				}
				s.addressID, err = identity.ParseIdentifierID(target)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			if raw, ok := fields[addressField]; ok {
				if string(raw) == "null" || json.Unmarshal(raw, &address) != nil || address == "" || len(address) > 4096 {
					return s, identityhttp.ErrInvalidInput
				}
			} else if change || s.addressID == "" {
				return s, identityhttp.ErrInvalidInput
			}
			parsed, err := url.Parse(callback)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.callback = *parsed
			s.address = email.AddressInput(address)
			return s, nil
		},
		Authenticate: func(r *http.Request, s requestState) (requestState, error) {
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if r.Context().Err() != nil || err != nil && !errors.Is(err, auth.ErrInvalidProof) {
				return s, identityhttp.ErrUnavailable
			}
			if err != nil || record.Proof.Proof.ID != s.proofID || record.Proof.Proof.Tenant != string(s.facts.TenantID()) || len(record.Proof.Proof.Subject) == 0 || len(record.Proof.Proof.Subject) > 128 {
				return s, failure{403, "denied", 0}
			}
			s.primary.Proof = record.Proof
			s.user = identity.UserID(record.Proof.Proof.Subject)
			s.caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(s.facts.TenantID()), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.user)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(s.user)}}}
			var user identity.UserID
			var destination string
			if change {
				request := asChange(s)
				if request.Validate() != nil {
					return s, identityhttp.ErrInvalidInput
				}
				user, destination, err = c.Change.ChangeRequestRateSource(r.Context(), request)
			} else {
				request := asSend(s)
				if request.Validate() != nil {
					return s, identityhttp.ErrInvalidInput
				}
				user, destination, err = c.Verification.VerificationSendRateSource(r.Context(), request)
			}
			if r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			if err != nil {
				return s, requestOwnerFailure(err)
			}
			if user != s.user || destination == "" || len(destination) > 4096 {
				return s, identityhttp.ErrUnavailable
			}
			s.destination = destination
			return s, nil
		},
		Admit: func(r *http.Request, s requestState) error {
			var out identityhttp.AuthRateResult
			var err error
			if change {
				out, err = c.SecretRate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: action, UserID: s.user, IdempotencyKey: s.key})
			} else {
				out, err = c.DeliveryRate.Admit(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: action, Identifier: s.destination, UserID: s.user})
			}
			return rateFailure(out, err)
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s requestState) {
			out := requestAttempt(r)
			out.CommitOutcome = "unknown"
			var result email.VerificationSendResult
			var err error
			if change {
				value, e := c.Change.ChangeRequest(r.Context(), asChange(s))
				result, err = email.VerificationSendResult(value), e
			} else {
				result, err = c.Verification.VerificationSend(r.Context(), asSend(s))
			}
			if result.CommandID != "" {
				if _, e := identity.ParseCommandID(string(result.CommandID)); e == nil {
					out.CommandID = result.CommandID
				}
			}
			if result.Outcome != identity.CommitOutcomeInvalid {
				out.CommitOutcome = outcome(result.Outcome)
			}
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome != identity.CommitOutcomeInvalid && result.Validate() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome == identity.CommitOutcomeInProgress {
				reject(w, r, failure{409, "in_progress", result.RetryAfter})
				return
			}
			if result.Outcome == identity.CommitOutcomeConflict {
				reject(w, r, failure{409, "conflict", 0})
				return
			}
			if err != nil {
				reject(w, r, requestOwnerFailure(err))
				return
			}
			if result.Outcome == identity.CommitOutcomeUnknown {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.DeliveryState != delivery.StateQueued || result.AddressID == "" {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out.Queued, out.DeliveryState = true, "queued"
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &confirmationPipeline{pipeline: &emailRequestPipeline{pipeline: pipeline}}, nil
}

func requestOwnerFailure(err error) error {
	var denied identity.ForbiddenError
	var conflict identity.ConflictError
	if errors.As(err, &conflict) {
		return failure{409, "conflict", 0}
	}
	if errors.As(err, &denied) || errors.Is(err, auth.ErrInvalidProof) || errors.Is(err, email.ErrInvalidVerification) {
		return failure{403, "denied", 0}
	}
	return identityhttp.ErrUnavailable
}

type emailRequestPipeline struct{ pipeline http.Handler }

func (p *emailRequestPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), requestAttemptKey{}, &RequestResponse{CommitOutcome: "none"}))
	p.pipeline.ServeHTTP(w, r)
}
func (p *emailRequestPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &emailRequestPipeline{pipeline: h}, nil
}

// Format redacts borrowed proof, session and rate configuration.
func (RequestConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("emailhttp.RequestConfig(redacted)"))
}

// MarshalJSON refuses implicit configuration export.
func (RequestConfig) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText refuses implicit text export.
func (RequestConfig) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// LogValue returns a constant redacted marker.
func (RequestConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.RequestConfig(redacted)")
}
func (requestState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("emailhttp.requestState(redacted)"))
}
func (requestState) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
func (requestState) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
func (requestState) LogValue() slog.Value {
	return slog.StringValue("emailhttp.requestState(redacted)")
}
