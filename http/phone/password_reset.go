package phonehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

// PasswordResetRisk borrows the phone owner's exact original-scope evaluation.
// Implementations authenticate browser/grant custody, derive actual account and
// carrier scope, and preserve original evidence/expiry on retry without renewed
// provider work. A caller-supplied user, risk verdict or carrier fact is forbidden.
type PasswordResetRisk interface {
	EvaluatePasswordResetRequestRisk(context.Context, phone.PasswordResetInitiationRiskRequest) (risk.PhoneEvidenceResult, error)
	EvaluatePasswordResetCompletionRisk(context.Context, phone.PasswordResetCompletionRiskRequest) (risk.PhoneEvidenceResult, error)
}

// PasswordResetSource authenticates the original grant, browser and trusted
// current disclosure policy before subject/challenge budgets. Duration is the
// immutable issued SMS interval, not remaining or renewed validity. Reads must
// work after their own completion for original replay, grant no mutation authority
// and perform no code comparison, debit, issuance, hashing or provider work.
type PasswordResetSource interface {
	PasswordResetCompletionRateSource(context.Context, capability.Proof, otp.SendFlow, authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error)
}

// PasswordResetConfig explicitly selects no-session phone/password recovery.
// Service owns independent confirmed TOTP, canonical capability, SMS, HIBP and
// atomic replacement/revocation; construction does not enable a weaker fallback.
// All owners/clocks are borrowed and concurrency-safe. NumberPolicy is copied.
// Cookie must be the original __Host-identity_flow profile; Device is the same
// deployment-signed browser profile used at initiation. Exact HTTPS Origin, not
// a session synchronizer, protects both operations. MaximumDuration is 1ms..30s;
// earlier inbound deadlines win. Construction performs no IO/provider work.
type PasswordResetConfig struct {
	Network         identityhttp.NetworkConfig
	Service         phone.PasswordResetService
	Risk            PasswordResetRisk
	Source          PasswordResetSource
	NumberPolicy    *phone.NumberPolicy
	DeliveryRate    *identityhttp.AuthRateLimiter
	CompletionRate  *identityhttp.ChallengeVerificationRateLimiter
	Cookie          session.CookiePolicy
	Origin          identityhttp.Origin
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// PasswordResetResponse is credential-free selected transport metadata.
// Accepted is ONLY a public request acknowledgment, never proof that an account
// exists, work committed or SMS was sent. Its CommandID is the client attempt,
// not a private server-owned request command. Completed/SessionsRevoked and the
// successor version occur only for a known successful completion. Unknown is not
// rollback. Reset never issues a session, clears a cookie or authenticates a user.
type PasswordResetResponse struct {
	Accepted          bool               `json:"accepted,omitempty"`
	Completed         bool               `json:"completed,omitempty"`
	CommandID         identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome     string             `json:"commitOutcome,omitempty"`
	CredentialVersion uint64             `json:"credentialVersion,omitempty"`
	SessionsRevoked   bool               `json:"sessionsRevoked,omitempty"`
	Error             string             `json:"error,omitempty"`
}

type passwordResetInput struct {
	facts             identityhttp.NetworkFacts
	device            session.BrowserDevice
	flow              otp.SendFlow
	command, issuance identity.CommandID
	key               identity.IdempotencyKey
	number            phone.Number
	phoneCode, totp   auth.OneTimeCode
	caller            authorization.DecisionContext
	token             string
	rate              identityhttp.ChallengeVerificationRateRequest
}

// Closure custody prevents enclosing middleware diagnostics from traversing raw
// tokens/codes or original target fields. No state is authority outside this call.
type passwordResetState struct{ read func() *passwordResetInput }
type passwordResetAttempt struct {
	out      PasswordResetResponse
	password primitive.Secret
	proof    capability.Proof
}
type passwordResetAttemptKey struct{}

func passwordResetAttemptFor(r *http.Request) *passwordResetAttempt {
	if a, ok := r.Context().Value(passwordResetAttemptKey{}).(*passwordResetAttempt); ok {
		return a
	}
	return &passwordResetAttempt{}
}

// NewPasswordResetRequestHandler selects POST /v1/phone/password-reset-request.
// Closed JSON contains commandID, riskIssuanceCommandID, flowID and number; one
// header Idempotency-Key is mandatory. Keep all original IDs/cookies on retries.
// Every valid rate-admitted submission receives the same acknowledgment shape,
// independent of recipient eligibility or native/provider result. This cannot
// be used as delivery, commitment or recovery evidence.
func NewPasswordResetRequestHandler(c PasswordResetConfig) (http.Handler, error) {
	return newPasswordResetHandler(c, false, nil)
}

// NewPasswordResetCompleteHandler selects explicit POST
// /v1/phone/password-reset-complete. Closed JSON contains commandID,
// riskIssuanceCommandID, flowID, token, phoneCode, totpCode and newPassword.
// Idempotency-Key is forbidden; the original command and complete immutable
// conjunction identify native replay. GET/link scanning cannot complete reset.
func NewPasswordResetCompleteHandler(c PasswordResetConfig) (http.Handler, error) {
	return newPasswordResetHandler(c, true, nil)
}

func newPasswordResetHandler(c PasswordResetConfig, complete bool, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || nilOwner(c.Risk) || nilOwner(c.Source) || c.NumberPolicy == nil || c.NumberPolicy.Profile() != phone.CurrentNumberProfile() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || !complete && !c.DeliveryRate.Configured() || complete && !c.CompletionRate.Configured() {
		return nil, identityhttp.ErrInvalidInput
	}
	policy := *c.NumberPolicy
	c.NumberPolicy = &policy
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil || cookie.Name != "__Host-identity_flow" {
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
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	path, action := "/v1/phone/password-reset-request", authorization.Action("identity.phone.password-reset-request")
	if complete {
		path, action = "/v1/phone/password-reset-complete", "identity.phone.password-reset-complete"
	}
	caller := func(tenant identity.TenantID, command identity.CommandID) authorization.DecisionContext {
		return authorization.DecisionContext{CorrelationID: string(command), PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: action, Resource: authorization.Resource{Type: "identity.user"}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	write := func(w http.ResponseWriter, r *http.Request, status int) {
		wire, err := json.Marshal(passwordResetAttemptFor(r).out)
		if err != nil || len(wire) > 4096 {
			status, wire = 503, []byte(`{"error":"unavailable"}`)
		}
		w.WriteHeader(status)
		_, _ = w.Write(append(wire, '\n'))
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		f := failure{503, "unavailable", 0}
		var specific failure
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var invalid identity.InvalidInputError
		switch {
		case errors.As(err, &specific):
			f = specific
		case errors.As(err, &denied):
			f = failure{403, "denied", 0}
		case errors.As(err, &conflict):
			f = failure{409, "conflict", 0}
		case errors.As(err, &invalid), errors.Is(err, identityhttp.ErrInvalidInput), errors.Is(err, phone.ErrInvalidPasswordReset), errors.Is(err, phone.ErrNumberInvalid):
			f = failure{400, "invalid_request", 0}
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		a := passwordResetAttemptFor(r)
		a.out.Accepted, a.out.Completed, a.out.SessionsRevoked, a.out.CredentialVersion = false, false, false, 0
		a.out.Error = f.code
		write(w, r, f.status)
	}
	p, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[passwordResetState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (passwordResetState, error) {
			s := &passwordResetInput{}
			state := passwordResetState{read: func() *passwordResetInput { return s }}
			if r.URL.Path != path || r.URL.EscapedPath() != r.URL.Path {
				return state, failure{404, "not_found", 0}
			}
			if r.Method != http.MethodPost {
				return state, failure{405, "method_not_allowed", 0}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return state, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return state, identityhttp.ErrInvalidInput
				}
			}
			keyPolicy := identityhttp.HeaderRequired
			if complete {
				keyPolicy = identityhttp.HeaderForbidden
			}
			var err error
			s.key, _, err = decoder.IdempotencyKey(r, keyPolicy)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant {
				return state, failure{421, "misdirected_request", 0}
			}
			if s.facts.Scheme() != "https" {
				return state, failure{403, "https_required", 0}
			}
			if _, err = origins.Check(r); err != nil {
				return state, failure{403, "origin_denied", 0}
			}
			browser, _, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return state, failure{403, "denied", 0}
			}
			if _, err = session.ParseToken(browser.Token()); err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			device, _, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), string(c.Origin), device.Token())
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			var flowID, number, code, totp, value string
			members := map[string]any{"commandID": &s.command, "riskIssuanceCommandID": &s.issuance, "flowID": &flowID}
			if complete {
				members["token"], members["phoneCode"], members["totpCode"], members["newPassword"] = &s.token, &code, &totp, &value
			} else {
				members["number"] = &number
			}
			if !closedFields(fields, members) {
				return state, identityhttp.ErrInvalidInput
			}
			if _, err = identity.ParseCommandID(string(s.command)); err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			if _, err = identity.ParseCommandID(string(s.issuance)); err != nil || s.issuance == s.command {
				return state, identityhttp.ErrInvalidInput
			}
			if _, err = identity.ParsePreAuthTransactionID(flowID); err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.flow, err = otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(flowID), browser)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.caller = caller(s.facts.TenantID(), s.command)
			if !complete {
				s.number, err = c.NumberPolicy.Canonicalize(r.Context(), number)
				if err != nil {
					return state, identityhttp.ErrInvalidInput
				}
				return state, nil
			}
			if len(s.token) < 32 || len(s.token) > 4096 || len(code) > 128 || len(totp) > 128 || len(value) == 0 || len(value) > 1<<20 {
				return state, identityhttp.ErrInvalidInput
			}
			s.phoneCode, err = auth.NewOneTimeCode(code)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.totp, err = auth.NewOneTimeCode(totp)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			raw := []byte(value)
			secret, err := primitive.NewSecret(raw)
			clear(raw)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			passwordResetAttemptFor(r).password = secret
			return state, nil
		},
		Authenticate: func(r *http.Request, state passwordResetState) (passwordResetState, error) {
			s := state.read()
			if !complete {
				return state, rateError(c.DeliveryRate.AdmitDeliveryIP(r.Context(), s.facts, string(action)))
			}
			if err := rateError(c.CompletionRate.AdmitIP(r.Context(), s.facts)); err != nil {
				return state, err
			}
			limits := capability.DefaultLimits()
			limits.MaxTokenBytes = 4096
			proof, err := capability.ParseProof(s.token, limits)
			s.token = ""
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			passwordResetAttemptFor(r).proof = proof
			user, credential, challenge, lifetime, err := c.Source.PasswordResetCompletionRateSource(r.Context(), proof, s.flow, s.caller)
			if err != nil {
				return state, err
			}
			if _, err = identity.ParseIdentifierID(string(credential)); err != nil {
				return state, identityhttp.ErrUnavailable
			}
			s.rate = identityhttp.ChallengeVerificationRateRequest{OperationID: string(action), UserID: user, ChallengeID: challenge, ChallengeLifetime: lifetime}
			return state, nil
		},
		Admit: func(r *http.Request, state passwordResetState) error {
			s := state.read()
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			if complete {
				return rateError(c.CompletionRate.AdmitChallenge(r.Context(), s.facts, s.rate))
			}
			number, err := s.number.Record()
			if err != nil {
				return identityhttp.ErrInvalidInput
			}
			return rateError(c.DeliveryRate.AdmitDeliveryIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: string(action), Identifier: number.E164}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state passwordResetState) {
			s := state.read()
			a := passwordResetAttemptFor(r)
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if !complete {
				// Phone's product contract requires enumeration-safe outcomes. Once
				// public transport/rate admission succeeds, neither eligibility nor
				// risk/provider/domain failures may change the acknowledgment. No
				// commitment, private request ID or delivery result is projected.
				input, err := phone.NewPasswordResetInitiationRiskRequest(phone.PasswordResetInitiationRiskRequestSpec{TenantID: s.facts.TenantID(), CommandID: s.command, IssuanceCommandID: s.issuance, Number: s.number, Flow: s.flow, Caller: s.caller, Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()})
				if err != nil {
					reject(w, r, identityhttp.ErrInvalidInput)
					return
				}
				attemptPasswordResetRequest(r.Context(), c, s, input)
				a.out = PasswordResetResponse{Accepted: true, CommandID: s.command}
				write(w, r, 202)
				return
			}
			riskRequest, err := phone.NewPasswordResetCompletionRiskRequest(phone.PasswordResetCompletionRiskRequestSpec{TenantID: s.facts.TenantID(), CommandID: s.command, IssuanceCommandID: s.issuance, Flow: s.flow, ResetCapability: a.proof, Caller: s.caller, Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()})
			if err != nil {
				reject(w, r, identityhttp.ErrInvalidInput)
				return
			}
			evaluated, err := c.Risk.EvaluatePasswordResetCompletionRisk(r.Context(), riskRequest)
			if err != nil {
				reject(w, r, err)
				return
			}
			// The actual native owner, not transport, distinguishes fresh
			// consumption from exact terminal receipt replay. Do not renew old
			// evidence or deny historical resolution merely because it aged.
			if !passwordResetEvidenceForPurpose(evaluated, "phone-password-reset-complete") {
				reject(w, r, identity.ForbiddenError{})
				return
			}
			input, err := phone.NewPasswordResetCompleteRequest(phone.PasswordResetCompleteRequestSpec{TenantID: s.facts.TenantID(), CommandID: s.command, Flow: s.flow, ResetCapability: a.proof, PhoneCode: s.phoneCode, IndependentTOTP: s.totp, RiskEvidence: evaluated.Evidence.Reference, RiskIssuanceCommandID: s.issuance, NewPassword: a.password, Caller: s.caller, Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()})
			if err != nil {
				reject(w, r, identityhttp.ErrInvalidInput)
				return
			}
			a.out.CommandID, a.out.CommitOutcome = s.command, "unknown"
			result, err := c.Service.PasswordResetComplete(r.Context(), input)
			if result != (phone.PasswordResetCompleteResult{}) {
				if result.Validate() != nil || result.CommandID != s.command {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				a.out.CommitOutcome = outcome(result.Outcome)
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			switch result.Outcome {
			case identity.CommitOutcomeCommitted:
				a.out.Completed, a.out.SessionsRevoked, a.out.CredentialVersion = true, result.SessionsRevoked, result.CredentialVersion
				write(w, r, 200)
			case identity.CommitOutcomeConflict:
				reject(w, r, failure{409, "conflict", 0})
			case identity.CommitOutcomeInProgress:
				reject(w, r, failure{409, "in_progress", time.Second})
			default:
				reject(w, r, identityhttp.ErrUnavailable)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	return &passwordResetHandler{pipeline: p}, nil
}

func passwordResetRiskAdmitted(r risk.PhoneEvidenceResult, purpose string, now time.Time) bool {
	e := r.Evidence
	return !now.IsZero() && passwordResetEvidenceForPurpose(r, purpose) && !e.IssuedAt.After(now) && e.ExpiresAt.After(now)
}

func passwordResetEvidenceForPurpose(r risk.PhoneEvidenceResult, purpose string) bool {
	e := r.Evidence
	return r.Outcome == risk.EvidenceCommitted && e.Purpose == purpose && e.Reference.Reveal() != "" && e.MaxUses == 1 && !e.IssuedAt.IsZero() && e.ExpiresAt.After(e.IssuedAt)
}

// The public acknowledgment deliberately reveals no account-dependent native
// result, including provider panics. This catches only the private attempt, never
// transport writes or middleware. Actual native owners still fail closed.
func attemptPasswordResetRequest(ctx context.Context, c PasswordResetConfig, s *passwordResetInput, input phone.PasswordResetInitiationRiskRequest) {
	defer func() { _ = recover() }()
	evaluated, err := c.Risk.EvaluatePasswordResetRequestRisk(ctx, input)
	if err != nil || !passwordResetRiskAdmitted(evaluated, "phone-password-reset-initiate", c.Now()) {
		return
	}
	request, err := phone.NewPasswordResetRequestRequest(phone.PasswordResetRequestRequestSpec{TenantID: s.facts.TenantID(), CommandID: s.command, Number: s.number, Flow: s.flow, RiskEvidence: evaluated.Evidence.Reference, RiskIssuanceCommandID: s.issuance, IdempotencyKey: s.key, Caller: s.caller, Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()})
	if err == nil {
		_, _ = c.Service.PasswordResetRequest(ctx, request)
	}
}

type passwordResetHandler struct{ pipeline http.Handler }

func (h *passwordResetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	a := &passwordResetAttempt{}
	defer func() {
		a.password.Destroy()
		_ = a.proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	}()
	r = r.WithContext(context.WithValue(r.Context(), passwordResetAttemptKey{}, a))
	h.pipeline.ServeHTTP(w, r)
}
func (h *passwordResetHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	p, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &passwordResetHandler{pipeline: p}, nil
}
func (PasswordResetConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.PasswordResetConfig(redacted)"))
}
func (PasswordResetConfig) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (PasswordResetConfig) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (passwordResetState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.passwordResetState(redacted)"))
}
func (passwordResetState) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (passwordResetState) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
