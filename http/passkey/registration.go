package passkeyhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// RegistrationState retains private original session, synchronizer and action
// custody. Hooks cannot replace requests or manufacture native admission.
// Principal returns metadata only; current owner validity still controls reuse.
type RegistrationState struct{ *registrationState }
type registrationState struct {
	facts        identityhttp.NetworkFacts
	body         requestBody
	key          identity.IdempotencyKey
	bearer       auth.BearerCredential
	csrf         session.CSRFToken
	credential   session.Credential
	read         session.GetResult
	deviceWire   string
	device       session.BrowserDevice
	request      passkey.RegistrationRequest
	proofExpires time.Time
	source       passkey.CeremonyRateSource
}

// Principal returns detached self-user scope from the actual session owner,
// not a validity lease or permission to execute a protected native operation.
func (s RegistrationState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.registrationState == nil || !s.read.Authenticated {
		return "", "", false
	}
	record, err := s.read.Session.Bindings()
	return record.TenantID, record.UserID, err == nil
}
func (RegistrationState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.RegistrationState(redacted)"))
}

// MarshalJSON denies implicit session/action-custody export.
func (RegistrationState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit session/action-custody export.
func (RegistrationState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewRegistrationOptionsHandler selects only authenticated existing-account
// POST /v1/passkey/register-options. A genuine original signed action proof is
// looked up by ID; keyed retries never regenerate an options challenge.
func NewRegistrationOptionsHandler(c RegistrationConfig) (http.Handler, error) {
	return NewRegistrationOptionsHandlerWithMiddleware(c, nil)
}

// NewRegistrationOptionsHandlerWithMiddleware freezes native request custody
// and retains current session/CSRF validity through synchronous trusted hooks.
func NewRegistrationOptionsHandlerWithMiddleware(c RegistrationConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newRegistrationHandler(c, m, false)
}

// NewRegistrationVerifyHandler selects only one-use existing-account
// POST /v1/passkey/register-verify. Its distinct proof and original source must
// authenticate before original challenge rate admission and native mutation.
func NewRegistrationVerifyHandler(c RegistrationConfig) (http.Handler, error) {
	return NewRegistrationVerifyHandlerWithMiddleware(c, nil)
}

// NewRegistrationVerifyHandlerWithMiddleware exposes actual owner phases
// without permitting a hook to replace a proof, response or native transaction.
func NewRegistrationVerifyHandlerWithMiddleware(c RegistrationConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newRegistrationHandler(c, m, true)
}

func newRegistrationHandler(c RegistrationConfig, m []identityhttp.MiddlewareDescriptor, complete bool) (http.Handler, error) {
	if !c.Sessions.Configured() || absent(c.Service) || absent(c.Proofs) || c.PolicyRevision == 0 || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || !visible(c.Audience, 256) || !complete && !c.OptionsRate.Configured() || complete && !c.VerificationRate.Configured() || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 {
		return nil, identityhttp.ErrInvalidInput
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	for index, key := range c.CSRFKeys {
		if key.Version() == 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		for _, prior := range c.CSRFKeys[:index] {
			if key.Version() == prior.Version() {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	i, err := newIngress(c.Network, c.Origin)
	if err != nil {
		return nil, err
	}
	csrfDecoder, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: i.origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil || cookie.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	operation := "register-options"
	if complete {
		operation = "register-verify"
	}
	action := "identity.passkey." + operation
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[RegistrationState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (RegistrationState, error) {
			s := RegistrationState{&registrationState{}}
			facts, body, key, err := i.decode(r, operation, true)
			if err != nil {
				return s, err
			}
			if body.signup || body.sessionEnrollment {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, s.body, s.key = facts, body, key
			bearer, present, err := i.decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.bearer = bearer
			s.csrf, _, err = identityhttp.DecodeCSRF(csrfDecoder, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			device, present, err := i.decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.deviceWire = device.Token()
			return s, nil
		},
		Authenticate: func(r *http.Request, s RegistrationState) (RegistrationState, error) {
			var admission identityhttp.AuthRateResult
			var err error
			if complete {
				admission, err = c.VerificationRate.AdmitIP(r.Context(), s.facts)
			} else {
				admission, err = c.OptionsRate.AdmitPasskeyOptionsIP(r.Context(), s.facts, action)
			}
			if err := rateFailure(admission, err); err != nil {
				return s, err
			}
			s.read, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !s.read.Authenticated {
				return s, failure{status: 401, code: "unauthenticated"}
			}
			if s.read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			record, err := s.read.Session.Bindings()
			if err != nil || record.TenantID != s.facts.TenantID() || record.Audience != c.Audience {
				return s, identityhttp.ErrUnavailable
			}
			binding := session.CSRFBinding{TenantID: record.TenantID, SessionID: record.SessionID, SessionVersion: record.Version}
			matched := false
			for _, key := range c.CSRFKeys {
				if s.read.Session.CSRFState().Check(binding, s.csrf, key) == nil {
					matched = true
					break
				}
			}
			if !matched {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), s.facts.Origin(), s.deviceWire)
			if err != nil {
				return s, failure{status: 403, code: "denied"}
			}
			s.deviceWire = ""
			proof, err := c.Proofs.Reauthentication(r.Context(), auth.ProofID(s.body.proofID))
			if err != nil {
				if errors.Is(err, auth.ErrInvalidProof) {
					return s, failure{status: 403, code: "denied"}
				}
				return s, identityhttp.ErrUnavailable
			}
			p := proof.Proof
			if p.Proof.ID != auth.ProofID(s.body.proofID) || p.Proof.Tenant != string(record.TenantID) || p.Proof.Subject != string(record.UserID) || p.SessionID != record.SessionID || p.SessionVersion != record.Version || p.Action != action || p.Proof.Purpose != "identity.password.verify" {
				return s, failure{status: 403, code: "denied"}
			}
			s.proofExpires = p.Proof.ExpiresAt
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(correlation), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(record.UserID)}, Tenant: authorization.TenantID(record.TenantID), Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
			s.request = passkey.RegistrationRequest{Primary: password.ActionPrimaryRequest{TenantID: record.TenantID, Session: s.bearer, Proof: p, Caller: caller, CSRFToken: s.csrf}, Origin: string(c.Origin), Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()}
			if complete {
				s.request.Primary.CommandID = identity.CommandID(s.body.commandID)
				s.source, err = c.Service.RegistrationRateSource(r.Context(), passkey.RegistrationCeremonyRateRequest{RegistrationRequest: s.request, CeremonyID: s.body.ceremonyID})
				if err != nil {
					return s, domainFailure(err)
				}
				if s.source.CeremonyID != s.body.ceremonyID || s.source.Kind != passkey.RateSourceUser || s.source.UserID != record.UserID || s.source.Identifier != "" || s.source.AnonymousFlowID != "" || s.source.Lifetime != 5*time.Minute {
					return s, identityhttp.ErrUnavailable
				}
			}
			requestDelivery(r).valid = func() bool { return registrationFresh(c, s) }
			return s, nil
		},
		Admit: func(r *http.Request, s RegistrationState) error {
			if !registrationFresh(c, s) {
				return identityhttp.ErrUnavailable
			}
			if !complete {
				return nil
			}
			return rateFailure(c.VerificationRate.AdmitChallenge(r.Context(), s.facts, identityhttp.ChallengeVerificationRateRequest{OperationID: action, UserID: s.source.UserID, ChallengeID: s.source.CeremonyID, ChallengeLifetime: s.source.Lifetime}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s RegistrationState) {
			if !registrationFresh(c, s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if complete {
				out, err := c.Service.Register(r.Context(), passkey.RegistrationCompletion{RegistrationRequest: s.request, CeremonyID: s.body.ceremonyID, Response: s.body.response, Label: s.body.label})
				if err != nil {
					rejectNative(w, r, err)
					return
				}
				verified, ok := out.Context()
				credential, has := out.Credential()
				if !ok || !has || verified.Command.CommandID != s.request.Primary.CommandID || verified.Command.TenantID != s.request.Primary.TenantID || verified.Command.UserID != s.source.UserID || verified.CeremonyID != s.body.ceremonyID || verified.Origin != string(c.Origin) || !verified.UserPresent || !verified.UserVerified || credential.TenantID != s.request.Primary.TenantID || credential.UserID != s.source.UserID {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				requestDelivery(r).observeCommitted(verified.Command.CommandID)
				requestDelivery(r).render(w, r, map[string]any{"registered": true, "commandID": s.request.Primary.CommandID, "commitOutcome": "committed"}, func() bool {
					return registrationFresh(c, s) && c.Now().Before(s.proofExpires) && c.Now().Before(verified.ExpiresAt)
				})
				return
			}
			out, err := c.Service.KeyedRegistrationOptions(r.Context(), passkey.KeyedRegistrationOptionsRequest{RegistrationRequest: s.request, IdempotencyKey: s.key})
			if err != nil {
				rejectNative(w, r, err)
				return
			}
			if out.Receipt.Validate() != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.CommandID != out.Receipt.Binding.CommandID || out.Receipt.Binding.TenantID != s.request.Primary.TenantID || out.Receipt.Binding.UserID != identity.UserID(s.request.Primary.Caller.Request.Subject.ID) || out.Receipt.Binding.ActorID != identity.ActorID(out.Receipt.Binding.UserID) || out.Receipt.Binding.ActorKind != authorization.SubjectUser || out.Receipt.Binding.OperationID != action {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response := optionsResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}
			requestDelivery(r).observeCommitted(out.CommandID)
			valid := func() bool { return registrationFresh(c, s) }
			if !out.Replayed {
				ceremony, ok := out.Options.Ceremony()
				if !ok || ceremony.ID != string(out.CommandID) || ceremony.Intent.Context.TenantID != s.facts.TenantID() || ceremony.Intent.Context.UserID != out.Receipt.Binding.UserID || ceremony.Intent.Origin != string(c.Origin) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				valid = func() bool {
					return registrationFresh(c, s) && c.Now().Before(s.proofExpires) && c.Now().Before(ceremony.ExpiresAt)
				}
				if err := out.Options.TransferJSON(r.Context(), func(_ context.Context, wire []byte) error {
					if len(wire) == 0 || len(wire) > 262144 {
						return identityhttp.ErrUnavailable
					}
					response.Options = append([]byte(nil), wire...)
					return nil
				}); err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
			}
			requestDelivery(r).render(w, r, response, valid)
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: c.MaximumDuration}, nil
}
func registrationFresh(c RegistrationConfig, s RegistrationState) bool {
	return s.registrationState != nil && s.read.ValidateAt(c.Now()) == nil && c.Now().Before(s.device.ExpiresAt())
}
