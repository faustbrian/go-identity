package passkeyhttp

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// SignupState retains immutable private original-flow request custody. It
// authenticates no user; hooks cannot select a prospective identity, alter
// native requests, acquire response secrets or renew validity.
type SignupState struct{ *signupState }
type signupState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	request    passkey.SignupRequest
	deviceWire string
	device     session.BrowserDevice
	started    time.Time
	source     passkey.CeremonyRateSource
}

func (SignupState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SignupState(redacted)"))
}

// MarshalJSON prohibits implicit original-flow custody export.
func (SignupState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit original-flow custody export.
func (SignupState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSignupOptionsHandler selects the explicit signup variant of canonical
// POST /v1/passkey/register-options. Keyed retry is native-owned and metadata-
// only; no user or session is created before genuine completion.
func NewSignupOptionsHandler(c SignupConfig) (http.Handler, error) {
	return NewSignupOptionsHandlerWithMiddleware(c, nil)
}

// NewSignupOptionsHandlerWithMiddleware exposes real bounded owner phases.
func NewSignupOptionsHandlerWithMiddleware(c SignupConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSignupHandler(c, m, false)
}

// NewSignupVerifyHandler selects the explicit original-flow signup variant of
// POST /v1/passkey/register-verify. Only fresh acknowledged native commitment
// can deliver the original issued session cookie and synchronizer once.
func NewSignupVerifyHandler(c SignupConfig) (http.Handler, error) {
	return NewSignupVerifyHandlerWithMiddleware(c, nil)
}

// NewSignupVerifyHandlerWithMiddleware retains synchronous secret custody.
func NewSignupVerifyHandlerWithMiddleware(c SignupConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSignupHandler(c, m, true)
}

func newSignupHandler(c SignupConfig, middleware []identityhttp.MiddlewareDescriptor, complete bool) (http.Handler, error) {
	if absent(c.Service) || !complete && !c.OptionsRate.Configured() || complete && !c.VerificationRate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || !visible(c.Audience, 256) {
		return nil, identityhttp.ErrInvalidInput
	}
	i, err := newIngress(c.Network, c.Origin)
	if err != nil {
		return nil, err
	}
	flowCookie, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flowCookie.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil || cookie.Name == flowCookie.Name || cookie.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, err
	}
	operation := "register-options"
	if complete {
		operation = "register-verify"
	}
	action := "identity.passkey." + operation
	caller := func(tenant identity.TenantID, flow identity.PreAuthTransactionID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(tenant), Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow)}}}
	}
	if caller("configuration", "configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SignupState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (SignupState, error) {
			var s SignupState
			facts, body, key, err := i.decode(r, operation, false)
			if err != nil {
				return s, err
			}
			if !body.signup {
				return s, identityhttp.ErrInvalidInput
			}
			// Pre-auth signup has no session branch. Ambient session custody is
			// rejected rather than silently downgrading an enrollment attempt.
			if _, _, err := i.decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			flow, present, err := i.decoder.CookieBearer(r, flowCookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			device, present, err := i.decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			token, err := session.ParseToken(flow.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s = SignupState{&signupState{facts: facts, body: body, key: key, deviceWire: device.Token(), request: passkey.SignupRequest{FlowID: identity.PreAuthTransactionID(body.flowID), Cookie: token, Origin: string(c.Origin), Network: facts.ClientIP().String()}}}
			if complete {
				s.request.CommandID, s.request.CorrelationID = identity.CommandID(body.commandID), body.commandID
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s SignupState) (SignupState, error) {
			s.started = c.Now()
			if s.started.IsZero() {
				return s, identityhttp.ErrUnavailable
			}
			var admitted identityhttp.AuthRateResult
			var err error
			if complete {
				admitted, err = c.VerificationRate.AdmitIP(r.Context(), s.facts)
			} else {
				admitted, err = c.OptionsRate.AdmitPasskeyOptionsIP(r.Context(), s.facts, action)
			}
			if err := rateFailure(admitted, err); err != nil {
				return s, err
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), s.facts.Origin(), s.deviceWire)
			if err != nil {
				return s, failure{status: 403, code: "denied"}
			}
			s.deviceWire, s.request.Device = "", s.device.DeviceID()
			if complete {
				s.source, err = c.Service.SignupRateSource(r.Context(), passkey.SignupCeremonyRateRequest{SignupRequest: s.request, CeremonyID: s.body.ceremonyID})
				if err != nil {
					return s, domainFailure(err)
				}
				if s.source.Kind != passkey.RateSourceAnonymousFlow || s.source.AnonymousFlowID != s.request.FlowID || s.source.CeremonyID != s.body.ceremonyID || s.source.Lifetime != 5*time.Minute || s.source.UserID != "" || s.source.Identifier != "" {
					return s, identityhttp.ErrUnavailable
				}
			}
			requestDelivery(r).valid = func() bool { return signupFresh(c, s) }
			return s, nil
		},
		Admit: func(r *http.Request, s SignupState) error {
			if !signupFresh(c, s) {
				return identityhttp.ErrUnavailable
			}
			if !complete {
				return nil
			}
			return rateFailure(c.VerificationRate.AdmitPasskeySignupChallenge(r.Context(), s.facts, identityhttp.PasskeySignupVerificationRateRequest{AnonymousFlowID: s.source.AnonymousFlowID, ChallengeID: s.source.CeremonyID, ChallengeLifetime: s.source.Lifetime}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SignupState) {
			if !signupFresh(c, s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if complete {
				out, err := c.Service.Signup(r.Context(), passkey.SignupCompletion{SignupRequest: s.request, CeremonyID: s.body.ceremonyID, Response: s.body.response, Label: s.body.label})
				if err != nil {
					rejectNative(w, r, err)
					return
				}
				deliverPasskeySession(w, r, authenticationDelivery{tenant: s.facts.TenantID(), command: s.request.CommandID, audience: c.Audience, cookie: c.SessionCookie, now: c.Now, fresh: func() bool { return signupFresh(c, s) }}, out.Session, out.CSRF, false, true)
				return
			}
			out, err := c.Service.KeyedSignupOptions(r.Context(), passkey.KeyedSignupOptionsRequest{SignupRequest: s.request, IdempotencyKey: s.key, Caller: caller(s.facts.TenantID(), s.request.FlowID)})
			if err != nil {
				rejectNative(w, r, err)
				return
			}
			b := out.Receipt.Binding
			if out.Receipt.Validate() != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.CommandID != b.CommandID || b.TenantID != s.facts.TenantID() || b.AnonymousFlowID != string(s.request.FlowID) || b.ActorID != c.ActorID || b.ActorKind != authorization.SubjectServiceAccount || b.OperationID != action {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			requestDelivery(r).observeCommitted(out.CommandID)
			response := optionsResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}
			valid := func() bool { return signupFresh(c, s) }
			if !out.Replayed {
				ceremony, ok := out.Options.Ceremony()
				if !ok || ceremony.ID != string(out.CommandID) || ceremony.Intent.Context.TenantID != s.facts.TenantID() || ceremony.Intent.Context.UserID == "" || ceremony.Intent.Context.AnonymousFlowID != "" || ceremony.Intent.Context.ActorID != c.ActorID || ceremony.Intent.Origin != string(c.Origin) || ceremony.Intent.Kind != "create" || !ceremony.Intent.ResidentKeyRequired {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				valid = func() bool { return signupFresh(c, s) && c.Now().Before(ceremony.ExpiresAt) }
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

func signupFresh(c SignupConfig, s SignupState) bool {
	now := c.Now()
	return !now.IsZero() && !now.Before(s.started) && now.Before(s.started.Add(min(c.MaximumDuration, 20*time.Second))) && now.Before(s.device.ExpiresAt())
}
