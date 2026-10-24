package passkeyhttp

import (
	"context"
	"fmt"
	"net/http"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

// SigninState is immutable request-local browser custody, not authentication.
// Hooks may observe its phase but cannot select a user, alter private requests,
// replace a rate source, retain secrets or renew delivery validity.
type SigninState struct{ *signinState }
type signinState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	request    passkey.SigninRequest
	deviceWire string
	device     session.BrowserDevice
	started    time.Time
	source     passkey.CeremonyRateSource
}

func (SigninState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SigninState(redacted)"))
}

// MarshalJSON denies implicit original browser-custody export.
func (SigninState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit original browser-custody export.
func (SigninState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSigninOptionsHandler selects only POST /v1/passkey/signin-options.
// Exact keyed admission belongs to native ownership. Matching retries return
// metadata only, never another challenge. No route is globally registered.
func NewSigninOptionsHandler(c SigninConfig) (http.Handler, error) {
	return NewSigninOptionsHandlerWithMiddleware(c, nil)
}

// NewSigninOptionsHandlerWithMiddleware exposes bounded real owner phases;
// middleware cannot replace frozen browser input or reveal-once response bytes.
func NewSigninOptionsHandlerWithMiddleware(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSigninHandler(c, m, false)
}

// NewSigninVerifyHandler selects only POST /v1/passkey/signin-verify. A genuine
// native original source precedes rate.verify and one native completion call.
// Only fresh acknowledged commitment can deliver the owned cookie and CSRF.
func NewSigninVerifyHandler(c SigninConfig) (http.Handler, error) {
	return NewSigninVerifyHandlerWithMiddleware(c, nil)
}

// NewSigninVerifyHandlerWithMiddleware preserves original flow/mode/remember,
// native one-use semantics and conservative response-custody validity.
func NewSigninVerifyHandlerWithMiddleware(c SigninConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSigninHandler(c, m, true)
}

func newSigninHandler(c SigninConfig, m []identityhttp.MiddlewareDescriptor, complete bool) (http.Handler, error) {
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
		return nil, identityhttp.ErrInvalidInput
	}
	if c.DiscoverableOnly && !c.Discoverable {
		return nil, identityhttp.ErrInvalidInput
	}
	var conditional ConditionalSigninService
	if c.Conditional {
		var ok bool
		conditional, ok = c.Service.(ConditionalSigninService)
		if !c.Discoverable || !ok || absent(conditional) {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	if !c.DiscoverableOnly {
		if _, err := c.Address.Parse(email.AddressInput("configuration@example.invalid")); err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	operation := "signin-options"
	if complete {
		operation = "signin-verify"
	}
	action := "identity.passkey." + operation
	caller := func(tenant identity.TenantID, flow identity.PreAuthTransactionID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(tenant), Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow)}}}
	}
	if caller("configuration", "configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SigninState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (SigninState, error) {
			var s SigninState
			facts, body, key, err := i.decode(r, operation, false)
			if err != nil {
				return s, err
			}
			if body.discoverable && !c.Discoverable || !body.discoverable && c.DiscoverableOnly {
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
			s = SigninState{&signinState{facts: facts, body: body, key: key, deviceWire: device.Token(), request: passkey.SigninRequest{FlowID: identity.PreAuthTransactionID(body.flowID), Cookie: token, Identifier: body.identifier, Origin: string(c.Origin), Network: facts.ClientIP().String()}}}
			if complete {
				s.request.CommandID = identity.CommandID(body.commandID)
				s.request.CorrelationID = body.commandID
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s SigninState) (SigninState, error) {
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
			s.deviceWire = ""
			s.request.Device = s.device.DeviceID()
			if !s.body.discoverable {
				// Email owns local-part folding and independent nontransitional
				// domain IDNA. Whole-mailbox folding changes DNS destinations.
				address, err := c.Address.Parse(email.AddressInput(s.body.identifier))
				if err != nil || !identifierText(address.Canonical().Record().Value) {
					return s, identityhttp.ErrInvalidInput
				}
				s.request.Identifier = address.Canonical().Record().Value
			}
			if complete {
				var source passkey.CeremonyRateSource
				if s.body.discoverable {
					source, err = c.Service.DiscoverableSigninRateSource(r.Context(), passkey.DiscoverableCeremonyRateRequest{DiscoverableSigninRequest: discoveryRequest(s.request), CeremonyID: s.body.ceremonyID})
				} else {
					source, err = c.Service.SigninRateSource(r.Context(), passkey.SigninCeremonyRateRequest{SigninRequest: s.request, CeremonyID: s.body.ceremonyID})
				}
				if err != nil {
					return s, domainFailure(err)
				}
				if !validSigninSource(source, s) {
					return s, identityhttp.ErrUnavailable
				}
				s.source = source
			}
			requestDelivery(r).valid = func() bool { return signinFresh(c, s) }
			return s, nil
		},
		Admit: func(r *http.Request, s SigninState) error {
			if !signinFresh(c, s) {
				return identityhttp.ErrUnavailable
			}
			if !complete {
				if s.body.discoverable {
					return nil
				}
				return rateFailure(c.OptionsRate.AdmitPasskeyOptionsIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: action, Identifier: s.request.Identifier}))
			}
			rate := identityhttp.PasskeyVerificationRateRequest{ChallengeID: s.source.CeremonyID, ChallengeLifetime: s.source.Lifetime}
			if s.body.discoverable {
				rate.AnonymousFlowID = s.source.AnonymousFlowID
			} else {
				rate.Identifier = s.source.Identifier
			}
			return rateFailure(c.VerificationRate.AdmitPasskeyChallenge(r.Context(), s.facts, rate))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SigninState) {
			if !signinFresh(c, s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if complete {
				signinComplete(c, w, r, s)
				return
			}
			var out passkey.KeyedAssertionOptionsResult
			var options interface {
				Ceremony() (webauthn.CeremonyRecord, bool)
				TransferJSON(context.Context, func(context.Context, []byte) error) error
			}
			var err error
			if s.body.discoverable && c.Conditional {
				selected, callErr := conditional.KeyedConditionalAuthenticationOptions(r.Context(), passkey.KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discoveryRequest(s.request), IdempotencyKey: s.key, Caller: caller(s.facts.TenantID(), s.request.FlowID)})
				out.CommandID, out.Receipt, out.Replayed = selected.CommandID, selected.Receipt, selected.Replayed
				options, err = selected.Options, callErr
			} else if s.body.discoverable {
				out, err = c.Service.KeyedDiscoverableAuthenticationOptions(r.Context(), passkey.KeyedDiscoverableOptionsRequest{DiscoverableSigninRequest: discoveryRequest(s.request), IdempotencyKey: s.key, Caller: caller(s.facts.TenantID(), s.request.FlowID)})
				options = out.Options
			} else {
				out, err = c.Service.KeyedAuthenticationOptions(r.Context(), passkey.KeyedSigninOptionsRequest{SigninRequest: s.request, IdempotencyKey: s.key, Caller: caller(s.facts.TenantID(), s.request.FlowID)})
				options = out.Options
			}
			if err != nil {
				rejectNative(w, r, err)
				return
			}
			if out.Receipt.Validate() != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.CommandID != out.Receipt.Binding.CommandID || out.Receipt.Binding.TenantID != s.facts.TenantID() || out.Receipt.Binding.AnonymousFlowID != string(s.request.FlowID) || out.Receipt.Binding.ActorID != c.ActorID || out.Receipt.Binding.ActorKind != authorization.SubjectServiceAccount || out.Receipt.Binding.OperationID != action {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response := optionsResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}
			requestDelivery(r).observeCommitted(out.CommandID)
			valid := func() bool { return signinFresh(c, s) }
			if !out.Replayed {
				ceremony, ok := options.Ceremony()
				if !ok || ceremony.ID != string(out.CommandID) || ceremony.Intent.Context.TenantID != s.facts.TenantID() || ceremony.Intent.Context.AnonymousFlowID != string(s.request.FlowID) || ceremony.Intent.Context.UserID != "" || ceremony.Intent.Origin != string(c.Origin) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				valid = func() bool { return signinFresh(c, s) && c.Now().Before(ceremony.ExpiresAt) }
				if err := options.TransferJSON(r.Context(), func(_ context.Context, wire []byte) error {
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

func discoveryRequest(r passkey.SigninRequest) passkey.DiscoverableSigninRequest {
	return passkey.DiscoverableSigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID}
}
func validSigninSource(source passkey.CeremonyRateSource, s SigninState) bool {
	if source.CeremonyID != s.body.ceremonyID || source.Lifetime != 5*time.Minute || source.UserID != "" {
		return false
	}
	if s.body.discoverable {
		return source.Kind == passkey.RateSourceAnonymousFlow && source.AnonymousFlowID == s.request.FlowID && source.Identifier == ""
	}
	return source.Kind == passkey.RateSourceIdentifier && source.Identifier == s.request.Identifier && source.AnonymousFlowID == ""
}
func signinFresh(c SigninConfig, s SigninState) bool {
	now := c.Now()
	return !now.IsZero() && !now.Before(s.started) && now.Before(s.started.Add(min(c.MaximumDuration, 20*time.Second))) && now.Before(s.device.ExpiresAt())
}

func signinComplete(c SigninConfig, w http.ResponseWriter, r *http.Request, s SigninState) {
	var out passkey.SigninResult
	var err error
	if s.body.discoverable {
		out, err = c.Service.DiscoverableSignin(r.Context(), passkey.DiscoverableSigninCompletion{DiscoverableSigninRequest: discoveryRequest(s.request), CeremonyID: s.body.ceremonyID, Response: s.body.response})
	} else {
		out, err = c.Service.Signin(r.Context(), passkey.SigninCompletion{SigninRequest: s.request, CeremonyID: s.body.ceremonyID, Response: s.body.response})
	}
	if err != nil {
		rejectNative(w, r, err)
		return
	}
	deliverPasskeySession(w, r, authenticationDelivery{tenant: s.facts.TenantID(), command: s.request.CommandID, audience: c.Audience, cookie: c.SessionCookie, now: c.Now, fresh: func() bool { return signinFresh(c, s) }}, out.Session, out.CSRF, out.CounterRisk, false)
}

// Both native signup and signin issue through the same session owner. Preserve
// a single transport serializer and custody check rather than giving signup a
// weaker cookie, proof, remember or post-middleware delivery path.
type authenticationDelivery struct {
	tenant   identity.TenantID
	command  identity.CommandID
	audience string
	cookie   session.CookiePolicy
	now      func() time.Time
	fresh    func() bool
}

func deliverPasskeySession(w http.ResponseWriter, r *http.Request, c authenticationDelivery, issued session.IssueResult, csrfToken session.CSRFToken, counterRisk, signup bool) {
	if issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed || issued.CommandID != c.command {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	spec, err := issued.Session.Bindings()
	now := c.now()
	if err != nil || spec.TenantID != c.tenant || spec.Audience != c.audience || spec.Authentication.Proof.Method != "passkey" || spec.Authentication.Proof.ID != auth.ProofID(c.command) || spec.Authentication.Proof.Tenant != string(spec.TenantID) || spec.Authentication.Proof.Subject != string(spec.UserID) || spec.Authentication.Proof.Purpose != "session-issue" || spec.Authentication.Proof.Audience != c.audience {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	requestDelivery(r).observeCommitted(issued.CommandID)
	if spec.IssuedAt.After(now) || spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(c.tenant), Subject: string(spec.UserID), Purpose: "session-issue", Audience: c.audience, Now: now}) != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	csrfState, err := issued.Session.CSRFState().Bindings()
	if err != nil || csrfState.Binding != (session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	if _, err := spec.Remember.Evaluate(now, spec.IssuedAt, spec.LastActivityAt, spec.Authentication.Proof.IssuedAt); err != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	attributes, err := c.cookie.Attributes(spec.Remember, now, spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
	observed := issued.Cookie
	if err != nil || observed.Name != attributes.Name || observed.Path != attributes.Path || observed.Domain != "" || !observed.Secure || !observed.HttpOnly || observed.SameSite != attributes.SameSite || observed.Partitioned || observed.Quoted || observed.RawExpires != "" || (attributes.MaxAge == 0 && (observed.MaxAge != 0 || !observed.Expires.IsZero())) || (attributes.MaxAge > 0 && (observed.MaxAge <= 0 || observed.Expires.IsZero() || observed.Expires.After(spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())))) {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	csrf, err := csrfToken.Reveal()
	if err != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	token, err := issued.Token.Reveal()
	if err != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	if _, err := session.ParseToken(token); err != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	attributes.Value = token
	d := requestDelivery(r)
	d.cookie, d.csrf = attributes.String(), csrf
	response := map[string]any{"signedIn": true, "commandID": c.command, "commitOutcome": "committed", "sessionID": spec.SessionID, "counterRisk": counterRisk}
	if signup {
		response["registered"] = true
	}
	d.render(w, r, response, func() bool {
		now := c.now()
		if !c.fresh() || spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: c.audience, Now: now}) != nil {
			return false
		}
		_, err := spec.Remember.Evaluate(now, spec.IssuedAt, spec.LastActivityAt, spec.Authentication.Proof.IssuedAt)
		return err == nil
	})
}
