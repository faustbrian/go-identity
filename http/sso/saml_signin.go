package ssohttp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

const (
	samlStartOperation = "identity.sso.saml-start"
	samlACSOperation   = "identity.sso.saml-acs"
)

// SAMLSigninStartRequest carries server-resolved scope and the original
// freshly issued frontchannel flow. The native owner signs and settles it.
type SAMLSigninStartRequest struct {
	TenantID                       identity.TenantID
	ProviderID                     string
	SuccessCallback, ErrorCallback url.URL
	LoginIntent                    sso.LoginIntent
	IdempotencyKey                 identity.IdempotencyKey
	Browser                        SigninBrowser
}

// SAMLSigninCallbackRequest carries the exact decoded form members, not
// validated XML or session authority. The native locator sets FlowID only
// after authenticating its original browser custody. Do not retain the form.
type SAMLSigninCallbackRequest struct {
	TenantID                     identity.TenantID
	ProviderID                   string
	ReceivedAssertionConsumerURL string
	RelayState, SAMLResponse     string
	Browser                      SigninBrowser
}

func (SAMLSigninStartRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLSigninStartRequest(redacted)")
}
func (SAMLSigninStartRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLSigninStartRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLSigninStartRequest) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLSigninStartRequest(redacted)")
}

func (SAMLSigninCallbackRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLSigninCallbackRequest(redacted)")
}
func (SAMLSigninCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLSigninCallbackRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLSigninCallbackRequest) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLSigninCallbackRequest(redacted)")
}

// SAMLSigninStarter invokes the selected installed SP-initiated native start.
type SAMLSigninStarter interface {
	StartSSOSAML(context.Context, SAMLSigninStartRequest) (sso.SigninStartResult, error)
}

// SAMLSigninCallbackOwner locates the original pending flow without side
// effects, then independently repeats protected checks for settlement.
type SAMLSigninCallbackOwner interface {
	SAMLCallbackRateSource(context.Context, SAMLSigninCallbackRequest) (SigninCallbackRateContext, error)
	CompleteSSOSAML(context.Context, SAMLSigninCallbackRequest) (SigninCallbackResult, error)
}

// SAMLSigninConfig selects a single installed linked-member SP-initiated
// browser profile. The SP and authorized IdP HTTPS origins serve distinct
// requests. The IdP endpoint, ACS and application returns are pinned, never
// derived from untrusted forwarding or assertion fields. The borrowed issuer
// must select this exact SAML ACS; FlowSignalKey is dedicated rate/risk
// correlation for the short-lived flow, not a device or authentication key.
type SAMLSigninConfig struct {
	Network                        identityhttp.NetworkConfig
	TenantID                       identity.TenantID
	Origin, IdentityProviderOrigin identityhttp.Origin
	ProviderID                     string
	AuthorizationEndpoint          string
	SuccessCallback, ErrorCallback string
	CallbackAllowlist              []string
	Audience                       string
	Cookie                         session.CookiePolicy
	CSRFCookie                     session.CSRFCookiePolicy
	Frontchannel                   *session.PreAuthIssuer
	FlowSignalKey                  session.DigestKey
	Lifetime                       session.LifetimeConfig
	Rate                           *identityhttp.AuthRateLimiter
	Now                            func() time.Time
	MaximumDuration                time.Duration
	Start                          SAMLSigninStarter
	Callback                       SAMLSigninCallbackOwner
}

// ACSNavigationPolicy selects the companion NewRouter transport admission.
// Add it to TransportPolicy.CORS when installing this feature. The router
// checks the exact route and origin; this grants no CORS response access.
func (c SAMLSigninConfig) ACSNavigationPolicy() identityhttp.CORSRoutePolicy {
	return identityhttp.CORSRoutePolicy{Method: http.MethodPost, Path: samlACSPath(c.ProviderID),
		Credentials: identityhttp.CORSSAMLPostNavigation, Origins: []identityhttp.Origin{c.IdentityProviderOrigin}}
}

func samlACSPath(provider string) string { return "/saml2/" + provider + "/acs" }

type samlSigninProfile struct {
	c                          SAMLSigninConfig
	network                    *identityhttp.NetworkResolver
	decoder                    *identityhttp.RequestDecoder
	startOrigin, acsOrigin     *identityhttp.OriginGuard
	startPath, acsPath, acsURL string
	endpoint                   url.URL
	frontchannel               session.FrontchannelCookiePolicy
	deleteCorrelation          http.Cookie
}

// NewSAMLSigninFeature selects the canonical signed login and POST ACS pair.
// It adds no wildcard, implicit provider, IdP-init, SLO or metadata route.
func NewSAMLSigninFeature(c SAMLSigninConfig) (identityhttp.Feature, error) {
	return newSAMLSigninFeature(c, nil)
}

func newSAMLSigninFeature(c SAMLSigninConfig, metadata *samlMetadataSelection) (identityhttp.Feature, error) {
	p, err := newSAMLSigninProfile(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	start, err := p.startHandler()
	if err != nil {
		return identityhttp.Feature{}, err
	}
	acs, err := p.acsHandler()
	if err != nil {
		return identityhttp.Feature{}, err
	}
	const owner = "sso/saml"
	var operations []identityhttp.OperationDescriptor
	for _, endpoint := range []struct {
		id      string
		handler http.Handler
		wire    *identityhttp.WireOperation
	}{{samlStartOperation, start, samlStartWire()}, {samlACSOperation, acs, samlACSWire()}} {
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
			Owner: owner, OperationID: endpoint.id, Handler: endpoint.handler, ProviderPathIDs: []string{c.ProviderID},
			CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 8192,
		})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = endpoint.wire
		operations = append(operations, op)
	}
	if metadata != nil {
		op, err := p.metadataOperation(owner, *metadata)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: owner, Operations: operations})
}

func newSAMLSigninProfile(c SAMLSigninConfig) (samlSigninProfile, error) {
	invalid := identityhttp.ErrInvalidInput
	if c.TenantID == "" || !validProviderID(c.ProviderID) || c.Frontchannel == nil || c.FlowSignalKey == (session.DigestKey{}) ||
		!configuredOwner(c.Start) || !configuredOwner(c.Callback) || !c.Rate.Configured() || c.Now == nil ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Audience == "" {
		return samlSigninProfile{}, invalid
	}
	startPath := "/saml2/" + c.ProviderID + "/login"
	acsPath := samlACSPath(c.ProviderID)
	front, err := session.NewFrontchannelCookiePolicy(acsPath)
	if err != nil {
		return samlSigninProfile{}, invalid
	}
	deleteCorrelation, _ := front.DeletionAttributes()
	endpoint, err := signinHTTPSURL(c.AuthorizationEndpoint)
	if err != nil || endpoint.RawQuery != "" || endpoint.Scheme+"://"+endpoint.Host != string(c.IdentityProviderOrigin) {
		return samlSigninProfile{}, invalid
	}
	if len(c.CallbackAllowlist) < 1 || len(c.CallbackAllowlist) > 64 || !slices.Contains(c.CallbackAllowlist, c.SuccessCallback) || !slices.Contains(c.CallbackAllowlist, c.ErrorCallback) {
		return samlSigninProfile{}, invalid
	}
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	for _, callback := range c.CallbackAllowlist {
		u, err := signinHTTPSURL(callback)
		if err != nil || u.Scheme+"://"+u.Host != string(c.Origin) || u.Path == acsPath || u.Path == startPath {
			return samlSigninProfile{}, invalid
		}
	}
	auth, authErr := c.Cookie.DeletionAttributes()
	csrf, csrfErr := c.CSRFCookie.DeletionAttributes()
	if authErr != nil || csrfErr != nil || auth.Name == csrf.Name || auth.SameSite != http.SameSiteLaxMode || csrf.SameSite != http.SameSiteLaxMode {
		return samlSigninProfile{}, invalid
	}
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return samlSigninProfile{}, invalid
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return samlSigninProfile{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return samlSigninProfile{}, err
	}
	originGuard := func(origin identityhttp.Origin) (*identityhttp.OriginGuard, error) {
		return identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	}
	startOrigin, err := originGuard(c.Origin)
	if err != nil {
		return samlSigninProfile{}, err
	}
	acsOrigin, err := originGuard(c.IdentityProviderOrigin)
	if err != nil {
		return samlSigninProfile{}, err
	}
	return samlSigninProfile{c: c, network: network, decoder: decoder, startOrigin: startOrigin, acsOrigin: acsOrigin, endpoint: endpoint,
		startPath: startPath, acsPath: acsPath, acsURL: string(c.Origin) + acsPath, frontchannel: front, deleteCorrelation: deleteCorrelation}, nil
}

func (p samlSigninProfile) requestNetwork(r *http.Request) (identityhttp.NetworkFacts, error) {
	facts, err := p.network.Resolve(r)
	if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.TenantID() != p.c.TenantID || facts.Scheme() != "https" || facts.Origin() != string(p.c.Origin) {
		return identityhttp.NetworkFacts{}, identity.ForbiddenError{}
	}
	return facts, nil
}

func (p samlSigninProfile) admitStartOrigin(r *http.Request) error {
	if headerPresent(r.Header, "Origin") {
		if _, err := p.startOrigin.Check(r); err == nil {
			return nil
		}
		return identity.ForbiddenError{}
	}
	// Fetch §3.2 omits Origin on ordinary GET navigation. Fetch Metadata
	// §2.3 proves the exact effective SP origin for a same-origin document
	// navigation; same-site alone is insufficient and Referer remains denied.
	if exactFetchMetadata(r.Header, "Sec-Fetch-Site", "same-origin") &&
		exactFetchMetadata(r.Header, "Sec-Fetch-Mode", "navigate") &&
		exactFetchMetadata(r.Header, "Sec-Fetch-Dest", "document") {
		return nil
	}
	return identity.ForbiddenError{}
}

func exactFetchMetadata(headers http.Header, name, want string) bool {
	found := false
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		if found || len(values) != 1 || values[0] != want {
			return false
		}
		found = true
	}
	return found
}

func (p samlSigninProfile) browser(facts identityhttp.NetworkFacts, cookie authentication.BearerCredential, token session.Token) (SigninBrowser, error) {
	// The flow signal accompanies this exact short cookie at both endpoints.
	// Ambient Lax device cookies cannot serve a cross-site POST. A signal is
	// only rate/risk input; the native owner still proves original possession.
	digest, err := token.Digest(p.c.FlowSignalKey, string(facts.TenantID()))
	if err != nil {
		return SigninBrowser{}, identity.ForbiddenError{}
	}
	return SigninBrowser{FlowCookie: cookie, Origin: facts.Origin(), Network: facts.ClientIP(), Device: base64.RawURLEncoding.EncodeToString(digest.Sum[:])}, nil
}

func exactSAMLRequest(r *http.Request, method, path string) bool {
	return r != nil && r.URL != nil && r.Method == method && r.URL.Path == path && r.URL.RawPath == "" && !r.URL.ForceQuery && len(r.Trailer) == 0 &&
		!headerPresent(r.Header, "Authorization") && !headerPresent(r.Header, "Proxy-Authorization") && !headerPresent(r.Header, "X-CSRF-Token")
}

type samlStartState struct {
	facts    identityhttp.NetworkFacts
	request  SAMLSigninStartRequest
	remember session.RememberPolicy
}

func (samlStartState) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.samlStartState(redacted)")
}

func (p samlSigninProfile) startHandler() (http.Handler, error) {
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[samlStartState]{
		MaximumDuration: p.c.MaximumDuration, Reject: writeSigninError,
		Decode: func(r *http.Request) (s samlStartState, err error) {
			if !exactSAMLRequest(r, http.MethodGet, p.startPath) || r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = p.requestNetwork(r)
			if err != nil {
				return s, err
			}
			if err := p.admitStartOrigin(r); err != nil {
				return s, err
			}
			s.request, s.remember, err = p.startInput(r)
			return s, err
		},
		Authenticate: func(_ *http.Request, s samlStartState) (samlStartState, error) { return s, nil },
		Admit: func(r *http.Request, s samlStartState) error {
			return admitSigninIP(r.Context(), p.c.Rate, s.facts, samlStartOperation, p.c.ProviderID)
		},
		Handle: p.start,
	})
	if err != nil {
		return nil, err
	}
	return &signinCallbackHandler{pipeline}, nil
}

func (p samlSigninProfile) startInput(r *http.Request) (SAMLSigninStartRequest, session.RememberPolicy, error) {
	var out SAMLSigninStartRequest
	var remember session.RememberPolicy
	query, err := p.decoder.Query(r)
	if err != nil {
		return out, remember, samlDecodeError(err)
	}
	key, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderOptional)
	if err != nil {
		return out, remember, samlDecodeError(err)
	}
	callbacks := map[string]string{"callback": p.c.SuccessCallback, "errorCallback": p.c.ErrorCallback}
	choice := session.RememberDefault
	for name, values := range query {
		value := values[0]
		switch name {
		case "callback", "errorCallback":
			if !slices.Contains(p.c.CallbackAllowlist, value) {
				return out, remember, identityhttp.ErrInvalidInput
			}
			callbacks[name] = value
		case "remember":
			switch value {
			case "false":
				choice = session.BrowserSession
			case "true":
				choice = session.PersistentSession
			default:
				return out, remember, identityhttp.ErrInvalidInput
			}
		default:
			return out, remember, identityhttp.ErrInvalidInput
		}
	}
	remember, err = session.ResolveRememberPolicy(choice, p.c.Lifetime)
	if err != nil {
		return out, remember, identityhttp.ErrInvalidInput
	}
	intent, err := sso.NewLoginIntent(remember)
	if err != nil {
		return out, remember, identityhttp.ErrInvalidInput
	}
	success, _ := signinHTTPSURL(callbacks["callback"])
	failure, _ := signinHTTPSURL(callbacks["errorCallback"])
	return SAMLSigninStartRequest{TenantID: p.c.TenantID, ProviderID: p.c.ProviderID, SuccessCallback: success, ErrorCallback: failure, LoginIntent: intent, IdempotencyKey: key}, remember, nil
}

func (p samlSigninProfile) start(w http.ResponseWriter, r *http.Request, s samlStartState) {
	ctx := r.Context()
	id, err := identity.NewCommandID()
	if err != nil {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	prep, err := p.c.Frontchannel.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: p.c.TenantID, CorrelationID: string(id), Remember: s.remember})
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	issued, err := p.c.Frontchannel.Issue(ctx, prep)
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	flow, err := issued.Flow.Bindings()
	intent := flow.Binding.Intent
	if err != nil || issued.CommandID != id || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed ||
		intent.TenantID != p.c.TenantID || intent.Action != samlACSOperation || intent.Origin != string(p.c.Origin) || intent.CallbackURL != p.acsURL ||
		intent.Purpose != session.PreAuthSessionIssuance || intent.Remember != s.remember || issued.Cookie.Name != p.deleteCorrelation.Name || issued.Cookie.Path != p.acsPath ||
		issued.Cookie.Value != "" || issued.Cookie.Domain != "" || !issued.Cookie.Secure || !issued.Cookie.HttpOnly || issued.Cookie.SameSite != http.SameSiteNoneMode {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	value, err := issued.Token.Reveal()
	if err != nil {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	browser, err := p.browser(s.facts, authentication.NewBearerCredential(value), issued.Token)
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	browser.FlowID = flow.Binding.ID
	s.request.Browser = browser
	out, err := p.c.Start.StartSSOSAML(ctx, s.request)
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	if !p.validStartResult(out, flow.Binding.ID) || ctx.Err() != nil {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	delivery := ctx.Value(signinDeliveryKey{}).(*signinDelivery)
	delivery.redirect = out.RedirectURI.String()
	delivery.current = func() bool {
		// Recalculate when headers are actually written so middleware delay
		// cannot extend Max-Age relative to the coordinator's original cutoff.
		cookie, err := p.frontchannel.Attributes(p.c.Now(), flow.Binding.ExpiresAt)
		if err != nil || ctx.Err() != nil {
			return false
		}
		cookie.Value = value
		if cookie.Valid() != nil {
			return false
		}
		delivery.cookies = []string{cookie.String()}
		return true
	}
	w.WriteHeader(http.StatusSeeOther)
}

func (p samlSigninProfile) validStartResult(out sso.SigninStartResult, flow identity.PreAuthTransactionID) bool {
	b := out.Completion.Binding
	if out.Completion.Validate() != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || b.TenantID != p.c.TenantID ||
		b.OperationID != samlStartOperation || b.SchemaID != "identity.sso.saml-start.v1" || b.AnonymousFlowID != string(flow) ||
		b.RecordID != out.TransactionID || out.TransactionID != string(b.CommandID) || out.ProviderID != p.c.ProviderID || out.Protocol != "saml" {
		return false
	}
	redirect, err := signinHTTPSURL(out.RedirectURI.String())
	if err != nil || redirect.RawQuery == "" {
		return false
	}
	q, err := url.ParseQuery(redirect.RawQuery)
	if err != nil || len(q) != 4 || !validSAMLRelay(q.Get("RelayState")) {
		return false
	}
	for _, key := range []string{"SAMLRequest", "RelayState", "SigAlg", "Signature"} {
		if len(q[key]) != 1 || q[key][0] == "" {
			return false
		}
	}
	redirect.RawQuery = ""
	return redirect == p.endpoint
}

type samlACSState struct {
	facts   identityhttp.NetworkFacts
	request SAMLSigninCallbackRequest
	source  SigninCallbackRateContext
	command identity.CommandID
}

func (samlACSState) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.samlACSState(redacted)")
}

func (p samlSigninProfile) acsHandler() (http.Handler, error) {
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[samlACSState]{
		MaximumDuration: p.c.MaximumDuration, Reject: writeSigninError, Decode: p.decodeACS,
		Authenticate: func(r *http.Request, s samlACSState) (samlACSState, error) {
			ctx := r.Context()
			if err := admitSigninIP(ctx, p.c.Rate, s.facts, samlACSOperation, p.c.ProviderID); err != nil {
				return s, err
			}
			rateInput := s.request
			rateInput.SAMLResponse = ""
			source, err := p.c.Callback.SAMLCallbackRateSource(ctx, rateInput)
			if err != nil {
				return s, err
			}
			flow, flowErr := identity.ParsePreAuthTransactionID(string(source.FlowID))
			command, commandErr := identity.ParseCommandID(source.TransactionID)
			if flowErr != nil || commandErr != nil || source.ProviderID != p.c.ProviderID || source.Lifetime < time.Second || source.Lifetime > 5*time.Minute {
				return s, identity.ForbiddenError{}
			}
			s.source, s.command, s.request.Browser.FlowID = source, command, flow
			return s, nil
		},
		Admit: func(r *http.Request, s samlACSState) error {
			decision, err := p.c.Rate.AdmitProviderTransaction(r.Context(), s.facts, samlACSOperation, p.c.ProviderID, s.source.TransactionID, s.source.Lifetime)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: decision.RetryAfter}
			}
			if err != nil || !decision.Allowed {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s samlACSState) {
			out, err := p.c.Callback.CompleteSSOSAML(r.Context(), s.request)
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			record, err := out.Issuance.Session.Bindings()
			if err != nil {
				writeSigninError(w, r, identityhttp.ErrUnavailable)
				return
			}
			delivery := SigninCallbackConfig{Browser: SigninBrowserConfig{TenantID: p.c.TenantID, Now: p.c.Now}, Audience: p.c.Audience,
				CallbackAllowlist: p.c.CallbackAllowlist, Cookie: p.c.Cookie, CSRFCookie: p.c.CSRFCookie}
			writeSigninDelivery(w, r, delivery, samlACSOperation, "sso-saml", out, s.command, s.request.Browser.FlowID,
				record.Authentication.Proof.ExpiresAt, p.deleteCorrelation.String())
		},
	})
	if err != nil {
		return nil, err
	}
	return &signinCallbackHandler{pipeline}, nil
}

func (p samlSigninProfile) decodeACS(r *http.Request) (s samlACSState, err error) {
	if !exactSAMLRequest(r, http.MethodPost, p.acsPath) || r.URL.RawQuery != "" {
		return s, identityhttp.ErrInvalidInput
	}
	s.facts, err = p.requestNetwork(r)
	if err != nil {
		return s, err
	}
	if _, err := p.acsOrigin.Check(r); err != nil {
		return s, identity.ForbiddenError{}
	}
	if _, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	cookie, _, err := p.decoder.CookieBearer(r, p.deleteCorrelation.Name, identityhttp.HeaderRequired)
	if err != nil {
		return s, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return s, identity.ForbiddenError{}
	}
	browser, err := p.browser(s.facts, cookie, token)
	if err != nil {
		return s, err
	}
	form, err := p.decoder.Form(r)
	if err != nil {
		return s, samlDecodeError(err)
	}
	relay, response := form.Get("RelayState"), form.Get("SAMLResponse")
	if len(form) != 2 || !validSAMLRelay(relay) || response == "" {
		return s, identityhttp.ErrInvalidInput
	}
	s.request = SAMLSigninCallbackRequest{TenantID: s.facts.TenantID(), ProviderID: p.c.ProviderID,
		ReceivedAssertionConsumerURL: p.acsURL, RelayState: relay, SAMLResponse: response, Browser: browser}
	return s, nil
}

func samlDecodeError(err error) error {
	var invalid identityhttp.DecodeError
	if errors.As(err, &invalid) {
		return identityhttp.ErrInvalidInput
	}
	return err
}

func validSAMLRelay(state string) bool {
	var raw [32]byte
	if len(state) != base64.RawURLEncoding.EncodedLen(len(raw)) {
		return false
	}
	n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(state))
	return err == nil && n == len(raw) && base64.RawURLEncoding.EncodeToString(raw[:]) == state
}
