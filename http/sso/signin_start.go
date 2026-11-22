package ssohttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

const signinStartOperation = "identity.sso.signin-start"
const signinStartPath = "/v1/sso/signin-start"

// SigninStarter invokes the installed native enterprise start owner. The
// transport passes trusted tenant and browser facts; this owner authenticates
// the original flow and performs the durable start and admission.
type SigninStarter interface {
	StartSSOOIDC(context.Context, identity.TenantID, sso.SigninStartRequest, SigninBrowser) (sso.SigninStartResult, error)
}

// OAuth2SigninStarter invokes the configured native enterprise OAuth2 start.
// The owner verifies original flow, provider activation and durable admission.
type OAuth2SigninStarter interface {
	StartSSOOAuth2(context.Context, identity.TenantID, sso.SigninStartRequest, SigninBrowser) (sso.SigninStartResult, error)
}

// OAuth2SigninStartConfig selects one installed OAuth2 provider by exact ID
// and pinned authorization endpoint. The callback allowlist is same-origin.
type OAuth2SigninStartConfig struct {
	ProviderID            string
	AuthorizationEndpoint string
	CallbackAllowlist     []string
	Start                 OAuth2SigninStarter
}

// MemberLinkStarter owns current session, original consent and durable start.
type MemberLinkStarter interface {
	StartSSOOIDCLink(context.Context, identity.TenantID, sso.SigninStartRequest, SigninBrowser, authentication.BearerCredential, session.CSRFToken) (sso.SigninStartResult, error)
}

// MemberLinkStartConfig opts the keyed start route into the explicit `link:true`
// variant alongside unchanged anonymous sign-in. Cookie must be SameSite=Lax
// so the original local session can accompany the provider's top-level return.
type MemberLinkStartConfig struct {
	Cookie session.CookiePolicy
	Start  MemberLinkStarter
}

type memberStartPolicy struct {
	owner MemberLinkStarter
	name  string
	csrf  *identityhttp.CSRFDecoder
}

// SigninStartConfig selects one installed static provider. AuthorizationEndpoint
// is the configured exact HTTPS endpoint, without a query. CallbackAllowlist is
// an exact same-origin allowlist; caller-supplied endpoints never select authority.
type SigninStartConfig struct {
	Browser               SigninBrowserConfig
	ProviderID            string
	AuthorizationEndpoint string
	CallbackAllowlist     []string
	Lifetime              session.LifetimeConfig
	Start                 SigninStarter
}

// NewSigninStartFeature selects only the keyed enterprise signin start route.
// It does not activate discovery or callback, create a browser flow, or own SQL.
func NewSigninStartFeature(c SigninStartConfig) (identityhttp.Feature, error) {
	return newSigninStartFeature(c, nil)
}

// NewSigninStartFeatureWithLink adds authenticated consent to the same keyed
// start route. A member start has no anonymous flow, never enables Remember,
// and requires the exact-origin header token and original local session cookie.
func NewSigninStartFeatureWithLink(c SigninStartConfig, link MemberLinkStartConfig) (identityhttp.Feature, error) {
	return newSigninStartFeature(c, &link)
}

func newSigninStartFeature(c SigninStartConfig, link *MemberLinkStartConfig) (identityhttp.Feature, error) {
	if !configuredOwner(c.Start) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	oidc, err := signinStartProviderFor(c.Browser.Origin, c.ProviderID, c.AuthorizationEndpoint, c.CallbackAllowlist, "oidc", c.Start.StartSSOOIDC)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return composeSigninStartFeature(c.Browser, c.Lifetime, &oidc, nil, link)
}

// NewOAuth2SigninStartFeature selects the keyed start route for only the
// configured OAuth2 provider. It does not expose discovery or callback.
func NewOAuth2SigninStartFeature(browser SigninBrowserConfig, lifetime session.LifetimeConfig, c OAuth2SigninStartConfig) (identityhttp.Feature, error) {
	if !configuredOwner(c.Start) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	oauth2, err := signinStartProviderFor(browser.Origin, c.ProviderID, c.AuthorizationEndpoint, c.CallbackAllowlist, "oauth2", c.Start.StartSSOOAuth2)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return composeSigninStartFeature(browser, lifetime, nil, &oauth2, nil)
}

// NewSigninStartFeatureWithOAuth2 selects exactly two distinct installed
// providers on the same keyed start route. Provider ID selects its configured
// owner; no request field chooses a protocol. Optional link is OIDC-only.
func NewSigninStartFeatureWithOAuth2(c SigninStartConfig, oauth2 OAuth2SigninStartConfig, link *MemberLinkStartConfig) (identityhttp.Feature, error) {
	if !configuredOwner(c.Start) || !configuredOwner(oauth2.Start) || c.ProviderID == oauth2.ProviderID {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	oidc, err := signinStartProviderFor(c.Browser.Origin, c.ProviderID, c.AuthorizationEndpoint, c.CallbackAllowlist, "oidc", c.Start.StartSSOOIDC)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	plain, err := signinStartProviderFor(c.Browser.Origin, oauth2.ProviderID, oauth2.AuthorizationEndpoint, oauth2.CallbackAllowlist, "oauth2", oauth2.Start.StartSSOOAuth2)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return composeSigninStartFeature(c.Browser, c.Lifetime, &oidc, &plain, link)
}

type signinStartProvider struct {
	id, protocol string
	endpoint     url.URL
	callbacks    []string
	start        func(context.Context, identity.TenantID, sso.SigninStartRequest, SigninBrowser) (sso.SigninStartResult, error)
}

func signinStartProviderFor(origin identityhttp.Origin, id, endpoint string, callbacks []string, protocol string,
	start func(context.Context, identity.TenantID, sso.SigninStartRequest, SigninBrowser) (sso.SigninStartResult, error),
) (signinStartProvider, error) {
	if !validProviderID(id) || len(callbacks) == 0 || len(callbacks) > 64 {
		return signinStartProvider{}, identityhttp.ErrInvalidInput
	}
	callbacks = slices.Clone(callbacks)
	for _, callback := range callbacks {
		u, err := signinHTTPSURL(callback)
		if err != nil || u.Scheme+"://"+u.Host != string(origin) {
			return signinStartProvider{}, identityhttp.ErrInvalidInput
		}
	}
	authorization, err := signinHTTPSURL(endpoint)
	if err != nil || authorization.RawQuery != "" {
		return signinStartProvider{}, identityhttp.ErrInvalidInput
	}
	return signinStartProvider{id: id, protocol: protocol, endpoint: authorization, callbacks: callbacks, start: start}, nil
}

func composeSigninStartFeature(c SigninBrowserConfig, lifetime session.LifetimeConfig, oidc, oauth2 *signinStartProvider, link *MemberLinkStartConfig) (identityhttp.Feature, error) {
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, lifetime); err != nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	browser, err := newSigninBrowserPolicy(c)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	var member *memberStartPolicy
	if link != nil {
		cookie, err := link.Cookie.DeletionAttributes()
		if err != nil || cookie.SameSite != http.SameSiteLaxMode || cookie.Name == browser.flowName || cookie.Name == browser.deviceName || !configuredOwner(link.Start) {
			return identityhttp.Feature{}, identityhttp.ErrInvalidInput
		}
		csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: browser.origins, FormField: "csrf_token"})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		member = &memberStartPolicy{owner: link.Start, name: cookie.Name, csrf: csrf}
	}
	providers := make(map[string]signinStartProvider, 2)
	for _, selected := range []*signinStartProvider{oidc, oauth2} {
		if selected != nil {
			providers[selected.id] = *selected
		}
	}
	handler, err := newSigninStartHandler(c, lifetime, browser, providers, member)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "sso", OperationID: signinStartOperation, Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 8192})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = signinStartWire()
	if member != nil {
		op.Wire = memberSigninStartWire(member.name)
	}
	if oauth2 != nil {
		op.Wire = oauth2SigninStartWire(op.Wire, oidc != nil, member != nil)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso", Operations: []identityhttp.OperationDescriptor{op}})
}

type signinStartState struct {
	facts    identityhttp.NetworkFacts
	browser  SigninBrowser
	device   session.BrowserDevice
	request  sso.SigninStartRequest
	cookie   authentication.BearerCredential
	csrf     session.CSRFToken
	link     bool
	provider signinStartProvider
}

func newSigninStartHandler(c SigninBrowserConfig, lifetime session.LifetimeConfig, browser signinBrowserPolicy, providers map[string]signinStartProvider, member *memberStartPolicy) (http.Handler, error) {
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[signinStartState]{
		MaximumDuration: c.MaximumDuration,
		Reject:          writeSigninError,
		Decode: func(r *http.Request) (s signinStartState, err error) {
			if r.URL == nil || r.Method != http.MethodPost || r.URL.Path != signinStartPath || r.URL.EscapedPath() != signinStartPath || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 || headerPresent(r.Header, "Authorization") {
				return s, identityhttp.ErrInvalidInput
			}
			if member == nil {
				if headerPresent(r.Header, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
				s.facts, s.browser, s.device, err = browser.resolve(r, true)
			} else {
				s.facts, s.browser, s.device, err = browser.resolveDevice(r, true)
			}
			if err != nil {
				return s, err
			}
			key, _, err := browser.decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](browser.decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if raw, present := body["link"]; present {
				if member == nil || string(raw) != "true" {
					return s, identityhttp.ErrInvalidInput
				}
				s.link = true
				delete(body, "link")
			}
			var providerID string
			if json.Unmarshal(body["providerID"], &providerID) != nil {
				return s, identityhttp.ErrInvalidInput
			}
			delete(body, "providerID")
			selected, ok := providers[providerID]
			if !ok || s.link && selected.protocol != "oidc" {
				return s, identityhttp.ErrInvalidInput
			}
			s.provider = selected
			s.request, s.browser.FlowID, err = selected.decodeStart(body, key, lifetime, s.link)
			if err != nil {
				return s, err
			}
			if s.link {
				s.cookie, err = browser.sessionCookie(r, member.name, identityhttp.HeaderRequired)
				if err != nil {
					return s, err
				}
				s.csrf, _, err = identityhttp.DecodeCSRF(member.csrf, r, session.ParseCSRFToken)
				if err != nil {
					return s, identity.ForbiddenError{}
				}
				return s, nil
			}
			if headerPresent(r.Header, "X-CSRF-Token") {
				return s, identityhttp.ErrInvalidInput
			}
			if member != nil {
				s.browser.FlowCookie, err = browser.sessionCookie(r, browser.flowName, identityhttp.HeaderRequired)
			}
			return s, err
		},
		Authenticate: func(r *http.Request, s signinStartState) (signinStartState, error) {
			return s, admitSigninIP(r.Context(), c.Rate, s.facts, signinStartOperation, s.provider.id)
		},
		Admit: func(_ *http.Request, s signinStartState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identity.ForbiddenError{}
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s signinStartState) {
			var out sso.SigninStartResult
			var err error
			if s.link {
				out, err = member.owner.StartSSOOIDCLink(r.Context(), s.facts.TenantID(), s.request, s.browser, s.cookie, s.csrf)
			} else {
				out, err = s.provider.start(r.Context(), s.facts.TenantID(), s.request, s.browser)
			}
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			if r.Context().Err() != nil || !s.device.ExpiresAt().After(c.Now()) || !s.provider.validResult(out, c.TenantID, s.browser.FlowID) {
				writeSigninError(w, r, identityhttp.ErrUnavailable)
				return
			}
			writeDiscoveryJSON(w, http.StatusOK, struct {
				AuthorizationURL string `json:"authorizationURL"`
				TransactionID    string `json:"transactionID"`
				ProviderID       string `json:"providerID"`
				Protocol         string `json:"protocol"`
			}{out.RedirectURI.String(), out.TransactionID, out.ProviderID, out.Protocol})
		},
	})
}

func (provider signinStartProvider) decodeStart(body map[string]json.RawMessage, key identity.IdempotencyKey, lifetime session.LifetimeConfig, link bool) (sso.SigninStartRequest, identity.PreAuthTransactionID, error) {
	var flow, command, domain, callback, errorCallback string
	var remember bool
	required := map[string]*string{"commandID": &command, "callback": &callback, "errorCallback": &errorCallback}
	if !link {
		required["flowID"] = &flow
	}
	for name, target := range required {
		value, present := body[name]
		if !present || string(value) == "null" || json.Unmarshal(value, target) != nil {
			return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
		}
		delete(body, name)
	}
	if raw, ok := body["domain"]; ok {
		if string(raw) == "null" || json.Unmarshal(raw, &domain) != nil || domain == "" {
			return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
		}
		delete(body, "domain")
	}
	if provider.protocol == "oauth2" && domain == "" {
		return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
	}
	choice := session.RememberDefault
	if link {
		choice = session.BrowserSession
	}
	if raw, ok := body["remember"]; ok {
		if string(raw) == "null" || json.Unmarshal(raw, &remember) != nil || link && remember {
			return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
		}
		choice = session.BrowserSession
		if remember {
			choice = session.PersistentSession
		}
		delete(body, "remember")
	}
	if len(body) != 0 || !slices.Contains(provider.callbacks, callback) || !slices.Contains(provider.callbacks, errorCallback) {
		return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
	}
	var flowID identity.PreAuthTransactionID
	var flowErr error
	if !link {
		flowID, flowErr = identity.ParsePreAuthTransactionID(flow)
	}
	commandID, commandErr := identity.ParseCommandID(command)
	success, successErr := signinHTTPSURL(callback)
	failure, failureErr := signinHTTPSURL(errorCallback)
	policy, policyErr := session.ResolveRememberPolicy(choice, lifetime)
	intent, intentErr := sso.NewLoginIntent(policy)
	if flowErr != nil || commandErr != nil || successErr != nil || failureErr != nil || policyErr != nil || intentErr != nil {
		return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
	}
	request := sso.SigninStartRequest{CommandID: commandID, ProviderID: provider.id, Domain: domain, SuccessCallback: success, ErrorCallback: failure, LoginIntent: intent, IdempotencyKey: key}
	return request, flowID, request.Validate()
}

func (provider signinStartProvider) validResult(out sso.SigninStartResult, tenant identity.TenantID, flow identity.PreAuthTransactionID) bool {
	b := out.Completion.Binding
	if out.Completion.Validate() != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || b.TenantID != tenant ||
		b.OperationID != signinStartOperation || b.AnonymousFlowID != string(flow) || b.RecordID != out.TransactionID || out.TransactionID != string(b.CommandID) || out.ProviderID != provider.id || out.Protocol != provider.protocol {
		return false
	}
	if provider.protocol == "oauth2" && (b.SchemaID != "identity.sso.signin-start.oauth2-v1" || flow == "") {
		return false
	}
	if flow == "" && (b.SchemaID != "identity.sso.signin-start.oidc-link-v1" || b.UserID == "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID)) {
		return false
	}
	redirect, err := signinHTTPSURL(out.RedirectURI.String())
	if err != nil || redirect.RawQuery == "" {
		return false
	}
	redirect.RawQuery = ""
	return redirect == provider.endpoint
}

func signinHTTPSURL(raw string) (url.URL, error) {
	if len(raw) == 0 || len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\t#") {
		return url.URL{}, identityhttp.ErrInvalidInput
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.ForceQuery || u.String() != raw {
		return url.URL{}, identityhttp.ErrInvalidInput
	}
	return *u, nil
}

func headerPresent(headers http.Header, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func validProviderID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func admitSigninIP(ctx context.Context, limiter *identityhttp.AuthRateLimiter, facts identityhttp.NetworkFacts, operation, provider string) error {
	decision, err := limiter.AdmitProviderIP(ctx, facts, operation, provider)
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return discoveryRateDenial{retry: decision.RetryAfter}
	}
	if err != nil || !decision.Allowed {
		return identityhttp.ErrRateUnavailable
	}
	return nil
}

func writeSigninError(w http.ResponseWriter, r *http.Request, err error) {
	clearSigninHeaders(w)
	var invalid identity.InvalidInputError
	var denied identity.ForbiddenError
	var conflict identity.ConflictError
	switch {
	case errors.As(err, &invalid):
		err = identityhttp.ErrInvalidInput
	case errors.As(err, &denied):
		err = sso.ErrForbidden
	case errors.As(err, &conflict), errors.Is(err, sso.ErrConflict):
		writeDiscoveryJSON(w, http.StatusConflict, struct {
			Error string `json:"error"`
		}{"conflict"})
		return
	}
	writeDiscoveryError(w, r, err)
}

func clearSigninHeaders(w http.ResponseWriter) {
	for name := range w.Header() {
		if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(strings.ToLower(name), strings.ToLower(http.TrailerPrefix)) {
			delete(w.Header(), name)
		}
	}
}
