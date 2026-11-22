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
	if !configuredOwner(c.Start) || !validProviderID(c.ProviderID) || len(c.CallbackAllowlist) == 0 || len(c.CallbackAllowlist) > 64 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	for _, callback := range c.CallbackAllowlist {
		u, err := signinHTTPSURL(callback)
		if err != nil || u.Scheme+"://"+u.Host != string(c.Browser.Origin) {
			return identityhttp.Feature{}, identityhttp.ErrInvalidInput
		}
	}
	endpoint, err := signinHTTPSURL(c.AuthorizationEndpoint)
	if err != nil || endpoint.RawQuery != "" {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	browser, err := newSigninBrowserPolicy(c.Browser)
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
	handler, err := newSigninStartHandler(c, browser, endpoint, member)
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
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso", Operations: []identityhttp.OperationDescriptor{op}})
}

type signinStartState struct {
	facts   identityhttp.NetworkFacts
	browser SigninBrowser
	device  session.BrowserDevice
	request sso.SigninStartRequest
	cookie  authentication.BearerCredential
	csrf    session.CSRFToken
	link    bool
}

func newSigninStartHandler(c SigninStartConfig, browser signinBrowserPolicy, endpoint url.URL, member *memberStartPolicy) (http.Handler, error) {
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[signinStartState]{
		MaximumDuration: c.Browser.MaximumDuration,
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
			s.request, s.browser.FlowID, err = c.decodeStart(body, key, s.link)
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
			return s, admitSigninIP(r.Context(), c.Browser.Rate, s.facts, signinStartOperation, c.ProviderID)
		},
		Admit: func(_ *http.Request, s signinStartState) error {
			if !s.device.ExpiresAt().After(c.Browser.Now()) {
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
				out, err = c.Start.StartSSOOIDC(r.Context(), s.facts.TenantID(), s.request, s.browser)
			}
			if err != nil {
				writeSigninError(w, r, err)
				return
			}
			if r.Context().Err() != nil || !s.device.ExpiresAt().After(c.Browser.Now()) || !validSigninStartResult(out, c.Browser.TenantID, s.browser.FlowID, c.ProviderID, endpoint) {
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

func (c SigninStartConfig) decodeStart(body map[string]json.RawMessage, key identity.IdempotencyKey, link bool) (sso.SigninStartRequest, identity.PreAuthTransactionID, error) {
	var flow, command, provider, domain, callback, errorCallback string
	var remember bool
	required := map[string]*string{"commandID": &command, "providerID": &provider, "callback": &callback, "errorCallback": &errorCallback}
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
	if len(body) != 0 || provider != c.ProviderID || !slices.Contains(c.CallbackAllowlist, callback) || !slices.Contains(c.CallbackAllowlist, errorCallback) {
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
	policy, policyErr := session.ResolveRememberPolicy(choice, c.Lifetime)
	intent, intentErr := sso.NewLoginIntent(policy)
	if flowErr != nil || commandErr != nil || successErr != nil || failureErr != nil || policyErr != nil || intentErr != nil {
		return sso.SigninStartRequest{}, "", identityhttp.ErrInvalidInput
	}
	request := sso.SigninStartRequest{CommandID: commandID, ProviderID: provider, Domain: domain, SuccessCallback: success, ErrorCallback: failure, LoginIntent: intent, IdempotencyKey: key}
	return request, flowID, request.Validate()
}

func validSigninStartResult(out sso.SigninStartResult, tenant identity.TenantID, flow identity.PreAuthTransactionID, provider string, endpoint url.URL) bool {
	b := out.Completion.Binding
	if out.Completion.Validate() != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || b.TenantID != tenant ||
		b.OperationID != signinStartOperation || b.AnonymousFlowID != string(flow) || b.RecordID != out.TransactionID || out.TransactionID != string(b.CommandID) || out.ProviderID != provider || out.Protocol != "oidc" {
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
	return redirect == endpoint
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
