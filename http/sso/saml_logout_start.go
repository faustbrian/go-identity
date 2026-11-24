package ssohttp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
)

const samlLogoutStartOperation = "identity.sso.saml-logout-start"

// SAMLLogoutStartResult is the native result. After authoritative selection,
// return LocalRevocation even alongside an error. ProviderRedirect may contain
// only the signed Redirect reserved for that committed local logout.
type SAMLLogoutStartResult struct {
	LocalRevocation  saml.LocalRevocation
	ProviderRedirect string
	LocalOnly        bool
}

func (SAMLLogoutStartResult) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLLogoutStartResult(redacted)")
}
func (SAMLLogoutStartResult) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLLogoutStartResult(redacted)")
}
func (SAMLLogoutStartResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLLogoutStartResult) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SAMLLogoutStartOwner authenticates the original cookie and synchronizer,
// owns keyed recovery and local revocation, and only then prepares remote
// logout. The implementation must accept bounded, concurrent calls.
type SAMLLogoutStartOwner interface {
	StartSSOSAMLLogout(context.Context, ProviderLogoutStartRequest) (SAMLLogoutStartResult, error)
}

// SAMLLogoutStartConfig selects a cookie-authenticated HTTPS start for one
// installed provider. Set RedirectEndpoint to the approved IdP HTTP-Redirect
// location (including any fixed query) or leave it empty for local-only.
// FinalRedirectAllowlist contains exact SP-origin continuations.
type SAMLLogoutStartConfig struct {
	Network                identityhttp.NetworkConfig
	TenantID               identity.TenantID
	Origin                 identityhttp.Origin
	ProviderID             string
	RedirectEndpoint       string
	FinalRedirectAllowlist []string
	Rate                   *identityhttp.AuthRateLimiter
	MaximumDuration        time.Duration
	Cookie                 session.CookiePolicy
	CSRFCookie             session.CSRFCookiePolicy
	Owner                  SAMLLogoutStartOwner
}

// NewSAMLLogoutStartOperation selects POST /saml2/{provider_id}/logout. It
// does not mount the IdP POST return, grant CORS, or authenticate any other
// credential. The native owner checks the original stored synchronizer.
func NewSAMLLogoutStartOperation(c SAMLLogoutStartConfig) (identityhttp.OperationDescriptor, error) {
	p, err := newSAMLLogoutStartProfile(c)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	handler, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[providerLogoutStartState]{
		MaximumDuration: c.MaximumDuration, Decode: p.decode, Reject: writeSigninError,
		Authenticate: func(r *http.Request, state providerLogoutStartState) (providerLogoutStartState, error) {
			return state, admitSigninIP(r.Context(), c.Rate, state.facts, samlLogoutStartOperation, c.ProviderID)
		},
		Admit:  func(*http.Request, providerLogoutStartState) error { return nil },
		Handle: p.start,
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "sso/saml", OperationID: samlLogoutStartOperation, ProviderPathIDs: []string{c.ProviderID},
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 8192, Handler: handler,
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = samlLogoutStartWire(p.authDelete.Name)
	return op, nil
}

type samlLogoutStartProfile struct {
	tenant                 identity.TenantID
	origin                 identityhttp.Origin
	provider, path         string
	endpoint               url.URL
	final                  map[string]struct{}
	network                *identityhttp.NetworkResolver
	decoder                *identityhttp.RequestDecoder
	csrf                   *identityhttp.CSRFDecoder
	authDelete, csrfDelete http.Cookie
	owner                  SAMLLogoutStartOwner
}

func newSAMLLogoutStartProfile(c SAMLLogoutStartConfig) (samlLogoutStartProfile, error) {
	var empty samlLogoutStartProfile
	invalid := identityhttp.ErrInvalidInput
	if c.TenantID == "" || !validProviderID(c.ProviderID) || !c.Rate.Configured() || !configuredOwner(c.Owner) ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second ||
		len(c.FinalRedirectAllowlist) == 0 || len(c.FinalRedirectAllowlist) > 64 {
		return empty, invalid
	}
	path := "/saml2/" + c.ProviderID + "/logout"
	var endpoint url.URL
	if c.RedirectEndpoint != "" {
		var err error
		endpoint, err = signinHTTPSURL(c.RedirectEndpoint)
		if err != nil || endpoint.Path == "" || !samlLogoutStartFixedQuery(endpoint.RawQuery) {
			return empty, invalid
		}
	}
	final := make(map[string]struct{}, len(c.FinalRedirectAllowlist))
	for _, raw := range c.FinalRedirectAllowlist {
		target, err := signinHTTPSURL(raw)
		_, duplicate := final[raw]
		if err != nil || duplicate || target.Path == path || target.Scheme+"://"+target.Host != string(c.Origin) {
			return empty, invalid
		}
		final[raw] = struct{}{}
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return empty, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return empty, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return empty, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return empty, err
	}
	authDelete, authErr := c.Cookie.DeletionAttributes()
	csrfDelete, csrfErr := c.CSRFCookie.DeletionAttributes()
	if authErr != nil || csrfErr != nil || authDelete.Name == csrfDelete.Name {
		return empty, invalid
	}
	return samlLogoutStartProfile{tenant: c.TenantID, origin: c.Origin, provider: c.ProviderID, path: path,
		endpoint: endpoint, final: final, network: network, decoder: decoder, csrf: csrf,
		authDelete: authDelete, csrfDelete: csrfDelete, owner: c.Owner}, nil
}

func (p samlLogoutStartProfile) decode(r *http.Request) (state providerLogoutStartState, err error) {
	invalid := identityhttp.ErrInvalidInput
	if r.URL == nil || r.Method != http.MethodPost || r.URL.Path != p.path || r.URL.RawPath != "" ||
		r.URL.ForceQuery || r.URL.RawQuery != "" || len(r.Trailer) != 0 ||
		headerPresent(r.Header, "Authorization") || headerPresent(r.Header, "Proxy-Authorization") {
		return state, invalid
	}
	facts, err := p.network.Resolve(r)
	if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.TenantID() != p.tenant || facts.Origin() != string(p.origin) {
		return state, sso.ErrForbidden
	}
	key, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
	if err != nil {
		return state, invalid
	}
	credential, _, err := p.decoder.CookieBearer(r, p.authDelete.Name, identityhttp.HeaderRequired)
	if err != nil {
		return state, sso.ErrForbidden
	}
	csrf, _, err := identityhttp.DecodeCSRF(p.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return state, sso.ErrForbidden
	}
	body, err := identityhttp.DecodeJSON[map[string]string](p.decoder, r)
	final := body["finalRedirect"]
	if err != nil || len(body) != 1 || final == "" {
		return state, invalid
	}
	if _, allowed := p.final[final]; !allowed {
		return state, sso.ErrForbidden
	}
	return providerLogoutStartState{facts: facts, request: ProviderLogoutStartRequest{
		TenantID: p.tenant, ProviderID: p.provider, IdempotencyKey: key,
		FinalRedirect: final, Origin: facts.Origin(), Session: credential, CSRF: csrf,
	}}, nil
}

type samlLogoutStartProjection struct {
	SessionID              string `json:"sessionId"`
	Version                uint64 `json:"version"`
	Committed              bool   `json:"committed"`
	ReconciliationRequired bool   `json:"reconciliationRequired"`
}

type samlLogoutStartBody struct {
	Outcome         string                    `json:"outcome"`
	LocalRevocation samlLogoutStartProjection `json:"localRevocation"`
}

func (p samlLogoutStartProfile) start(w http.ResponseWriter, r *http.Request, state providerLogoutStartState) {
	out, err := p.owner.StartSSOSAMLLogout(r.Context(), state.request)
	local := out.LocalRevocation
	if local.Validate() != nil {
		if err == nil || local != (saml.LocalRevocation{}) {
			err = identityhttp.ErrUnavailable
		}
		writeSigninError(w, r, err)
		return
	}
	clearSigninHeaders(w)
	canceled := r.Context().Err() != nil
	if local.Committed && !canceled {
		http.SetCookie(w, &p.authDelete)
		http.SetCookie(w, &p.csrfDelete)
	}
	body := samlLogoutStartBody{Outcome: "unavailable", LocalRevocation: samlLogoutStartProjection(local)}
	status := http.StatusServiceUnavailable
	// The local projection survives a late cancellation or remote failure,
	// but neither can authorize another provider navigation.
	switch {
	case local.ReconciliationRequired:
		body.Outcome = "unknown-reconciliation"
	case err != nil || canceled || !local.Committed:
	case out.LocalOnly && out.ProviderRedirect == "":
		body.Outcome, status = "local-only", http.StatusOK
	case !out.LocalOnly && validSAMLLogoutStartRedirect(out.ProviderRedirect, p.endpoint):
		w.Header().Set("Location", out.ProviderRedirect)
		body.Outcome, status = "redirect", http.StatusSeeOther
	}
	writeDiscoveryJSON(w, status, body)
}

func samlLogoutStartFixedQuery(query string) bool {
	values, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	for key := range values {
		switch strings.ToLower(key) {
		case "samlrequest", "samlresponse", "relaystate", "sigalg", "signature":
			return false
		}
	}
	return true
}

func validSAMLLogoutStartRedirect(raw string, endpoint url.URL) bool {
	if endpoint.Host == "" {
		return false
	}
	target, err := signinHTTPSURL(raw)
	if err != nil {
		return false
	}
	signed := target.RawQuery
	target.RawQuery = endpoint.RawQuery
	if target != endpoint {
		return false
	}
	if endpoint.RawQuery != "" {
		var matched bool
		signed, matched = strings.CutPrefix(signed, endpoint.RawQuery+"&")
		if !matched {
			return false
		}
	}
	parts := strings.Split(signed, "&")
	if len(parts) != 3 || parts[1] != "SigAlg="+url.QueryEscape(saml.SignatureAlgorithmRSAPSSSHA256) {
		return false
	}
	return canonicalSAMLLogoutRedirectField(parts[0], "SAMLRequest=") &&
		canonicalSAMLLogoutRedirectField(parts[2], "Signature=")
}

func canonicalSAMLLogoutRedirectField(raw, prefix string) bool {
	wire, present := strings.CutPrefix(raw, prefix)
	if !present {
		return false
	}
	decoded, err := url.QueryUnescape(wire)
	return err == nil && url.QueryEscape(decoded) == wire && validSAMLLogoutWire(decoded)
}

func samlLogoutStartWire(cookie string) *identityhttp.WireOperation {
	name, _ := json.Marshal(cookie)
	const projection = `{"type":"object","additionalProperties":false,"required":["sessionId","version","committed","reconciliationRequired"],"properties":{"sessionId":{"type":"string","minLength":1,"maxLength":128},"version":{"type":"integer","minimum":1},"committed":{"type":"boolean"},"reconciliationRequired":{"type":"boolean"}}}`
	result := func(outcome string) string {
		return `{"type":"object","additionalProperties":false,"required":["outcome","localRevocation"],"properties":{"outcome":` +
			outcome + `,"localRevocation":{"$ref":"#/components/schemas/SAMLLogoutLocalRevocation"}}}`
	}
	const unavailable = `{"type":"object","additionalProperties":false,"required":["error"],"properties":{"error":{"type":"string"}}}`
	return &identityhttp.WireOperation{Definition: []byte(`{
  "operationId":"identity.sso.saml-logout-start",
  "summary":"Start logout from an installed SAML provider session",
  "description":"Exact SP Origin, original session cookie and synchronizer, and one retry key. Local revocation is independent of provider availability. Only known local commit deletes cookies. Reuse the original request and key to reconcile an unknown local outcome.",
  "security":[{"SAMLLogoutSession":[],"SAMLLogoutCSRF":[]}],
  "parameters":[{"name":"provider_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128}},{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}],
  "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["finalRedirect"],"properties":{"finalRedirect":{"type":"string","format":"uri","maxLength":8192}}}}}},
  "responses":{
    "200":{"description":"Confirmed local-only logout; both cookies deleted.","headers":{"Set-Cookie":{"schema":{"type":"string"}}},"content":{"application/json":{"schema":` + result(`{"const":"local-only"}`) + `}}},
    "303":{"description":"Reserved signed Redirect after confirmed local revocation; both cookies deleted.","headers":{"Location":{"schema":{"type":"string","format":"uri"}},"Set-Cookie":{"schema":{"type":"string"}}},"content":{"application/json":{"schema":` + result(`{"const":"redirect"}`) + `}}},
    "400":{"description":"Invalid request; no selected local session."},
    "403":{"description":"Logout denied; no selected local session."},
    "409":{"description":"Original operation conflict before selection."},
    "429":{"description":"Provider quota exhausted.","headers":{"Retry-After":{"schema":{"type":"integer","minimum":1}}}},
    "503":{"description":"No provider redirect. A selected local outcome is included when known or pending reconciliation. Only committed local revocation deletes cookies.","headers":{"Set-Cookie":{"schema":{"type":"string"}}},"content":{"application/json":{"schema":{"oneOf":[` + unavailable + `,` + result(`{"enum":["unavailable","unknown-reconciliation"]}`) + `]}}}}
  }
}`), Schemas: []identityhttp.WireComponent{{Name: "SAMLLogoutLocalRevocation", Definition: []byte(projection)}},
		SecuritySchemes: []identityhttp.WireComponent{
			{Name: "SAMLLogoutSession", Definition: []byte(`{"type":"apiKey","in":"cookie","name":` + string(name) + `}`)},
			{Name: "SAMLLogoutCSRF", Definition: []byte(`{"type":"apiKey","in":"header","name":"X-CSRF-Token"}`)},
		}}
}
