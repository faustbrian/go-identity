package ssohttp

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

const samlLogoutOperation = "identity.sso.saml-slo"
const samlLogoutMaxWire = 1 << 20
const samlLogoutMaxRelayBytes = 80 // SAML Bindings §3.5.3.

// SAMLLogoutRequest carries only the LogoutRequest form field and trusted
// route scope. Transport has not verified the XML or selected any session.
type SAMLLogoutRequest struct {
	TenantID                identity.TenantID
	ProviderID, SAMLRequest string
}

// SAMLLogoutResponseRequest carries only the LogoutResponse form field and
// trusted route scope. Only the native owner's signed InResponseTo may select
// the original logout; this branch has no subject or session selector.
type SAMLLogoutResponseRequest struct {
	TenantID                 identity.TenantID
	ProviderID, SAMLResponse string
}

func (SAMLLogoutRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLLogoutRequest(redacted)")
}
func (SAMLLogoutRequest) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLLogoutRequest(redacted)")
}
func (SAMLLogoutRequest) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (SAMLLogoutRequest) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

func (SAMLLogoutResponseRequest) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLLogoutResponseRequest(redacted)")
}
func (SAMLLogoutResponseRequest) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLLogoutResponseRequest(redacted)")
}
func (SAMLLogoutResponseRequest) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLLogoutResponseRequest) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SAMLLogoutRequestResult contains the native signed response for the exact
// IdP destination after known fresh local commit. Both empty means no wire
// should be delivered, such as one already-settled exact replay.
type SAMLLogoutRequestResult struct{ Destination, SAMLResponse string }

func (SAMLLogoutRequestResult) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLLogoutRequestResult(redacted)")
}
func (SAMLLogoutRequestResult) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLLogoutRequestResult(redacted)")
}
func (SAMLLogoutRequestResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SAMLLogoutRequestResult) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SAMLLogoutRequestRelayResult pairs the signed native response with the
// original optional opaque handle. Empty replay has no response or handle.
type SAMLLogoutRequestRelayResult struct {
	SAMLLogoutRequestResult
	RelayState string
}

func (SAMLLogoutRequestRelayResult) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.SAMLLogoutRequestRelayResult(redacted)")
}
func (SAMLLogoutRequestRelayResult) LogValue() slog.Value {
	return slog.StringValue("ssohttp.SAMLLogoutRequestRelayResult(redacted)")
}

// SAMLLogoutResponseResult contains the original, native-authorized application
// continuation after fresh successful settlement. Empty means no redirect.
type SAMLLogoutResponseResult struct{ FinalRedirect string }

// SAMLLogoutRequestOwner handles a signed IdP-initiated request without an
// SP-initiated response-settlement dependency. It has the same native
// verification, replay, local revocation and delivery contract.
type SAMLLogoutRequestOwner interface {
	HandleSAMLLogoutRequest(context.Context, SAMLLogoutRequest) (SAMLLogoutRequestResult, error)
}

// SAMLLogoutRequestRelayOwner verifies and handles the installed IdP request.
// It binds the optional handle to the native request intent and echoes it
// exactly only with signed response wire after a fresh, known local commit.
// Empty string means absent. Treat the value as opaque, never as authority.
type SAMLLogoutRequestRelayOwner interface {
	HandleSAMLLogoutRequestWithRelayState(context.Context, SAMLLogoutRequest, string) (SAMLLogoutRequestRelayResult, error)
}

// SAMLLogoutOwner is the selected native signed logout service adapter. It
// verifies the exact corresponding message, owns replay, and settles the
// original local effect independently of the remote outcome. It never takes
// a browser cookie, redirect target, session selector, or RelayState from this
// profile, and must be bounded, synchronous and safe for concurrent calls.
type SAMLLogoutOwner interface {
	SAMLLogoutRequestOwner
	SettleSAMLLogoutResponse(context.Context, SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error)
}

// SAMLLogoutConfig selects one installed provider, its exact POST reply
// endpoint, and separately allowlisted SP-origin continuations. The clock and
// replay authority belong to the native owner. This constructor neither opens
// a store nor enables a route independently of NewRouter and NavigationPolicy.
type SAMLLogoutConfig struct {
	Network                        identityhttp.NetworkConfig
	TenantID                       identity.TenantID
	Origin, IdentityProviderOrigin identityhttp.Origin
	ProviderID, ResponseEndpoint   string
	FinalRedirectAllowlist         []string
	Rate                           *identityhttp.AuthRateLimiter
	MaximumDuration                time.Duration
	Owner                          SAMLLogoutOwner
	// RequestOnlyOwner selects an installation with no SP-initiated response
	// settlement. Leave Owner and FinalRedirectAllowlist unset in this mode.
	RequestOnlyOwner SAMLLogoutRequestOwner
}

// NavigationPolicy is the required routing companion for this installed SLO
// path. The two origins are the effective SP destination and only IdP sender.
func (c SAMLLogoutConfig) NavigationPolicy() identityhttp.CORSRoutePolicy {
	return identityhttp.CORSRoutePolicy{Method: http.MethodPost, Path: samlLogoutPath(c.ProviderID),
		Credentials: identityhttp.CORSSAMLLogoutPostNavigation, Origins: []identityhttp.Origin{c.Origin, c.IdentityProviderOrigin}}
}

func samlLogoutPath(provider string) string { return "/saml2/" + provider + "/slo" }

// NewSAMLLogoutOperation opts into the canonical SLO POST operation only.
// Include it in the sso/saml feature and install NavigationPolicy on NewRouter.
// This profile does not add logout start, RelayState, wildcard routes or
// session cookie handling. An unavailable owner never discloses a response.
func NewSAMLLogoutOperation(c SAMLLogoutConfig) (identityhttp.OperationDescriptor, error) {
	return newSAMLLogoutOperation(c, nil)
}

// NewSAMLLogoutOperationWithRequestRelayState selects optional opaque state
// on the signed IdP LogoutRequest branch only. Leave RequestOnlyOwner unset;
// supply Owner only when also selecting the unchanged SP-response branch.
// Mount the operation with the same exact NavigationPolicy as the base route.
func NewSAMLLogoutOperationWithRequestRelayState(c SAMLLogoutConfig, owner SAMLLogoutRequestRelayOwner) (identityhttp.OperationDescriptor, error) {
	if !configuredOwner(owner) || c.RequestOnlyOwner != nil || c.Owner != nil && !configuredOwner(c.Owner) {
		return identityhttp.OperationDescriptor{}, identityhttp.ErrInvalidInput
	}
	return newSAMLLogoutOperation(c, owner)
}

func newSAMLLogoutOperation(c SAMLLogoutConfig, relayOwner SAMLLogoutRequestRelayOwner) (identityhttp.OperationDescriptor, error) {
	p, err := newSAMLLogoutProfile(c, relayOwner)
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[samlLogoutState]{
		MaximumDuration: c.MaximumDuration, Decode: p.decode, Reject: writeSigninError,
		Authenticate: func(_ *http.Request, s samlLogoutState) (samlLogoutState, error) { return s, nil },
		Admit: func(r *http.Request, s samlLogoutState) error {
			// No unverified XML ID can choose a transaction quota. The owner
			// performs signature validation and durable one-shot admission.
			return admitSigninIP(r.Context(), c.Rate, s.facts, samlLogoutOperation, c.ProviderID)
		},
		Handle: p.handle,
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "sso/saml", OperationID: samlLogoutOperation, ProviderPathIDs: []string{c.ProviderID},
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 8192, Handler: &signinCallbackHandler{pipeline: pipeline},
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	if relayOwner != nil {
		op.Wire, err = samlLogoutRelayWire(c.Owner != nil)
		if err != nil {
			return identityhttp.OperationDescriptor{}, err
		}
	} else if c.RequestOnlyOwner != nil {
		op.Wire = samlLogoutRequestWire()
	} else {
		op.Wire = samlLogoutWire()
	}
	return op, nil
}

type samlLogoutProfile struct {
	c              SAMLLogoutConfig
	path           string
	decoder        *identityhttp.RequestDecoder
	network        *identityhttp.NetworkResolver
	idp            *identityhttp.OriginGuard
	requestOwner   SAMLLogoutRequestOwner
	relayOwner     SAMLLogoutRequestRelayOwner
	finalRedirects map[string]struct{}
}

func newSAMLLogoutProfile(c SAMLLogoutConfig, relayOwner SAMLLogoutRequestRelayOwner) (samlLogoutProfile, error) {
	var empty samlLogoutProfile
	invalid := identityhttp.ErrInvalidInput
	var requestOwner SAMLLogoutRequestOwner = c.Owner
	if c.RequestOnlyOwner != nil {
		if c.Owner != nil || len(c.FinalRedirectAllowlist) != 0 {
			return empty, invalid
		}
		requestOwner = c.RequestOnlyOwner
	}
	if relayOwner != nil && c.Owner == nil && len(c.FinalRedirectAllowlist) != 0 {
		return empty, invalid
	}
	if relayOwner == nil && !configuredOwner(requestOwner) {
		return empty, invalid
	}
	if c.TenantID == "" || !validProviderID(c.ProviderID) || c.Origin == c.IdentityProviderOrigin ||
		!c.Rate.Configured() || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.FinalRedirectAllowlist) > 64 {
		return empty, invalid
	}
	path := samlLogoutPath(c.ProviderID)
	endpoint, err := signinHTTPSURL(c.ResponseEndpoint)
	if err != nil || endpoint.Path == "" || endpoint.Scheme+"://"+endpoint.Host != string(c.IdentityProviderOrigin) {
		return empty, invalid
	}
	redirects := make(map[string]struct{}, len(c.FinalRedirectAllowlist))
	for _, raw := range c.FinalRedirectAllowlist {
		target, err := signinHTTPSURL(raw)
		_, duplicate := redirects[raw]
		if err != nil || duplicate || target.Path == path || target.Scheme+"://"+target.Host != string(c.Origin) {
			return empty, invalid
		}
		redirects[raw] = struct{}{}
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return empty, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return empty, err
	}
	// Validate both canonical origins even for direct use of the operation.
	if _, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny}); err != nil {
		return empty, err
	}
	idp, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.IdentityProviderOrigin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return empty, err
	}
	return samlLogoutProfile{c: c, path: path, decoder: decoder, network: network, idp: idp,
		requestOwner: requestOwner, relayOwner: relayOwner, finalRedirects: redirects}, nil
}

type samlLogoutState struct {
	facts   identityhttp.NetworkFacts
	request *SAMLLogoutRequest
	relay   string
	reply   SAMLLogoutResponseRequest
}

func (samlLogoutState) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "ssohttp.samlLogoutState(redacted)")
}

func (p samlLogoutProfile) decode(r *http.Request) (s samlLogoutState, err error) {
	invalid := identityhttp.ErrInvalidInput
	if r.Method != http.MethodPost || r.URL.Path != p.path || r.URL.EscapedPath() != p.path || r.URL.ForceQuery || r.URL.RawQuery != "" || len(r.Trailer) != 0 ||
		headerPresent(r.Header, "Authorization") || headerPresent(r.Header, "Proxy-Authorization") || headerPresent(r.Header, "X-CSRF-Token") {
		return s, invalid
	}
	s.facts, err = p.network.Resolve(r)
	if err != nil || s.facts.Realm() != identityhttp.RealmTenant || s.facts.TenantID() != p.c.TenantID || s.facts.Origin() != string(p.c.Origin) {
		return s, identity.ForbiddenError{}
	}
	if _, err := p.idp.Check(r); err != nil {
		return s, identity.ForbiddenError{}
	}
	if _, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return s, invalid
	}
	form, err := p.decoder.Form(r)
	if err != nil {
		return s, samlDecodeError(err)
	}
	if _, request := form["SAMLRequest"]; request {
		wantFields := 1
		if _, hasRelay := form["RelayState"]; hasRelay {
			state := form.Get("RelayState")
			if p.relayOwner == nil || !validSAMLLogoutRelayState(state) {
				return s, invalid
			}
			s.relay = state
			wantFields++
		}
		wire := form.Get("SAMLRequest")
		if len(form) != wantFields || !validSAMLLogoutWire(wire) {
			return s, invalid
		}
		s.request = &SAMLLogoutRequest{TenantID: p.c.TenantID, ProviderID: p.c.ProviderID, SAMLRequest: wire}
		return s, nil
	}
	if p.c.Owner == nil || len(form) != 1 {
		return s, invalid
	}
	if wire := form.Get("SAMLResponse"); validSAMLLogoutWire(wire) {
		s.reply = SAMLLogoutResponseRequest{TenantID: p.c.TenantID, ProviderID: p.c.ProviderID, SAMLResponse: wire}
		return s, nil
	}
	return s, invalid
}

func validSAMLLogoutRelayState(value string) bool {
	if len(value) == 0 || len(value) > samlLogoutMaxRelayBytes {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

func validSAMLLogoutWire(wire string) bool {
	if wire == "" || len(wire) > samlLogoutMaxWire || strings.ContainsAny(wire, "\r\n") {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(wire)
	defer clear(decoded)
	return err == nil && len(decoded) != 0
}

func (p samlLogoutProfile) handle(w http.ResponseWriter, r *http.Request, s samlLogoutState) {
	ctx := r.Context()
	delivery := ctx.Value(signinDeliveryKey{}).(*signinDelivery)
	current := func() bool { return ctx.Err() == nil }
	if s.request != nil {
		result, err := p.handleRequest(ctx, *s.request, s.relay)
		if err != nil {
			writeSigninError(w, r, err)
			return
		}
		if !current() {
			writeSigninError(w, r, ctx.Err())
			return
		}
		if result == (SAMLLogoutRequestRelayResult{}) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if result.RelayState != s.relay || result.Destination != p.c.ResponseEndpoint || !validSAMLLogoutWire(result.SAMLResponse) {
			writeSigninError(w, r, identityhttp.ErrUnavailable)
			return
		}
		// Retain only the SP origin for the IdP's browser-origin check. The
		// global no-referrer response header still protects other operations.
		var relayField string
		if result.RelayState != "" {
			relayField = `<input type="hidden" name="RelayState" value="` + html.EscapeString(result.RelayState) + `">`
		}
		page := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="strict-origin"><title>Complete logout</title></head>` +
			`<body><main><h1>Complete logout</h1><form method="post" action="` + html.EscapeString(p.c.ResponseEndpoint) + `">` +
			`<input type="hidden" name="SAMLResponse" value="` + html.EscapeString(result.SAMLResponse) + `">` + relayField +
			`<button type="submit">Continue logout</button></form></main></body></html>`
		delivery.confirmation = &signinConfirmationPage{html: page, formAction: string(p.c.IdentityProviderOrigin), current: current}
		w.WriteHeader(http.StatusOK)
		return
	}
	result, err := p.c.Owner.SettleSAMLLogoutResponse(ctx, s.reply)
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	if !current() {
		writeSigninError(w, r, ctx.Err())
		return
	}
	if result.FinalRedirect == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, allowed := p.finalRedirects[result.FinalRedirect]; !allowed {
		writeSigninError(w, r, identityhttp.ErrUnavailable)
		return
	}
	delivery.redirect, delivery.current = result.FinalRedirect, current
	w.WriteHeader(http.StatusSeeOther)
}

func (p samlLogoutProfile) handleRequest(ctx context.Context, request SAMLLogoutRequest, relay string) (SAMLLogoutRequestRelayResult, error) {
	if p.relayOwner != nil {
		return p.relayOwner.HandleSAMLLogoutRequestWithRelayState(ctx, request, relay)
	}
	result, err := p.requestOwner.HandleSAMLLogoutRequest(ctx, request)
	return SAMLLogoutRequestRelayResult{SAMLLogoutRequestResult: result}, err
}
