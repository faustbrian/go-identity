package impersonationhttp

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

type cookieIngress struct {
	network      *identityhttp.NetworkResolver
	decoder      *identityhttp.RequestDecoder
	origin       *identityhttp.OriginGuard
	csrf         *identityhttp.CSRFDecoder
	parentCookie string
	duration     time.Duration
}

var errMisdirected = errors.New("impersonation http: not a mapped HTTPS tenant")

func newCookieIngress(config identityhttp.NetworkConfig, origins []identityhttp.Origin, name string, duration time.Duration) (cookieIngress, error) {
	var ingress cookieIngress
	if !validOrdinaryCookie(name, duration) {
		return ingress, identityhttp.ErrInvalidInput
	}
	var err error
	ingress.network, err = identityhttp.NewNetworkResolver(config)
	if err != nil {
		return cookieIngress{}, err
	}
	ingress.decoder, err = identityhttp.NewRequestDecoder(config.Limits)
	if err != nil {
		return cookieIngress{}, err
	}
	ingress.origin, err = identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{
		Network: ingress.network, TrustedOrigins: origins, RefererFallback: identityhttp.RefererFallbackDeny,
	})
	if err != nil {
		return cookieIngress{}, err
	}
	ingress.csrf, err = identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: ingress.origin, FormField: "csrf_token"})
	if err != nil {
		return cookieIngress{}, err
	}
	ingress.parentCookie, ingress.duration = name, duration
	return ingress, nil
}

func (h cookieIngress) facts(r *http.Request) (identityhttp.NetworkFacts, error) {
	facts, err := mappedHTTPSFacts(h.network, r)
	if err != nil {
		return identityhttp.NetworkFacts{}, err
	}
	origin, err := h.origin.Check(r)
	if err != nil {
		return identityhttp.NetworkFacts{}, err
	}
	if string(origin) != facts.Origin() {
		return identityhttp.NetworkFacts{}, identityhttp.OriginError{}
	}
	return facts, nil
}

func validOrdinaryCookie(name string, duration time.Duration) bool {
	return strings.HasPrefix(name, "__Host-") && name != "__Host-" && len(name) <= 128 &&
		name != ChildCookieName && name != ChildCSRFCookieName &&
		(&http.Cookie{Name: name, Value: "x", Path: "/", Secure: true}).Valid() == nil &&
		duration >= time.Millisecond && duration <= 30*time.Second
}

func mappedHTTPSFacts(network *identityhttp.NetworkResolver, r *http.Request) (identityhttp.NetworkFacts, error) {
	facts, err := network.Resolve(r)
	if err != nil && !errors.Is(err, identityhttp.DecodeError{}) {
		return identityhttp.NetworkFacts{}, err
	}
	if err != nil || facts.Scheme() != "https" || facts.TenantID() == "" {
		return identityhttp.NetworkFacts{}, errMisdirected
	}
	return facts, nil
}

func missingOwner(owner any) bool {
	if owner == nil {
		return true
	}
	switch v := reflect.ValueOf(owner); v.Kind() {
	case reflect.Pointer, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

func canonicalCookieOperation(id string, handler http.Handler) (identityhttp.OperationDescriptor, error) {
	return identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/impersonation", OperationID: id, Handler: handler,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 16384,
	})
}
