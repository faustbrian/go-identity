package identityhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-http-middleware/cors"
	"github.com/felixge/httpsnoop"
)

// CORSCredentialMode fixes a route's browser credential profile, never selected
// from request cookies/headers. Zero is invalid. This is not authentication.
type CORSCredentialMode uint8

const (
	// CORSNoCredentials never grants browser ambient credentials.
	CORSNoCredentials CORSCredentialMode = iota + 1
	// CORSCookieCredentials grants credentials only to exact configured origins.
	CORSCookieCredentials
	// CORSBearerCredentials never grants ambient credentials and forces no-store,
	// including ordinary requests without Origin. Bearer acquisition is separate.
	CORSBearerCredentials
)

// CORSRoutePolicy binds one exact method/path to copied CORS policy. Methods
// are the seven supported uppercase HTTP methods; paths follow Route's exact
// grammar. Credentials is always explicit. Empty Origins disables CORS for the
// route and requires empty headers/exposure and zero MaxAge. Otherwise Origins
// contains 1..128 distinct canonical HTTPS origins, each <=2048 bytes.
// Header lists contain <=64 distinct case-insensitive HTTP tokens, each <=128
// bytes, with no wildcard; exposed Set-Cookie/Set-Cookie2 are forbidden. MaxAge
// is whole seconds in [0,24h]. No implicit header, method or credential grant.
type CORSRoutePolicy struct {
	Method, Path   string
	Credentials    CORSCredentialMode
	Origins        []Origin
	AllowedHeaders []string
	ExposedHeaders []string
	MaxAge         time.Duration
}

// CORSConfig borrows the immutable current-request network owner and copies
// 0..1024 distinct method/path policies. Empty Routes disables all cross-origin
// access. The future secure router must bind these to its actual descriptors;
// this standalone admission wrapper does not validate feature dependencies.
type CORSConfig struct {
	Network *NetworkResolver
	Routes  []CORSRoutePolicy
}

type corsRoute struct {
	origins map[Origin]struct{}
	headers map[string]struct{}
	bearer  bool
	wrap    func(http.Handler) http.Handler
}

type corsHandler struct {
	network *NetworkResolver
	next    http.Handler
	routes  map[string]corsRoute
}

// NewCORSHandler validates/copies route policy without IO or handler invocation.
// Invalid network/handler, bounds, duplicates or unsafe policy returns
// ErrInvalidInput and no handler. The generic Golib Fetch CORS engine handles
// protocol responses after strict identity admission. Preflights never invoke
// next, authenticate, consume quota/state, or read/close the request body.
// Ordinary missing-Origin and same-effective-origin calls may invoke next with
// no grants even when CORS is disabled; this is NOT origin/token CSRF proof.
// Other origins require exact route and origin membership. No Referer fallback,
// wildcard, dynamic origin or private-network grant is supported.
//
// The returned immutable handler is concurrent-safe if next is. It borrows next
// and Network; callers own their lifetimes and must not mutate constructor
// inputs during construction. Request metadata is never mutated. It retains
// Vary and CORS/cache header custody through ordinary commitment paths and handler
// return, without buffering responses or starting goroutines. Trusted handlers
// must not unwrap/hijack the writer to bypass transport policy. This wrapper is
// not a secure router, authorizer, cookie serializer or protocol-flow validator.
func NewCORSHandler(config CORSConfig, next http.Handler) (http.Handler, error) {
	if config.Network == nil || config.Network.decoder == nil || next == nil || len(config.Routes) > 1024 {
		return nil, ErrInvalidInput
	}
	if f, ok := next.(http.HandlerFunc); ok && f == nil {
		return nil, ErrInvalidInput
	}
	h := &corsHandler{network: config.Network, next: next, routes: make(map[string]corsRoute, len(config.Routes))}
	for _, policy := range config.Routes {
		if !corsMethod(policy.Method) || !validPath(policy.Path) || policy.Credentials < CORSNoCredentials || policy.Credentials > CORSBearerCredentials || policy.MaxAge < 0 || policy.MaxAge > 24*time.Hour || policy.MaxAge%time.Second != 0 {
			return nil, ErrInvalidInput
		}
		key := policy.Method + " " + policy.Path
		if _, duplicate := h.routes[key]; duplicate {
			return nil, ErrInvalidInput
		}
		route := corsRoute{bearer: policy.Credentials == CORSBearerCredentials}
		if len(policy.Origins) == 0 {
			if len(policy.AllowedHeaders) != 0 || len(policy.ExposedHeaders) != 0 || policy.MaxAge != 0 {
				return nil, ErrInvalidInput
			}
			h.routes[key] = route
			continue
		}
		guard, err := NewOriginGuard(OriginGuardConfig{Network: config.Network, TrustedOrigins: policy.Origins})
		if err != nil {
			return nil, err
		}
		route.origins = guard.origins
		route.headers, err = corsHeaderSet(policy.AllowedHeaders, false)
		if err != nil {
			return nil, err
		}
		if _, err := corsHeaderSet(policy.ExposedHeaders, true); err != nil {
			return nil, err
		}
		origins := make([]string, len(policy.Origins))
		for i, origin := range policy.Origins {
			origins[i] = string(origin)
		}
		route.wrap, err = cors.New(cors.Policy{
			AllowedOrigins: origins, AllowedMethods: []string{policy.Method},
			AllowedHeaders: slices.Clone(policy.AllowedHeaders), ExposedHeaders: slices.Clone(policy.ExposedHeaders),
			AllowCredentials: policy.Credentials == CORSCookieCredentials, MaxAgeSeconds: int(policy.MaxAge / time.Second),
			MaxHeaderValues: 128, MaxHeaderBytes: int(config.Network.decoder.limits.MaximumHeaderBytes),
		})
		if err != nil {
			return nil, ErrInvalidInput
		}
		h.routes[key] = route
	}
	return h, nil
}

func (h *corsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clearCORSGrants(w.Header())
	baseVary := corsVary(w.Header())
	_, methodPresent, _ := originHeader(requestHeaders(r), "Access-Control-Request-Method")
	preflight := r != nil && r.Method == http.MethodOptions && methodPresent
	required := append(baseVary, "Origin")
	if preflight {
		required = append(required, "Access-Control-Request-Method", "Access-Control-Request-Headers")
	}
	applyCORSHeaders(w.Header(), nil, required, preflight)
	deny := func(status int) {
		applyCORSHeaders(w.Header(), nil, required, true)
		for name := range w.Header() {
			if strings.EqualFold(name, "Location") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "identity.http.origin_denied\n")
	}
	facts, err := h.network.Resolve(r)
	if err != nil {
		status := http.StatusForbidden
		var malformed DecodeError
		if errors.As(err, &malformed) {
			status = http.StatusBadRequest
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusRequestTimeout
		}
		deny(status)
		return
	}
	origin, originPresent, valid := originHeader(r.Header, "Origin")
	method, _, methodValid := originHeader(r.Header, "Access-Control-Request-Method")
	requestedHeaders, headersPresent, headersValid := originHeader(r.Header, "Access-Control-Request-Headers")
	_, privatePresent, privateValid := originHeader(r.Header, "Access-Control-Request-Private-Network")
	if !valid || !methodValid || !headersValid || !privateValid || privatePresent || (!preflight && (methodPresent || headersPresent)) {
		deny(http.StatusForbidden)
		return
	}
	if originPresent {
		canonical, ok := (&OriginGuard{network: h.network}).canonicalOrigin(origin)
		if !ok || string(canonical) != origin {
			deny(http.StatusForbidden)
			return
		}
	}
	if !validPath(r.URL.Path) || r.URL.RawPath != "" {
		deny(http.StatusForbidden)
		return
	}
	selectedMethod := r.Method
	if preflight {
		if !originPresent || !corsMethod(method) {
			deny(http.StatusForbidden)
			return
		}
		selectedMethod = method
	}
	route, selected := h.routes[selectedMethod+" "+r.URL.Path]
	_, allowed := route.origins[Origin(origin)]
	if preflight {
		if !selected || !allowed || !corsRequestedHeaders(requestedHeaders, headersPresent, route.headers) {
			deny(http.StatusForbidden)
			return
		}
	} else if originPresent && origin != facts.Origin() && !allowed {
		deny(http.StatusForbidden)
		return
	}
	if err := r.Context().Err(); err != nil {
		deny(http.StatusRequestTimeout)
		return
	}
	if !originPresent || !allowed {
		serveCORSCustody(h.next, w, r, nil, required, route.bearer)
		return
	}
	// Canonicalize only a detached bounded header map for the generic engine.
	// The application still receives the original immutable borrowed request.
	engineRequest := r.Clone(r.Context())
	for _, name := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		raw, present, _ := originHeader(r.Header, name)
		for key := range engineRequest.Header {
			if strings.EqualFold(key, name) {
				delete(engineRequest.Header, key)
			}
		}
		if present {
			engineRequest.Header.Set(name, raw)
		}
	}
	next := http.HandlerFunc(func(owned http.ResponseWriter, _ *http.Request) {
		grants := make(http.Header)
		for key, values := range owned.Header() {
			if strings.HasPrefix(strings.ToLower(key), "access-control-") {
				grants[key] = slices.Clone(values)
			}
		}
		serveCORSCustody(h.next, owned, r, grants, required, route.bearer)
	})
	route.wrap(next).ServeHTTP(w, engineRequest)
}

func requestHeaders(r *http.Request) http.Header {
	if r == nil {
		return nil
	}
	return r.Header
}

func corsMethod(method string) bool {
	return slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, method)
}

func corsHeaderSet(headers []string, exposed bool) (map[string]struct{}, error) {
	if len(headers) > 64 {
		return nil, ErrInvalidInput
	}
	set := make(map[string]struct{}, len(headers))
	for _, name := range headers {
		lower := strings.ToLower(name)
		if len(name) > 128 || !headerToken(name) || name == "*" || exposed && (lower == "set-cookie" || lower == "set-cookie2") {
			return nil, ErrInvalidInput
		}
		if _, exists := set[lower]; exists {
			return nil, ErrInvalidInput
		}
		set[lower] = struct{}{}
	}
	return set, nil
}

func corsRequestedHeaders(raw string, present bool, allowed map[string]struct{}) bool {
	if !present {
		return true
	}
	if raw == "" || len(raw) > 8192 {
		return false
	}
	seen := make(map[string]bool)
	for count := 0; ; count++ {
		if count == 64 {
			return false
		}
		name, rest, more := strings.Cut(raw, ",")
		name = strings.Trim(name, " \t")
		if name == "*" || len(name) > 128 || !headerToken(name) {
			return false
		}
		lower := strings.ToLower(name)
		if _, ok := allowed[lower]; !ok || seen[lower] {
			return false
		}
		seen[lower] = true
		if !more {
			return true
		}
		raw = rest
	}
}

func clearCORSGrants(header http.Header) {
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			delete(header, name)
		}
	}
}

func corsVary(header http.Header) []string {
	var result []string
	for name, values := range header {
		if !strings.EqualFold(name, "Vary") {
			continue
		}
		for _, line := range values {
			for _, token := range strings.Split(line, ",") {
				token = strings.TrimSpace(token)
				if headerToken(token) {
					result = append(result, strings.ToLower(token))
				}
			}
		}
	}
	return result
}

func applyCORSHeaders(header, grants http.Header, required []string, noStore bool) {
	clearCORSGrants(header)
	for name, values := range grants {
		header[name] = slices.Clone(values)
	}
	vary := append(corsVary(header), required...)
	for name := range header {
		if strings.EqualFold(name, "Vary") {
			delete(header, name)
		}
	}
	for i := range vary {
		vary[i] = strings.ToLower(vary[i])
	}
	slices.Sort(vary)
	var canonical []string
	for _, name := range slices.Compact(vary) {
		canonical = append(canonical, http.CanonicalHeaderKey(name))
	}
	header.Set("Vary", strings.Join(canonical, ", "))
	if noStore {
		for name := range header {
			if strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "Pragma") || strings.EqualFold(name, "Expires") {
				delete(header, name)
			}
		}
		header.Set("Cache-Control", "no-store")
		header.Set("Pragma", "no-cache")
		header.Set("Expires", "0")
	}
}

func serveCORSCustody(next http.Handler, w http.ResponseWriter, r *http.Request, grants http.Header, required []string, noStore bool) {
	apply := func() { applyCORSHeaders(w.Header(), grants, required, noStore) }
	apply()
	defer apply() // net/http may commit implicitly after a header-only handler returns.
	owned := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) { apply(); next(code) }
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(p []byte) (int, error) { apply(); return next(p) }
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(reader io.Reader) (int64, error) {
				apply()
				return next(corsPolicyReader{reader: reader, apply: apply})
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { apply(); next() } },
	})
	next.ServeHTTP(owned, r)
}

// ReaderFrom may read before committing headers. A reader callback can mutate
// those headers after the pre-call hook, so restore policy after every Read,
// before the underlying writer can observe bytes/EOF and commit. Deliberately
// expose only Reader: optional source fast paths must not bypass this custody.
type corsPolicyReader struct {
	reader io.Reader
	apply  func()
}

func (r corsPolicyReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.apply()
	return n, err
}
