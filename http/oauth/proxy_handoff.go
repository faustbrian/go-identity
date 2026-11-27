package oauthhttp

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// The M20 browser/native handoff profile carries only the encrypted result,
// never provider tokens, and bounds decoding before allocation.
const maximumProxyHandoffEnvelope = 8192

func proxyHandoffLocation(destination string, flow identity.PreAuthTransactionID, envelope []byte) (string, error) {
	endpoint, err := proxyHandoffEndpoint(destination)
	if err != nil || endpoint.Path == "/" || len(envelope) < 1 || len(envelope) > maximumProxyHandoffEnvelope {
		return "", identityhttp.ErrInvalidInput
	}
	if _, err := identity.ParsePreAuthTransactionID(string(flow)); err != nil {
		return "", identityhttp.ErrInvalidInput
	}
	return destination + "#identity-proxy-v1." + string(flow) + "." + base64.RawURLEncoding.EncodeToString(envelope), nil
}

// Parsing establishes bounded wire syntax only. Native completion must still
// authenticate the envelope and its original browser/transaction bindings.
func parseProxyHandoff(flow, encoded string) (identity.PreAuthTransactionID, []byte, error) {
	id, err := identity.ParsePreAuthTransactionID(flow)
	if err != nil || len(encoded) < 2 || len(encoded) > base64.RawURLEncoding.EncodedLen(maximumProxyHandoffEnvelope) {
		return "", nil, identityhttp.ErrInvalidInput
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(envelope) < 1 || len(envelope) > maximumProxyHandoffEnvelope || base64.RawURLEncoding.EncodeToString(envelope) != encoded {
		return "", nil, identityhttp.ErrInvalidInput
	}
	return id, envelope, nil
}

// NewProxyHandoffLanding constructs a concurrency-safe, stateless GET landing
// for an explicitly registered canonical HTTPS endpoint. Endpoint must have a
// non-root path; success is a distinct canonical path at the same exact origin.
// It accepts direct HTTPS requests only, not forwarded-header alternatives.
// Invalid configuration returns identityhttp.ErrInvalidInput without IO.
//
// The fixed script removes the fragment before any request, validates the
// bounded v1 handoff, and posts only {flow,envelope} to this exact endpoint.
// Only 204 permits navigation to success. This handler owns no authentication,
// POST completion, cookies, envelope consumption or resources; the caller must
// compose the separately authenticated native POST adapter at the same path.
func NewProxyHandoffLanding(endpoint, success string) (http.Handler, error) {
	destination, err := proxyHandoffEndpoint(endpoint)
	if err != nil || destination.Path == "/" {
		return nil, identityhttp.ErrInvalidInput
	}
	completed, err := proxyHandoffEndpoint(success)
	if err != nil || destination.Host != completed.Host || destination.Path == completed.Path {
		return nil, identityhttp.ErrInvalidInput
	}
	page := "<!doctype html><html><head><meta charset=\"utf-8\"></head><body data-success=\"" + html.EscapeString(completed.Path) + "\"><script>" + proxyHandoffScript + "</script></body></html>"
	digest := sha256.Sum256([]byte(proxyHandoffScript))
	csp := "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", csp)
		if !proxyHandoffLandingRequest(r, destination) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	}), nil
}

func proxyHandoffLandingRequest(r *http.Request, endpoint *url.URL) bool {
	if r == nil || r.URL == nil || r.TLS == nil || r.Host != endpoint.Host || r.Method != http.MethodGet {
		return false
	}
	u := r.URL
	if u.Path != endpoint.Path || u.EscapedPath() != endpoint.Path || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.User != nil || u.Opaque != "" {
		return false
	}
	if u.Scheme != "" && u.Scheme != "https" || u.Host != "" && u.Host != endpoint.Host {
		return false
	}
	return r.ContentLength == 0 && (r.Body == nil || r.Body == http.NoBody) && len(r.TransferEncoding) == 0 && len(r.Trailer) == 0
}

// Keep the DNS/port/path profile aligned with oauth/proxy's registered
// PreviewTarget: it deliberately excludes wildcard, IDN and IP registrations.
// This is syntax validation, not production's separate exact allowlist check.
func proxyHandoffEndpoint(raw string) (*url.URL, error) {
	if len(raw) < 1 || len(raw) > 2048 || strings.ContainsAny(raw, "\\#*%") {
		return nil, identityhttp.ErrInvalidInput
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "https://") || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.String() != raw || u.Path == "" || path.Clean(u.Path) != u.Path {
		return nil, identityhttp.ErrInvalidInput
	}
	host := u.Hostname()
	if len(host) < 1 || len(host) > 253 || !strings.Contains(host, ".") || host != strings.ToLower(host) {
		return nil, identityhttp.ErrInvalidInput
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.HasPrefix(label, "xn--") {
			return nil, identityhttp.ErrInvalidInput
		}
		for i := range len(label) {
			b := label[i]
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	if top := labels[len(labels)-1][0]; top < 'a' || top > 'z' {
		return nil, identityhttp.ErrInvalidInput
	}
	port := u.Port()
	if port == "" {
		if u.Host != host {
			return nil, identityhttp.ErrInvalidInput
		}
	} else {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || number == 443 || strconv.Itoa(number) != port || u.Host != host+":"+port {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	return u, nil
}

// The script is independent of configuration so its CSP hash stays fixed.
// Configured success is escaped HTML data, never executable JavaScript.
// Fetch section 3.2 (https://fetch.spec.whatwg.org/#origin-header) requires CORS
// mode to retain the actual Origin on a no-referrer POST. The exact relative
// URL, CSP connect-src 'self' and redirect rejection still confine this request.
const proxyHandoffScript = `(async () => {
"use strict";
const fragment = location.hash;
try {
  history.replaceState(null, "", location.pathname);
  const prefix = "#identity-proxy-v1.";
  if (location.search !== "" || fragment.length > prefix.length + 22 + 1 + 10923 || !fragment.startsWith(prefix)) return;
  const fields = fragment.slice(prefix.length).split(".");
  if (fields.length !== 2) return;
  const [flow, envelope] = fields;
  if (flow.length !== 22 || envelope.length < 2 || envelope.length > 10923) return;
  const decode = (encoded) => {
    if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return null;
    const decoded = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
    const canonical = btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return canonical === encoded ? decoded : null;
  };
  const flowBytes = decode(flow);
  const envelopeBytes = decode(envelope);
  if (flowBytes === null || flowBytes.length !== 16 || !Array.from(flowBytes).some((byte) => byte.charCodeAt(0) !== 0)) return;
  if (envelopeBytes === null || envelopeBytes.length < 1 || envelopeBytes.length > 8192) return;
  const response = await fetch(location.pathname, {
    method: "POST",
    mode: "cors",
    credentials: "same-origin",
    referrerPolicy: "no-referrer",
    redirect: "error",
    cache: "no-store",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({flow, envelope}),
    signal: AbortSignal.timeout(15000)
  });
  if (response.status === 204) location.replace(document.body.dataset.success);
} catch {
  // Failure leaves a neutral page without disclosing the handoff.
}
})();`
