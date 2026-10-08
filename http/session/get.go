// Package sessionhttp supplies explicitly selected session HTTP integrations.
// Base identity/http does not import this module or any optional session owner.
package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// GetConfig explicitly selects one transport and immutable network policy.
// Sessions and Rate must be valid owner-constructed, concurrency-safe services;
// they remain borrowed and must outlive requests. Share Rate across all routes,
// never construct it per request. Cookie must be valid even in bearer mode.
// Now is a trusted prompt concurrency-safe clock. MaximumDuration is 1ms..30s;
// earlier inbound deadlines win. Construction copies network configuration.
type GetConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Rate            *identityhttp.SafeRateLimiter
	Transport       session.CredentialKind
	Cookie          session.CookiePolicy
	Now             func() time.Time
	MaximumDuration time.Duration
}

// GetResponse is the explicit credential-free read projection. It conveys no
// reusable authentication authority. Unauthenticated responses omit all subject
// and session fields. Sensitive extension/enrichment data is not implicit.
type GetResponse struct {
	Authenticated     bool       `json:"authenticated"`
	Principal         *Principal `json:"principal,omitempty"`
	Session           *Session   `json:"session,omitempty"`
	NeedsRefresh      bool       `json:"needsRefresh"`
	RefreshEligibleAt *time.Time `json:"refreshEligibleAt,omitempty"`
}

// Principal identifies only the admitted owner and exact host-mapped tenant.
// It is response metadata, not an authorization proof.
type Principal struct {
	TenantID identity.TenantID `json:"tenantID"`
	UserID   identity.UserID   `json:"userID"`
}

// Session exposes stable public read metadata, never lookup/CSRF digests,
// authority vectors, credential IDs, historical proofs or bearer material.
type Session struct {
	ID                string    `json:"id"`
	IssuedAt          time.Time `json:"issuedAt"`
	LastActivityAt    time.Time `json:"lastActivityAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	AbsoluteExpiresAt time.Time `json:"absoluteExpiresAt"`
}

// NewGetHandler constructs only GET /v1/session/get, without registration or IO.
// It validates the request envelope, exact HTTPS tenant host, non-keyed empty
// request and explicitly selected credential channel before owner access.
// Cookie mode rejects Authorization; bearer mode ignores ambient cookies and
// never falls back. All decisions use canonical rate.safe admission. Positive
// owner custody is checked again after rate work, preserving original expiry.
// Success is 200 authenticated metadata or enumeration-safe unauthenticated;
// malformed input is 400, wrong host/realm 421, wrong path 404/method 405,
// rate denial 429 with Retry-After, operational/cancellation failure 503.
// Every response is no-store, nosniff JSON and never emits Set-Cookie. No read
// updates activity, rotates credentials, refreshes authority or starts work in
// a goroutine. The server retains body/connection cleanup and bounded writes.
// This handler alone is not full feature/router/OpenAPI or browser qualification.
func NewGetHandler(c GetConfig) (http.Handler, error) {
	if !c.Sessions.Configured() || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || (c.Transport != session.CredentialCookie && c.Transport != session.CredentialBearer) {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Nothing writes before a complete bounded result has been prepared.
		defer func() {
			if recover() != nil {
				response(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			}
		}()
		if r == nil || r.URL == nil {
			response(w, 400, `{"error":"invalid_request"}`)
			return
		}
		if r.URL.Path != "/v1/session/get" || r.URL.EscapedPath() != "/v1/session/get" {
			response(w, 404, `{"error":"not_found"}`)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			response(w, 405, `{"error":"method_not_allowed"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), c.MaximumDuration)
		defer cancel()
		r = r.WithContext(ctx)
		if ctx.Err() != nil {
			response(w, 503, `{"error":"unavailable"}`)
			return
		}
		if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.Trailer) != 0 {
			response(w, 400, `{"error":"invalid_request"}`)
			return
		}
		facts, err := network.Resolve(r)
		if err != nil {
			var invalid identityhttp.DecodeError
			if errors.As(err, &invalid) {
				response(w, 421, `{"error":"misdirected_request"}`)
			} else {
				response(w, 503, `{"error":"unavailable"}`)
			}
			return
		}
		if facts.Realm() != identityhttp.RealmTenant {
			response(w, 421, `{"error":"misdirected_request"}`)
			return
		}
		if facts.Scheme() != "https" {
			response(w, 400, `{"error":"invalid_request"}`)
			return
		}
		requirement := identityhttp.HeaderForbidden
		if c.Transport == session.CredentialBearer {
			requirement = identityhttp.HeaderOptional
		}
		bearer, present, err := decoder.Bearer(r, requirement)
		if err != nil {
			response(w, 400, `{"error":"invalid_request"}`)
			return
		}
		wire := ""
		if c.Transport == session.CredentialBearer {
			if present {
				wire = bearer.Token()
			}
		} else {
			wire, err = cookieToken(r.Header, cookie.Name)
			if err != nil {
				response(w, 400, `{"error":"invalid_request"}`)
				return
			}
		}
		var result session.GetResult
		if wire != "" {
			token, parseErr := session.ParseToken(wire)
			if parseErr != nil {
				response(w, 400, `{"error":"invalid_request"}`)
				return
			}
			credential, _ := session.NewCredential(c.Transport, token)
			result, err = c.Sessions.Get(ctx, session.GetRequest{TenantID: facts.TenantID(), Credential: credential})
			if err != nil {
				response(w, 503, `{"error":"unavailable"}`)
				return
			}
		}
		out := GetResponse{}
		var user identity.UserID
		if result.Authenticated {
			if result.ValidateAt(c.Now()) != nil {
				response(w, 503, `{"error":"unavailable"}`)
				return
			}
			spec, bindingErr := result.Session.Bindings()
			if bindingErr != nil || spec.TenantID != facts.TenantID() {
				response(w, 503, `{"error":"unavailable"}`)
				return
			}
			user = spec.UserID
			lifetime, lifetimeErr := result.Session.Lifetime(c.Now())
			if lifetimeErr != nil {
				response(w, 503, `{"error":"unavailable"}`)
				return
			}
			eligible := result.RefreshEligibleAt.UTC()
			out = GetResponse{Authenticated: true, Principal: &Principal{TenantID: spec.TenantID, UserID: user}, Session: &Session{ID: spec.SessionID, IssuedAt: spec.IssuedAt.UTC(), LastActivityAt: spec.LastActivityAt.UTC(), ExpiresAt: lifetime.ExpiresAt.UTC(), AbsoluteExpiresAt: lifetime.AbsoluteExpiresAt.UTC()}, NeedsRefresh: result.NeedsRefresh, RefreshEligibleAt: &eligible}
		}
		admitted, err := c.Rate.Admit(ctx, facts, "identity.session.get", user)
		if errors.Is(err, identityhttp.ErrRateLimited) {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((admitted.RetryAfter+time.Second-1)/time.Second), 10))
			response(w, 429, `{"error":"rate_limited"}`)
			return
		}
		if err != nil || !admitted.Allowed || ctx.Err() != nil || (result.Authenticated && result.ValidateAt(c.Now()) != nil) {
			response(w, 503, `{"error":"unavailable"}`)
			return
		}
		body, err := json.Marshal(out)
		if err != nil {
			response(w, 503, `{"error":"unavailable"}`)
			return
		}
		response(w, 200, string(body))
	}), nil
}

func response(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(body + "\n"))
}

func cookieToken(headers http.Header, name string) (string, error) {
	count, total := 0, 0
	selected := ""
	found := false
	for key, values := range headers {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, raw := range values {
			total += len(raw)
			if total > 16384 || raw == "" {
				return "", identityhttp.DecodeError{}
			}
			for _, part := range strings.Split(raw, ";") {
				count++
				if count > 32 {
					return "", identityhttp.DecodeError{}
				}
				part = strings.Trim(part, " \t")
				n, v, ok := strings.Cut(part, "=")
				if !ok || !cookieName(n) {
					return "", identityhttp.DecodeError{}
				}
				quoted := len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"'
				if quoted {
					v = v[1 : len(v)-1]
				}
				for i := range len(v) {
					b := v[i]
					if !(b == 0x21 || b >= 0x23 && b <= 0x2b || b >= 0x2d && b <= 0x3a || b >= 0x3c && b <= 0x5b || b >= 0x5d && b <= 0x7e) {
						return "", identityhttp.DecodeError{}
					}
				}
				if n == name {
					if found || quoted || len(v) == 0 || len(part) > 3800 {
						return "", identityhttp.DecodeError{}
					}
					found, selected = true, v
				}
			}
		}
	}
	return selected, nil
}

func cookieName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b <= 32 || b >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(b)) {
			return false
		}
	}
	return true
}
