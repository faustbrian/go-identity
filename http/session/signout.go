package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// SignOutConfig selects the same immutable transport/network/rate profile as
// GetConfig. Exactly the selected CookieSignOut or BearerSignOut is required;
// compose it with the same primary SessionService and cookie policy. Cookie
// mode requires 1..128 exact trusted HTTPS origins and denies Referer fallback.
// Bearer mode rejects TrustedOrigins rather than silently using cookie policy.
// Services are borrowed, concurrency-safe and must outlive requests; no IO or
// resource ownership is transferred at construction.
type SignOutConfig struct {
	GetConfig
	CookieSignOut  *session.CookieSignOutService
	BearerSignOut  *session.SignOutService
	TrustedOrigins []identityhttp.Origin
}

// SignOutRecovery is the original durable command's exact scope locator, not
// authorization or renewed authentication. Query the owned recovery service
// under current result-access policy before retrying an ambiguous operation.
// These fields never contain credentials, digests, proof or CSRF material.
type SignOutRecovery struct {
	CommandID       identity.CommandID        `json:"commandID"`
	TenantID        identity.TenantID         `json:"tenantID"`
	UserID          identity.UserID           `json:"userID,omitempty"`
	AnonymousFlowID string                    `json:"anonymousFlowID,omitempty"`
	ActorID         identity.ActorID          `json:"actorID"`
	ActorKind       authorization.SubjectKind `json:"actorKind"`
	OperationID     string                    `json:"operationID"`
	RecordID        string                    `json:"recordID,omitempty"`
	LinkMode        identity.AccountLinkMode  `json:"linkMode,omitempty"`
}

// SignOutResponse is the explicit credential-free success/error projection.
// CommitOutcome is none, not_committed, committed, unknown, conflict or
// in_progress. none means no authoritative command observation, not rollback.
// A committed observation accompanied by an error does not clear transport.
// ClearBearer instructs the caller to discard only its presented bearer after
// success; cookie removal is conveyed only by the exact Set-Cookie tuple.
// CommandID is generated once per admitted call and never replaced or retried.
type SignOutResponse struct {
	SignedOut     bool               `json:"signedOut"`
	ClearBearer   bool               `json:"clearBearer"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	Recovery      *SignOutRecovery   `json:"recovery,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// NewSignOutHandler constructs only POST /v1/session/signout. Bodies are strict
// JSON {} or URL-encoded empty fields/one csrf_token; JSON CSRF uses exactly one
// X-CSRF-Token header. Query parameters and Idempotency-Key are forbidden. Token
// absence reaches the domain owner: absent/inactive logout succeeds, but active
// cookie logout requires exact primary transaction-bound CSRF. Present empty,
// duplicate, malformed or mixed channels always deny. Bearer rejects CSRF input
// and ignores ambient cookies, never falling back or deleting their transport.
// Exact HTTPS host determines tenant. rate.safe admission precedes mutation;
// subject discovery is a primary read, not preauthentication database limiting.
// Only committed error-free or absent/inactive success clears transport. Errors
// preserve original command/outcome/recovery without automatic retries. Status
// codes are 200 success, 400 malformed, 403 denial, 404 path, 405 method, 421 host,
// 429 rate, 409 conflict/in-progress and 503 unavailable/ambiguous/canceled.
// Responses are no-store/nosniff JSON. Whole-request deadlines never extend the
// inbound deadline. No goroutines, stores, transactions or journals are added;
// the server retains bounded body/read/write cleanup. This is not full feature,
// OpenAPI, native HTTP/browser or release qualification.
func NewSignOutHandler(c SignOutConfig) (http.Handler, error) {
	if _, err := NewGetHandler(c.GetConfig); err != nil {
		return nil, err
	}
	if c.Transport == session.CredentialCookie {
		if c.CookieSignOut == nil || c.BearerSignOut != nil {
			return nil, identityhttp.ErrInvalidInput
		}
	} else if c.BearerSignOut == nil || c.CookieSignOut != nil || len(c.TrustedOrigins) != 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	network, _ := identityhttp.NewNetworkResolver(c.Network)
	decoder, _ := identityhttp.NewRequestDecoder(c.Network.Limits)
	cookie, _ := c.Cookie.DeletionAttributes()
	var origins *identityhttp.OriginGuard
	if c.Transport == session.CredentialCookie {
		var err error
		origins, err = identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
		if err != nil {
			return nil, err
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := SignOutResponse{CommitOutcome: "none"}
		send := func(status int, code string) {
			out.Error = code
			body, err := json.Marshal(out)
			if err != nil {
				response(w, 503, `{"error":"unavailable"}`)
				return
			}
			response(w, status, string(body))
		}
		defer func() {
			if recover() != nil {
				out.SignedOut = false
				out.ClearBearer = false
				send(503, "unavailable")
			}
		}()
		if r == nil || r.URL == nil {
			send(400, "invalid_request")
			return
		}
		if r.URL.Path != "/v1/session/signout" || r.URL.EscapedPath() != "/v1/session/signout" {
			send(404, "not_found")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			send(405, "method_not_allowed")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), c.MaximumDuration)
		defer cancel()
		r = r.WithContext(ctx)
		if ctx.Err() != nil {
			send(503, "unavailable")
			return
		}
		if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
			send(400, "invalid_request")
			return
		}
		facts, err := network.Resolve(r)
		if err != nil {
			var invalid identityhttp.DecodeError
			if errors.As(err, &invalid) {
				send(421, "misdirected_request")
			} else {
				send(503, "unavailable")
			}
			return
		}
		if facts.Realm() != identityhttp.RealmTenant {
			send(421, "misdirected_request")
			return
		}
		if facts.Scheme() != "https" {
			send(400, "invalid_request")
			return
		}
		if origins != nil {
			if _, err := origins.Check(r); err != nil {
				send(403, "origin_denied")
				return
			}
		}
		csrf, err := logoutInput(decoder, r, c.Transport)
		if err != nil {
			if ctx.Err() != nil {
				send(503, "unavailable")
			} else {
				send(400, "invalid_request")
			}
			return
		}
		requirement := identityhttp.HeaderForbidden
		if c.Transport == session.CredentialBearer {
			requirement = identityhttp.HeaderOptional
		}
		bearer, present, err := decoder.Bearer(r, requirement)
		if err != nil {
			send(400, "invalid_request")
			return
		}
		wire := ""
		if c.Transport == session.CredentialCookie {
			wire, err = cookieToken(r.Header, cookie.Name)
		} else if present {
			wire = bearer.Token()
		}
		if err != nil {
			send(400, "invalid_request")
			return
		}
		var credential session.Credential
		var user identity.UserID
		if wire != "" {
			token, err := session.ParseToken(wire)
			if err != nil {
				send(400, "invalid_request")
				return
			}
			credential, _ = session.NewCredential(c.Transport, token)
			caller, err := c.Sessions.Get(ctx, session.GetRequest{TenantID: facts.TenantID(), Credential: credential})
			if err != nil {
				send(503, "unavailable")
				return
			}
			if caller.Authenticated {
				b, err := caller.Session.Bindings()
				if err != nil || b.TenantID != facts.TenantID() || caller.ValidateAt(c.Now()) != nil {
					send(503, "unavailable")
					return
				}
				user = b.UserID
			}
		}
		admitted, err := c.Rate.Admit(ctx, facts, "identity.session.signout", user)
		if errors.Is(err, identityhttp.ErrRateLimited) {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((admitted.RetryAfter+time.Second-1)/time.Second), 10))
			send(429, "rate_limited")
			return
		}
		if err != nil || !admitted.Allowed || ctx.Err() != nil {
			send(503, "unavailable")
			return
		}
		id, err := identity.NewCommandID()
		if err != nil {
			send(503, "unavailable")
			return
		}
		out.CommandID = id
		request := session.SignOutRequest{TenantID: facts.TenantID(), CommandID: id, CorrelationID: string(id), Transport: c.Transport, Credential: credential}
		var result session.SignOutResult
		if c.Transport == session.CredentialCookie {
			result, err = c.CookieSignOut.SignOut(ctx, request, csrf)
		} else {
			result, err = c.BearerSignOut.SignOut(ctx, request)
		}
		out.CommitOutcome = logoutOutcome(result.CommitOutcome)
		if q := result.Recovery; q.CommandID != "" {
			out.Recovery = &SignOutRecovery{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, RecordID: q.RecordID, LinkMode: q.LinkMode}
		}
		if err != nil || ctx.Err() != nil || !result.SignedOut || result.CommandID != id {
			var forbidden identity.ForbiddenError
			switch {
			case errors.Is(err, session.ErrCSRFDenied), errors.Is(err, session.ErrUnauthenticated), errors.As(err, &forbidden):
				send(403, "denied")
			case result.CommitOutcome == identity.CommitOutcomeConflict:
				send(409, "conflict")
			case result.CommitOutcome == identity.CommitOutcomeInProgress:
				w.Header().Set("Retry-After", strconv.FormatInt(int64((result.RetryAfter+time.Second-1)/time.Second), 10))
				send(409, "in_progress")
			default:
				send(503, "unavailable")
			}
			return
		}
		if c.Transport == session.CredentialCookie {
			if !result.ClearCookie || result.ClearBearer || result.Cookie.String() != cookie.String() {
				send(503, "unavailable")
				return
			}
			http.SetCookie(w, &cookie)
		} else {
			if !result.ClearBearer || result.ClearCookie {
				send(503, "unavailable")
				return
			}
			out.ClearBearer = true
		}
		out.SignedOut = true
		send(200, "")
	}), nil
}

// Optional syntax is workflow-specific: absence is not CSRF admission. Only the
// domain owner can distinguish inactive success from an active protected call.
// Base codecs still own media, framing, raw/decoded bounds and duplicate fields.
func logoutInput(d *identityhttp.RequestDecoder, r *http.Request, mode session.CredentialKind) (session.CSRFToken, error) {
	wire := ""
	found := false
	for name, values := range r.Header {
		if strings.EqualFold(name, "X-CSRF-Token") {
			if found || len(values) != 1 || values[0] == "" {
				return session.CSRFToken{}, identityhttp.DecodeError{}
			}
			wire, found = values[0], true
		}
	}
	// Try the owning strict codec for the selected media, without reading the
	// body twice. Its complete Content-Type validation remains authoritative.
	jsonBody := false
	for name, values := range r.Header {
		if strings.EqualFold(name, "Content-Type") && len(values) == 1 {
			jsonBody = strings.HasPrefix(strings.ToLower(values[0]), "application/json")
		}
	}
	if jsonBody {
		if _, err := identityhttp.DecodeJSON[struct{}](d, r); err != nil {
			return session.CSRFToken{}, err
		}
	} else {
		fields, err := d.Form(r)
		if err != nil {
			return session.CSRFToken{}, err
		}
		for name, values := range fields {
			if name != "csrf_token" || found || mode != session.CredentialCookie || len(values) != 1 || values[0] == "" {
				return session.CSRFToken{}, identityhttp.DecodeError{}
			}
			wire, found = values[0], true
		}
	}
	if !found {
		return session.CSRFToken{}, nil
	}
	if mode != session.CredentialCookie {
		return session.CSRFToken{}, identityhttp.DecodeError{}
	}
	token, err := session.ParseCSRFToken(wire)
	if err != nil {
		return session.CSRFToken{}, identityhttp.DecodeError{}
	}
	return token, nil
}

func logoutOutcome(outcome identity.CommitOutcome) string {
	switch outcome {
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	default:
		return "none"
	}
}
