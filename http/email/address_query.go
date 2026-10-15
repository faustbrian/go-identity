package emailhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// AddressQueryService supplies authorized primary email observations, not
// caller-created projections, authentication or mutation. The concrete native
// email owner and reference handle implement this consumer-owned port.
type AddressQueryService interface {
	AddressGet(context.Context, email.AddressGetRequest) (email.AddressGetResult, error)
	AddressList(context.Context, email.AddressListRequest) (email.AddressListResult, error)
}

// AdministrativeAddressQueryService supplies mandatory native access auditing.
// Configuration is not permission: each read still authorizes the real actor
// against its explicit tenant, action and target before disclosing any data.
type AdministrativeAddressQueryService interface {
	AddressQueryService
	AdministrativeQueriesConfigured() bool
}

func administrativeQueriesConfigured(service AddressQueryService) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	owner, ok := service.(AdministrativeAddressQueryService)
	return ok && owner.AdministrativeQueriesConfigured()
}

// AddressQueryConfig selects cookie-authenticated human reads. Admin-target
// reads require explicit AdministrativeTargets and native auditing; bearer
// profiles are not enabled. Service/Sessions share native
// primary authority; the canonical safe Rate is shared with other safe routes.
// All owners and prompt Now remain borrowed, bounded and concurrency-safe.
// Positive PolicyRevision is trusted startup policy. MaximumDuration is 1ms..30s;
// earlier cancellation and original session validity win through final delivery.
type AddressQueryConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         AddressQueryService
	Rate            *identityhttp.SafeRateLimiter
	Cookie          session.CookiePolicy
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
	// AdministrativeTargets explicitly permits a targetSubjectID selector, never
	// an authorization claim. The service must support required native auditing.
	AdministrativeTargets bool
}

// AddressView is explicitly disclosed personal metadata, not an authentication
// or freshness lease. Omitted canonical/display values remain omitted. Never log
// these DTOs; they belong only in the authorized no-store response.
type AddressView struct {
	IdentifierID        identity.IdentifierID `json:"identifierID"`
	UserID              identity.UserID       `json:"userID"`
	Canonical           string                `json:"canonical,omitempty"`
	Display             string                `json:"display,omitempty"`
	Primary             bool                  `json:"primary"`
	Verified            bool                  `json:"verified"`
	IdentifierVersion   uint64                `json:"identifierVersion"`
	VerificationVersion uint64                `json:"verificationVersion"`
}

// Native identifier snapshots retain up to512 bytes per value. A page of100
// maximally JSON-escaped values and IDs must fit without silently truncating
// valid primary data. This bound includes the complete serialized response.
const maximumAddressResponse = 1 << 20

type addressParameters struct {
	target identity.UserID
	id     identity.IdentifierID
	limit  uint32
	cursor email.Cursor
}

func decodeAddressQuery(values url.Values, get bool, administrative ...bool) (out addressParameters, err error) {
	invalid := identityhttp.ErrInvalidInput
	if len(administrative) > 1 {
		return out, invalid
	}
	admin := len(administrative) == 1 && administrative[0]
	for key, items := range values {
		if len(items) != 1 || items[0] == "" {
			return out, invalid
		}
		v := items[0]
		if key == "targetSubjectID" {
			if !admin {
				return out, invalid
			}
			id, e := identity.ParseIdentifierID(v)
			if e != nil {
				return out, invalid
			}
			out.target = identity.UserID(id)
			continue
		}
		if get {
			if key != "addressID" {
				return out, invalid
			}
			id, e := identity.ParseIdentifierID(v)
			if e != nil {
				return out, invalid
			}
			out.id = id
			continue
		}
		switch key {
		case "limit":
			n, e := strconv.ParseUint(v, 10, 32)
			if e != nil || n < 1 || n > 100 || strconv.FormatUint(n, 10) != v {
				return out, invalid
			}
			out.limit = uint32(n)
		case "cursor":
			if len(v) > 512 {
				return out, invalid
			}
			out.cursor = email.Cursor(v)
		default:
			return out, invalid
		}
	}
	if get && out.id == "" {
		return out, invalid
	}
	return out, nil
}

type addressState struct {
	facts      identityhttp.NetworkFacts
	credential session.Credential
	original   session.GetResult
	user       identity.UserID
	parameters addressParameters
}

func (addressState) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "emailhttp.addressState(redacted)")
}
func (addressState) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
func (addressState) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// NewAddressGetHandler constructs GET /v1/email/address-get?addressID=... only.
// Exact HTTPS tenant and one actual session cookie are required. Requests with
// a body, trailers, Authorization or Idempotency-Key headers deny. Unknown or
// duplicate queries and unselected target overrides also deny. Absence/foreign/forbidden
// addresses share one denial. No credentials,
// cookies, refresh, mutation, command or recovery are emitted.
func NewAddressGetHandler(c AddressQueryConfig) (http.Handler, error) {
	return newAddressQueryHandler(c, nil, true)
}

// NewAddressListHandler constructs GET /v1/email/address-list with optional
// canonical limit1..100 and native cursor<=512 bytes. It shares get's authority,
// cancellation/no-store guarantees. Only explicit AdministrativeTargets accepts
// targetSubjectID, without granting authority or changing the authenticated actor.
func NewAddressListHandler(c AddressQueryConfig) (http.Handler, error) {
	return newAddressQueryHandler(c, nil, false)
}

func newAddressQueryHandler(c AddressQueryConfig, m []identityhttp.MiddlewareDescriptor, get bool) (http.Handler, error) {
	if !c.Sessions.Configured() || nilService(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	if c.AdministrativeTargets && !administrativeQueriesConfigured(c.Service) {
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
	action, path := "identity.email.address-list", "/v1/email/address-list"
	if get {
		action, path = "identity.email.address-get", "/v1/email/address-get"
	}
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
		f := failure{503, "unavailable", 0}
		var denied identity.ForbiddenError
		var invalid identity.InvalidInputError
		if errors.As(err, &denied) {
			f = failure{403, "denied", 0}
		}
		if errors.Is(err, identityhttp.ErrInvalidInput) || errors.As(err, &invalid) {
			f = failure{400, "invalid_request", 0}
		}
		var specific failure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodGet)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(f.retry, time.Hour)+time.Second-1)/time.Second), 10))
		}
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"error":"`+f.code+`"}`)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[addressState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (addressState, error) {
			var s addressState
			if r.URL.Path != path || r.URL.EscapedPath() != path {
				return s, failure{404, "not_found", 0}
			}
			if r.Method != http.MethodGet {
				return s, failure{405, "method_not_allowed", 0}
			}
			if _, _, e := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, e := decoder.Bearer(r, identityhttp.HeaderForbidden); e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Body != nil && r.Body != http.NoBody || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			values, e := decoder.Query(r)
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.parameters, e = decodeAddressQuery(values, get, c.AdministrativeTargets)
			if e != nil {
				return s, e
			}
			s.facts, e = network.Resolve(r)
			if e != nil || s.facts.Realm() != identityhttp.RealmTenant {
				return s, failure{421, "misdirected_request", 0}
			}
			if s.facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			bearer, present, e := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderOptional)
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if !present {
				return s, failure{403, "denied", 0}
			}
			token, e := session.ParseToken(bearer.Token())
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, e = session.NewCredential(session.CredentialCookie, token)
			return s, e
		},
		Authenticate: func(r *http.Request, s addressState) (addressState, error) {
			got, e := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if e != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !got.Authenticated || got.ValidateAt(c.Now()) != nil {
				return s, failure{403, "denied", 0}
			}
			b, e := got.Session.Bindings()
			if e != nil || b.TenantID != s.facts.TenantID() || b.Authentication.Kind == session.AuthenticationAnonymous {
				return s, failure{403, "denied", 0}
			}
			s.original, s.user = got, b.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s addressState) error {
			admitted, e := c.Rate.Admit(r.Context(), s.facts, action, s.user)
			if errors.Is(e, identityhttp.ErrRateLimited) {
				return failure{429, "rate_limited", admitted.RetryAfter}
			}
			if e != nil || !admitted.Allowed || r.Context().Err() != nil || s.original.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s addressState) {
			if s.original.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			target := s.user
			if s.parameters.target != "" {
				target = s.parameters.target
			}
			administrative := c.AdministrativeTargets && target != s.user
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: action, Request: authorization.Request{Tenant: authorization.TenantID(s.facts.TenantID()), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.user)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(target)}, Environment: authorization.Environment{Time: c.Now().UTC()}}}
			var result any
			if get {
				out, e := c.Service.AddressGet(r.Context(), email.AddressGetRequest{TenantID: s.facts.TenantID(), TargetSubjectID: target, AddressID: s.parameters.id, Caller: caller})
				if e != nil {
					reject(w, r, e)
					return
				}
				view, e := addressTargetView(out.Address, s.facts.TenantID(), target, c.Now(), administrative)
				if e != nil {
					reject(w, r, e)
					return
				}
				if out.Outcome != identity.CommitOutcomeNotCommitted || view.IdentifierID != s.parameters.id {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				result = struct {
					Address AddressView `json:"address"`
				}{view}
			} else {
				out, e := c.Service.AddressList(r.Context(), email.AddressListRequest{TenantID: s.facts.TenantID(), TargetSubjectID: target, Limit: s.parameters.limit, Cursor: s.parameters.cursor, Caller: caller})
				if e != nil {
					reject(w, r, e)
					return
				}
				limit := s.parameters.limit
				if limit == 0 {
					limit = 25
				}
				if out.Outcome != identity.CommitOutcomeNotCommitted || out.Addresses == nil || len(out.Addresses) > int(limit) || len(out.NextCursor) > 512 {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				views := make([]AddressView, 0, len(out.Addresses))
				for _, p := range out.Addresses {
					view, e := addressTargetView(p, s.facts.TenantID(), target, c.Now(), administrative)
					if e != nil {
						reject(w, r, e)
						return
					}
					if len(views) > 0 && views[len(views)-1].IdentifierID >= view.IdentifierID {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
					views = append(views, view)
				}
				result = struct {
					Addresses  []AddressView `json:"addresses"`
					NextCursor email.Cursor  `json:"nextCursor,omitempty"`
				}{views, out.NextCursor}
			}
			body, e := json.Marshal(result)
			if e != nil || len(body) > maximumAddressResponse {
				clear(body)
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			defer clear(body)
			if r.Context().Err() != nil || s.original.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			writeAddressJSON(w, r, body, func() bool { return s.original.ValidateAt(c.Now()) == nil })
		},
	})
	if err != nil {
		return nil, err
	}
	return &confirmationPipeline{pipeline: &addressPipeline{pipeline: pipeline}}, nil
}

func addressView(p identity.IdentifierProjection, tenant identity.TenantID, user identity.UserID, now time.Time) (AddressView, error) {
	return addressTargetView(p, tenant, user, now, false)
}

func addressTargetView(p identity.IdentifierProjection, tenant identity.TenantID, user identity.UserID, now time.Time, administrative bool) (AddressView, error) {
	b, e := p.Bindings()
	if e != nil || b.TenantID != tenant || b.UserID != user || b.Kind != identity.IdentifierEmail || now.IsZero() || b.ObservedAt.After(now) {
		return AddressView{}, identityhttp.ErrUnavailable
	}
	// Self reads must deny a newly blocked identity even if preliminary session
	// evidence has time remaining. Explicitly authorized administrative reads
	// may inspect blocked targets; they never authenticate as those targets.
	if !administrative && b.Status != identity.StatusActive {
		return AddressView{}, identity.ForbiddenError{}
	}
	canonical, display, visible := p.Values()
	if len(canonical) > 512 || len(display) > 512 {
		return AddressView{}, identityhttp.ErrUnavailable
	}
	if !visible {
		canonical, display = "", ""
	}
	return AddressView{b.IdentifierID, b.UserID, canonical, display, b.Primary, b.Verified, b.IdentifierVersion, b.VerificationVersion}, nil
}

// Format redacts borrowed authority and deployment policy.
func (AddressQueryConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "emailhttp.AddressQueryConfig(redacted)")
}

// LogValue emits no credential, address or policy metadata.
func (AddressQueryConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.AddressQueryConfig(redacted)")
}

// MarshalJSON denies implicit deployment export.
func (AddressQueryConfig) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit deployment export.
func (AddressQueryConfig) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
