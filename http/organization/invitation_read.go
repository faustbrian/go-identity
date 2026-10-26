package organizationhttp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

// InvitationReader is the neutral current-read port implemented directly by
// the native invitation owner. Get remains owner-only; ListMine authenticates
// the current verified recipient without requiring organization membership.
// Both methods must honor ctx and support concurrent independent requests.
type InvitationReader interface {
	Get(context.Context, organization.InvitationReadRequest) (organization.InvitationDelivery, error)
	ListMine(context.Context, organization.InvitationListMineRequest) (organization.InvitationListMineResult, error)
}

// InvitationLister owns current organization-owner authorization and a bounded
// invitation-ID keyset page. It must honor ctx, support concurrent calls and
// return no partial page on failure. A cursor is not authority or a snapshot.
// This separate port preserves existing InvitationReader implementations.
type InvitationLister interface {
	List(context.Context, organization.InvitationReadRequest) (organization.InvitationPage, error)
}

// InvitationListResponse contains safe organization-scoped invitation metadata.
// NextCursor is the last returned ID when more rows exist; reuse it unchanged
// with the same organization. Every request rechecks current owner authority.
type InvitationListResponse struct {
	Invitations []InvitationView `json:"invitations"`
	NextCursor  organization.ID  `json:"nextCursor,omitempty"`
}

// InvitationView is explicit safe metadata, never an address, delivery custody,
// capability or permission to accept. Status is a closed lowercase lifecycle.
type InvitationView struct {
	ID             organization.ID   `json:"id"`
	OrganizationID organization.ID   `json:"organizationID"`
	Role           organization.Role `json:"role"`
	Status         string            `json:"status"`
	Version        uint64            `json:"version"`
	ExpiresAt      time.Time         `json:"expiresAt"`
}

// InvitationReadResponse contains only the selected current owner's metadata.
type InvitationReadResponse struct {
	Invitation InvitationView `json:"invitation"`
}

// InvitationListMineResponse is a bounded current-state page, not a snapshot.
// Return NextCursor unchanged for this same current subject; it grants no access.
type InvitationListMineResponse struct {
	Invitations []InvitationView              `json:"invitations"`
	NextCursor  organization.InvitationCursor `json:"nextCursor,omitempty"`
}

type invitationInput struct {
	facts       identityhttp.NetworkFacts
	auth        organization.Authentication
	observed    session.GetResult
	actor       identity.UserID
	org, id     organization.ID
	cursor      organization.InvitationCursor
	limit       uint32
	correlation string
}
type invitationState struct{ input func() *invitationInput }

// Principal exposes detached current actor metadata, never credential custody.
func (s invitationState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.input == nil {
		return "", "", false
	}
	in := s.input()
	return in.auth.TenantID, in.actor, in.actor != ""
}
func (invitationState) Format(s fmt.State, _ rune) {
	s.Write([]byte("organizationhttp.InvitationState(redacted)"))
}
func (invitationState) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (invitationState) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (invitationState) LogValue() slog.Value {
	return slog.StringValue("organizationhttp.InvitationState(redacted)")
}

func invitationPath(op organization.Operation) string {
	if op == organization.InvitationGet {
		return "/v1/organization/invitation/get"
	}
	if op == organization.InvitationListMine {
		return "/v1/organization/invitation/list-mine"
	}
	if op == organization.InvitationList {
		return "/v1/organization/invitation/list"
	}
	return ""
}
func newInvitationHandler(c Config, op organization.Operation, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	path := invitationPath(op)
	missingOwner := nilService(c.Invitations)
	if op == organization.InvitationList {
		missingOwner = nilService(c.InvitationLister)
	}
	if path == "" || missingOwner || !c.Sessions.Configured() || !c.SafeRate.Configured() || c.Now == nil {
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
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[invitationState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (invitationState, error) {
			var zero invitationState
			if r == nil || r.URL == nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if r.URL.Path != path || r.URL.RawPath != "" || r.URL.EscapedPath() != path {
				return zero, requestFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return zero, requestFailure{status: 405, code: "method_not_allowed", allow: http.MethodGet}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			bearer, _, err := decoder.Bearer(r, identityhttp.HeaderRequired)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(bearer.Token()); err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return zero, networkFailure(err)
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return zero, requestFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Body != nil && r.Body != http.NoBody {
				return zero, identityhttp.ErrInvalidInput
			}
			query, err := decoder.Query(r)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			in := &invitationInput{facts: facts, auth: organization.Authentication{TenantID: facts.TenantID(), Bearer: bearer}}
			for k := range query {
				if op == organization.InvitationGet && k != "organizationID" && k != "invitationID" || op == organization.InvitationListMine && k != "cursor" && k != "limit" || op == organization.InvitationList && k != "organizationID" && k != "cursor" && k != "limit" {
					return zero, identityhttp.ErrInvalidInput
				}
			}
			if op == organization.InvitationGet {
				in.org, in.id = organization.ID(query.Get("organizationID")), organization.ID(query.Get("invitationID"))
				if !boundedID(string(in.org)) || !boundedID(string(in.id)) {
					return zero, identityhttp.ErrInvalidInput
				}
			} else if op == organization.InvitationList {
				in.org = organization.ID(query.Get("organizationID"))
				in.cursor = organization.InvitationCursor(query.Get("cursor"))
				n, e := strconv.ParseUint(query.Get("limit"), 10, 32)
				if !boundedID(string(in.org)) || e != nil || n < 1 || n > 100 || strconv.FormatUint(n, 10) != query.Get("limit") {
					return zero, identityhttp.ErrInvalidInput
				}
				if _, present := query["cursor"]; present && !boundedID(string(in.cursor)) {
					return zero, identityhttp.ErrInvalidInput
				}
				in.limit = uint32(n)
			} else {
				in.limit = 100
				if values, present := query["limit"]; present {
					n, e := strconv.ParseUint(values[0], 10, 32)
					if e != nil || n < 1 || n > 200 || strconv.FormatUint(n, 10) != values[0] {
						return zero, identityhttp.ErrInvalidInput
					}
					in.limit = uint32(n)
				}
				in.cursor = organization.InvitationCursor(query.Get("cursor"))
				if _, present := query["cursor"]; present && !boundedInvitationCursor(string(in.cursor)) {
					return zero, identityhttp.ErrInvalidInput
				}
			}
			id, err := identity.NewCommandID()
			if err != nil {
				return zero, identityhttp.ErrUnavailable
			}
			in.correlation = string(id)
			return invitationState{input: func() *invitationInput { return in }}, nil
		},
		Authenticate: func(r *http.Request, state invitationState) (invitationState, error) {
			in := state.input()
			token, err := session.ParseToken(in.auth.Bearer.Token())
			if err != nil {
				return invitationState{}, identityhttp.ErrInvalidInput
			}
			credential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return invitationState{}, identityhttp.ErrInvalidInput
			}
			observed, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: in.auth.TenantID, Credential: credential})
			if err != nil {
				return invitationState{}, identityhttp.ErrUnavailable
			}
			if !observed.Authenticated || observed.ValidateAt(c.Now()) != nil {
				return invitationState{}, requestFailure{status: 403, code: "forbidden"}
			}
			binding, err := observed.Session.Bindings()
			if err != nil || binding.TenantID != in.auth.TenantID || binding.Authentication.Kind != session.AuthenticationVerified {
				return invitationState{}, requestFailure{status: 403, code: "forbidden"}
			}
			in.observed, in.actor = observed, binding.UserID
			return state, nil
		},
		Admit: func(r *http.Request, state invitationState) error {
			in := state.input()
			result, err := c.SafeRate.Admit(r.Context(), in.facts, string(op), in.actor)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return requestFailure{status: 429, code: "rate_limited", retry: result.RetryAfter}
			}
			if err != nil || !result.Allowed || in.observed.ValidateAt(c.Now()) != nil || r.Context().Err() != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state invitationState) {
			in := state.input()
			if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			var response any
			var err error
			if op == organization.InvitationGet {
				var out organization.InvitationDelivery
				out, err = c.Invitations.Get(r.Context(), organization.InvitationReadRequest{Authentication: in.auth, OrganizationID: in.org, ID: in.id, CorrelationID: in.correlation})
				if err == nil {
					var view InvitationView
					view, err = invitationView(in, out.Invitation, false)
					response = InvitationReadResponse{Invitation: view}
				}
			} else if op == organization.InvitationList {
				var out organization.InvitationPage
				out, err = c.InvitationLister.List(r.Context(), organization.InvitationReadRequest{Authentication: in.auth, OrganizationID: in.org, Cursor: organization.ID(in.cursor), Limit: in.limit, CorrelationID: in.correlation})
				if err == nil {
					response, err = ownerInvitationPage(in, out)
				}
			} else {
				var out organization.InvitationListMineResult
				out, err = c.Invitations.ListMine(r.Context(), organization.InvitationListMineRequest{Authentication: in.auth, Cursor: in.cursor, Limit: in.limit, CorrelationID: in.correlation})
				if err == nil {
					response, err = invitationPage(in, out)
				}
			}
			if err != nil {
				status, code := 503, "unavailable"
				if errors.Is(err, organization.ErrInvalidInput) {
					status, code = 400, "invalid_request"
				} else if errors.Is(err, organization.ErrForbidden) {
					status, code = 403, "forbidden"
				}
				reject(w, r, requestFailure{status: status, code: code})
				return
			}
			if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			writeJSON(w, 200, response)
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: pipeline}, nil
}
func boundedInvitationCursor(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}
func invitationView(in *invitationInput, i organization.Invitation, mine bool) (InvitationView, error) {
	// Match the native Invitation contract: zero IssuedVersion is legacy first
	// issuance; terminal transitions advance once, while natural expiry does
	// not. Do not turn an inconsistent owner projection into HTTP success.
	issued := i.IssuedVersion
	if issued == 0 {
		issued = 1
	}
	versionValid := issued < ^uint64(0) && ((i.Status == organization.InvitationPending || i.Status == organization.InvitationExpired) && i.Version == issued || (i.Status == organization.InvitationAccepted || i.Status == organization.InvitationCancelled || i.Status == organization.InvitationRejected || i.Status == organization.InvitationExpired) && i.Version == issued+1)
	if i.TenantID != in.auth.TenantID || !boundedID(string(i.ID)) || !boundedID(string(i.OrganizationID)) || !boundedID(string(i.RecipientUserID)) || !boundedID(string(i.RecipientIdentifierID)) || i.RecipientIdentifierVersion == 0 || !boundedID(string(i.CreatedBy)) || i.Role != organization.RoleMember || !versionValid || i.ExpiresAt.IsZero() || !i.ExpiresAt.Equal(i.ExpiresAt.UTC().Truncate(time.Second)) || i.ExpiresAt.Year() < 1 || i.ExpiresAt.Year() > 9999 || mine && i.RecipientUserID != in.actor || !mine && (i.OrganizationID != in.org || i.ID != in.id) {
		return InvitationView{}, organization.ErrUnavailable
	}
	status := ""
	switch i.Status {
	case organization.InvitationPending:
		status = "pending"
	case organization.InvitationAccepted:
		status = "accepted"
	case organization.InvitationExpired:
		status = "expired"
	case organization.InvitationCancelled:
		status = "cancelled"
	case organization.InvitationRejected:
		status = "rejected"
	default:
		return InvitationView{}, organization.ErrUnavailable
	}
	return InvitationView{ID: i.ID, OrganizationID: i.OrganizationID, Role: i.Role, Status: status, Version: i.Version, ExpiresAt: i.ExpiresAt}, nil
}
func invitationPage(in *invitationInput, page organization.InvitationListMineResult) (InvitationListMineResponse, error) {
	var zero InvitationListMineResponse
	if len(page.Invitations) > int(in.limit) || page.NextCursor != "" && (!boundedInvitationCursor(string(page.NextCursor)) || len(page.Invitations) != int(in.limit) || page.NextCursor == in.cursor) {
		return zero, organization.ErrUnavailable
	}
	views := make([]InvitationView, len(page.Invitations))
	var previous organization.ID
	for n, i := range page.Invitations {
		if n > 0 && i.ID <= previous {
			return zero, organization.ErrUnavailable
		}
		v, err := invitationView(in, i, true)
		if err != nil {
			return zero, err
		}
		views[n], previous = v, i.ID
	}
	return InvitationListMineResponse{Invitations: views, NextCursor: page.NextCursor}, nil
}

func ownerInvitationPage(in *invitationInput, page organization.InvitationPage) (InvitationListResponse, error) {
	var zero InvitationListResponse
	if _, err := readResponse(&requestInput{auth: in.auth, org: in.org, actor: in.actor}, organization.View{Organization: page.Organization, Actor: page.Actor}); err != nil || page.Actor.Role != organization.RoleOwner || len(page.Invitations) > int(in.limit) {
		return zero, organization.ErrUnavailable
	}
	views := make([]InvitationView, len(page.Invitations))
	previous := organization.ID(in.cursor)
	for n, item := range page.Invitations {
		if item.Invitation.ID <= previous {
			return zero, organization.ErrUnavailable
		}
		scoped := *in
		scoped.id = item.Invitation.ID
		view, err := invitationView(&scoped, item.Invitation, false)
		if err != nil {
			return zero, err
		}
		views[n], previous = view, item.Invitation.ID
	}
	if page.NextCursor != "" && (len(views) != int(in.limit) || page.NextCursor != previous) {
		return zero, organization.ErrUnavailable
	}
	return InvitationListResponse{Invitations: views, NextCursor: page.NextCursor}, nil
}
