package session

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// AdminSessionListRequest selects one target in the administrator's tenant.
// ActorID must match the authenticated session, never supply authority by
// itself. The transport variant may omit it and use only the credential.
// Limit is 1..100. Cursor is a locator bound to the operation, tenant, actor,
// audience and target; it never grants access and cannot bypass fresh policy.
type AdminSessionListRequest struct {
	TenantID        identity.TenantID
	ActorID         identity.SubjectID
	TargetSubjectID identity.SubjectID
	Credential      Credential
	Cursor          string
	Limit           uint16
}

// AdminSessionListResult is one bounded safe page in the original session
// audience. Inactive records are included so administrators can distinguish
// retained tombstones from active sessions. A zero result discloses nothing.
type AdminSessionListResult struct {
	Sessions   []Device
	NextCursor string
}

// AdminListService borrows the selected primary session, page reader and policy.
// It owns no store or mutation permissions and never alters self-list access.
type AdminListService struct{ list *ListService }

// NewAdminListService freezes the explicit admin read dependencies. The primary
// reader determines the accepted ordinary session profile and audience.
func NewAdminListService(sessions *SessionService, pages SessionPageReader, config ListConfig) (*AdminListService, error) {
	list, err := NewListService(sessions, pages, config)
	if err != nil {
		return nil, err
	}
	return &AdminListService{list: list}, nil
}

// AdminSessionList authenticates the claimed actor with the original credential
// and applies current target authorization before reading a bounded page.
func (s *AdminListService) AdminSessionList(ctx context.Context, req AdminSessionListRequest) (AdminSessionListResult, error) {
	if req.ActorID == "" {
		return AdminSessionListResult{}, ErrInvalidInput
	}
	return s.adminSessionList(ctx, req, nil)
}

// AdminSessionListWithAdmission calls the trusted transport's admission hook
// once after actor authentication and target authorization, before the page
// read. An omitted ActorID is derived solely from the current credential. The
// hook runs synchronously under original validity; its error denies disclosure.
func (s *AdminListService) AdminSessionListWithAdmission(ctx context.Context, req AdminSessionListRequest, admit func(context.Context, identity.UserID) error) (AdminSessionListResult, error) {
	if admit == nil {
		return AdminSessionListResult{}, ErrInvalidInput
	}
	return s.adminSessionList(ctx, req, admit)
}

func (s *AdminListService) adminSessionList(ctx context.Context, req AdminSessionListRequest, admit func(context.Context, identity.UserID) error) (out AdminSessionListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AdminSessionListResult{}, ErrUnavailable
		}
	}()
	if s == nil || s.list == nil || ctx == nil || !authorityKey(string(req.TargetSubjectID), 128) ||
		req.ActorID != "" && !authorityKey(string(req.ActorID), 128) || req.Limit < 1 || req.Limit > 100 {
		return out, ErrInvalidInput
	}
	marker, scope, err := parseListCursor(req.Cursor)
	if err != nil {
		return out, err
	}
	l := s.list
	bounded, stop := context.WithTimeout(ctx, l.config.MaximumDuration)
	defer stop()
	caller, err := l.sessions.Get(bounded, GetRequest{TenantID: req.TenantID, Credential: req.Credential})
	if err != nil {
		return out, signOutError(err)
	}
	now := l.sessions.config.Clock.Now()
	if caller.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	actor, err := caller.Session.Bindings()
	if err != nil || actor.TenantID != req.TenantID || (req.ActorID != "" && identity.SubjectID(actor.UserID) != req.ActorID) {
		return out, identity.ForbiddenError{}
	}
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	valid, expire := context.WithTimeout(bounded, caller.ValidUntil().Sub(now))
	defer expire()
	expected := listScopeDigest("identity.admin.session-list.cursor.v1\x00", true, string(actor.TenantID), string(actor.UserID), actor.Audience, string(req.TargetSubjectID))
	if req.Cursor != "" && scope != expected {
		return out, ErrInvalidInput
	}
	decision, err := l.config.Authorization.Decide(valid, authorization.DecisionContext{
		PolicyRevision: l.config.PolicyRevision,
		Request: authorization.Request{
			Tenant: authorization.TenantID(actor.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(actor.UserID), Kind: authorization.SubjectUser},
			Action: "identity.admin.session-list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(req.TargetSubjectID)},
			Environment: authorization.Environment{Time: now},
		},
	})
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if err != nil {
		return out, ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != l.config.PolicyRevision {
		return out, identity.ForbiddenError{}
	}
	if err := currentAdminListObservation(valid, l.sessions, caller); err != nil {
		return out, err
	}
	if admit != nil {
		if err := admit(valid, actor.UserID); err != nil {
			return out, err
		}
		if err := currentAdminListObservation(valid, l.sessions, caller); err != nil {
			return out, err
		}
	}
	query := SessionPageQuery{TenantID: actor.TenantID, UserID: identity.UserID(req.TargetSubjectID), Audience: actor.Audience, AfterSessionID: marker, Limit: req.Limit}
	page, err := l.pages.ReadSessionPage(valid, query)
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if err != nil {
		return out, signOutError(err)
	}
	devices, last, err := projectSessionPage(page, query, caller.Session, actor, l.sessions.config.Clock.Now(), true)
	if err != nil {
		return out, err
	}
	if err := currentAdminListObservation(valid, l.sessions, caller); err != nil {
		return out, err
	}
	out.Sessions = devices
	if page.HasMore {
		out.NextCursor = encodeListCursor(expected, last)
	}
	return out, nil
}

func currentAdminListObservation(ctx context.Context, s *SessionService, caller GetResult) error {
	if caller.ValidateAt(s.config.Clock.Now()) != nil {
		return ErrUnauthenticated
	}
	if ctx.Err() != nil {
		return sessionReadFailure(ctx)
	}
	return nil
}

// Format redacts the credential and target scope.
func (AdminSessionListRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.AdminSessionListRequest(redacted)"))
}

// Format redacts identifying session metadata.
func (AdminSessionListResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.AdminSessionListResult(redacted)"))
}

// MarshalJSON denies implicit credential and scope export.
func (AdminSessionListRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit credential and scope export.
func (AdminSessionListRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON leaves authorized display projection to the explicit caller.
func (AdminSessionListResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit metadata export.
func (AdminSessionListResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
