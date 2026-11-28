package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestAdminSessionListPagesOnlyTheAuthorizedTarget(t *testing.T) {
	primary, input, _, observed, _, _ := validationFixture(t)
	actor, _ := observed.Session.Bindings()
	const target = "target-user"
	first := listRecord(t, observed.Session, "target-a", func(s *session.SessionSpec) { s.UserID = target })
	second := listRecord(t, observed.Session, "target-b", func(s *session.SessionSpec) { s.UserID = target })
	var scans, charges int
	allowed := true
	policy := listPolicy(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		r := dc.Request
		if r.Action != "identity.admin.session-list" || r.Tenant != authorization.TenantID(actor.TenantID) || r.Subject.ID != authorization.SubjectID(actor.UserID) || r.Subject.Kind != authorization.SubjectUser || r.Resource.Type != "identity.user" || r.Resource.ID != target {
			t.Fatal("authorization didn't bind the actual actor to the exact target")
		}
		if !allowed {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	pages := sessionPageReader(func(_ context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
		scans++
		if q.TenantID != actor.TenantID || q.UserID != target || q.Audience != actor.Audience || q.Limit != 1 || scans != charges {
			t.Fatal("page used an unadmitted, different or unbounded scope")
		}
		if q.AfterSessionID == "" {
			return session.SessionPage{Entries: []session.SessionListEntry{{Session: first, Label: "first device", Revoked: true}}, HasMore: true}, nil
		}
		if q.AfterSessionID != "target-a" {
			t.Fatal("continuation lost its exclusive position")
		}
		return session.SessionPage{Entries: []session.SessionListEntry{{Session: second}}}, nil
	})
	service, err := session.NewAdminListService(primary, pages, session.ListConfig{Authorization: policy, PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	req := session.AdminSessionListRequest{TenantID: input.TenantID, Credential: input.Credential, TargetSubjectID: target, Limit: 1}
	admit := func(ctx context.Context, user identity.UserID) error {
		charges++
		if _, ok := ctx.Deadline(); !ok || user != actor.UserID {
			t.Fatal("quota received a target instead of the current administrator")
		}
		return nil
	}
	page, err := service.AdminSessionListWithAdmission(context.Background(), req, admit)
	if err != nil || len(page.Sessions) != 1 || page.Sessions[0].SessionID != "target-a" || page.Sessions[0].Label != "first device" || !page.Sessions[0].Inactive || page.Sessions[0].Current || page.NextCursor == "" {
		t.Fatal("missing safe target device or continuation", err)
	}
	req.Cursor = page.NextCursor
	foreign := req
	foreign.TargetSubjectID = "another-user"
	if out, err := service.AdminSessionListWithAdmission(context.Background(), foreign, admit); !errors.Is(err, session.ErrInvalidInput) || len(out.Sessions) != 0 || scans != 1 || charges != 1 {
		t.Fatal("cursor crossed target or consumed a quota attempt", err)
	}
	page, err = service.AdminSessionListWithAdmission(context.Background(), req, admit)
	if err != nil || len(page.Sessions) != 1 || page.Sessions[0].SessionID != "target-b" || page.Sessions[0].Current || page.NextCursor != "" || charges != 2 {
		t.Fatal("continuation returned another subject or unbounded page", err)
	}
	allowed = false
	var denied identity.ForbiddenError
	if out, err := service.AdminSessionListWithAdmission(context.Background(), req, admit); !errors.As(err, &denied) || len(out.Sessions) != 0 || scans != 2 || charges != 2 {
		t.Fatal("old cursor bypassed current policy", err)
	}
}

func TestAdminSessionListRejectsUnboundActorAndExpiredOriginalEvidence(t *testing.T) {
	primary, input, clock, observed, _, _ := validationFixture(t)
	actor, _ := observed.Session.Bindings()
	scans := 0
	pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
		scans++
		clock.now = observed.ValidUntil
		return session.SessionPage{}, nil
	})
	service, err := session.NewAdminListService(primary, pages, session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	req := session.AdminSessionListRequest{TenantID: input.TenantID, Credential: input.Credential, ActorID: "not-the-actor", TargetSubjectID: "target-user", Limit: 2}
	var denied identity.ForbiddenError
	if out, err := service.AdminSessionList(context.Background(), req); !errors.As(err, &denied) || out.Sessions != nil || scans != 0 {
		t.Fatal("caller-provided actor was accepted as authority", err)
	}
	req.ActorID = identity.SubjectID(actor.UserID)
	quotaDenied := errors.New("quota unavailable")
	if out, err := service.AdminSessionListWithAdmission(context.Background(), req, func(context.Context, identity.UserID) error { return quotaDenied }); !errors.Is(err, quotaDenied) || out.Sessions != nil || scans != 0 {
		t.Fatal("denied quota reached target data", err)
	}
	if out, err := service.AdminSessionList(context.Background(), req); !errors.Is(err, session.ErrUnauthenticated) || out.Sessions != nil || out.NextCursor != "" || scans != 1 {
		t.Fatal("expired original authority allowed disclosure", err)
	}
}
