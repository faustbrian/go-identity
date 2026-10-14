package identity

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
)

func TestUserListAuthorizesAndContinuesStableSnapshot(t *testing.T) {
	f := newQueryFixture(t)
	repo := &listStore{queryStore: f.repo}
	service, err := NewUserDirectoryService(repo, f.service.authorize, queryRedact, f.service.config, UserListConfig{
		CursorKey: [32]byte{1}, CursorTTL: time.Minute,
		ValidateCanonicalIdentifier: func(context.Context, IdentifierKind, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := UserListRequest{TenantID: "tenant-a", Limit: 1, Filters: UserListFilters{Statuses: []Status{StatusActive}}, Context: f.request.Context}
	req.Context.Request.Action = "identity.user.list"
	req.Context.Request.Resource = authorization.Resource{Type: "identity.user.collection", ID: "tenant-a"}
	page, err := service.UserList(context.Background(), req)
	if err != nil || len(page.Users) != 1 || page.Users[0].ID != "user-a" || page.NextCursor == "" {
		t.Fatal("first authorized page missing", err)
	}
	req.Cursor = page.NextCursor
	page, err = service.UserList(context.Background(), req)
	if err != nil || len(page.Users) != 1 || page.Users[0].ID != "user-b" || page.NextCursor != "" || repo.calls != 2 {
		t.Fatal("snapshot continuation failed", err)
	}
}

type listStore struct {
	*queryStore
	calls int
	fn    func(context.Context, ListUsersQuery) (UserPage, error)
}

func (r *listStore) List(ctx context.Context, q ListUsersQuery) (UserPage, error) {
	r.calls++
	if r.fn != nil {
		return r.fn(ctx, q)
	}
	if _, ok := ctx.Deadline(); !ok || q.TenantID != "tenant-a" || q.Limit != 1 {
		panic("unbounded or unscoped listing")
	}
	if q.Cursor == (Cursor{}) {
		next, err := NewCursor("AQEBAQEBAQEBAQEBAQEBAQ", 1)
		if err != nil {
			return UserPage{}, err
		}
		return UserPage{Users: []User{{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}}, Next: next}, nil
	}
	if q.Cursor.SnapshotID() != "AQEBAQEBAQEBAQEBAQEBAQ" || q.Cursor.Position() != 1 {
		panic("snapshot changed")
	}
	return UserPage{Users: []User{{ID: "user-b", TenantID: "tenant-a", Status: StatusActive, Version: 1}}}, nil
}

func newListFixture(t *testing.T) (*UserQueryService, *listStore, UserListRequest) {
	t.Helper()
	f := newQueryFixture(t)
	repo := &listStore{queryStore: f.repo}
	s, err := NewUserDirectoryService(repo, f.service.authorize, queryRedact, f.service.config, UserListConfig{
		CursorKey: [32]byte{1}, CursorTTL: time.Minute,
		ValidateCanonicalIdentifier: func(context.Context, IdentifierKind, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := UserListRequest{TenantID: "tenant-a", Limit: 1, Filters: UserListFilters{Statuses: []Status{StatusActive}}, Context: f.request.Context}
	req.Context.Request.Action = "identity.user.list"
	req.Context.Request.Resource = authorization.Resource{Type: "identity.user.collection", ID: "tenant-a"}
	return s, repo, req
}

func requireNoListOutput(t *testing.T, result UserListResult, err error) {
	t.Helper()
	if err == nil || result.Users != nil || result.NextCursor != "" {
		t.Fatal("failed listing returned partial output")
	}
}

func TestUserListSnapshotExpiryBoundsInFlightWork(t *testing.T) {
	s, repo, req := newListFixture(t)
	s.listConfig.CursorTTL = time.Millisecond
	repo.fn = func(ctx context.Context, _ ListUsersQuery) (UserPage, error) {
		timer := time.NewTimer(20 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return UserPage{}, ctx.Err()
		case <-timer.C:
			return UserPage{Users: []User{{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}}}, nil
		}
	}
	got, err := s.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired snapshot remained usable during work")
	}
}

func TestUserListSnapshotIsStableDespiteLiveDirectoryChanges(t *testing.T) {
	s, repo, req := newListFixture(t)
	live := []User{{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}, {ID: "user-b", TenantID: "tenant-a", Status: StatusActive, Version: 1}}
	var snapshot []User
	repo.fn = func(_ context.Context, q ListUsersQuery) (UserPage, error) {
		if q.Cursor == (Cursor{}) {
			snapshot = slices.Clone(live)
		}
		start := q.Cursor.Position()
		if start > uint64(len(snapshot)) {
			return UserPage{}, errors.New("snapshot position")
		}
		end := min(start+uint64(q.Limit), uint64(len(snapshot)))
		p := UserPage{Users: slices.Clone(snapshot[start:end])}
		if end < uint64(len(snapshot)) {
			p.Next, _ = NewCursor("AQEBAQEBAQEBAQEBAQEBAQ", end)
		}
		return p, nil
	}
	first, err := s.UserList(context.Background(), req)
	if err != nil || len(first.Users) != 1 {
		t.Fatal("initial snapshot failed")
	}
	// Insert before the old page boundary and delete a not-yet-read live row.
	live = []User{{ID: "user-0", TenantID: "tenant-a", Status: StatusActive, Version: 2}, {ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 2}}
	req.Cursor = first.NextCursor
	second, err := s.UserList(context.Background(), req)
	if err != nil || len(second.Users) != 1 || second.Users[0].ID != "user-b" || second.Users[0].Version != 1 || second.NextCursor != "" {
		t.Fatal("continuation used changed live rows", err)
	}
}

func TestUserListCannotRestartExpiryAfterSlowClock(t *testing.T) {
	s, repo, req := newListFixture(t)
	s.listConfig.CursorTTL = time.Millisecond
	s.config.Clock = queryClockFunc(func() time.Time { time.Sleep(5 * time.Millisecond); return queryClock{}.Now() })
	got, err := s.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
	if !errors.Is(err, context.DeadlineExceeded) || repo.calls != 0 {
		t.Fatal("elapsed work renewed cursor interval")
	}
}

func TestUserListRejectsPositiveWrappedUnixTimestamp(t *testing.T) {
	s, repo, req := newListFixture(t)
	s.config.Clock = queryClockFunc(func() time.Time { return time.Date(2600, 1, 1, 0, 0, 0, 0, time.UTC) })
	got, err := s.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
	if repo.calls != 0 {
		t.Fatal("unrepresentable clock reached storage")
	}
}

func TestUserListAdmissionBeforeDependencies(t *testing.T) {
	for name, change := range map[string]func(*UserListRequest){
		"zero limit":         func(r *UserListRequest) { r.Limit = 0 },
		"large limit":        func(r *UserListRequest) { r.Limit = 101 },
		"large cursor":       func(r *UserListRequest) { r.Cursor = strings.Repeat("x", 1025) },
		"wrong target":       func(r *UserListRequest) { r.Context.Request.Resource.ID = "other" },
		"wrong action":       func(r *UserListRequest) { r.Context.Request.Action = "identity.user.get" },
		"empty statuses":     func(r *UserListRequest) { r.Filters.Statuses = nil },
		"unknown status":     func(r *UserListRequest) { r.Filters.Statuses = []Status{"unknown"} },
		"duplicate status":   func(r *UserListRequest) { r.Filters.Statuses = []Status{StatusActive, StatusActive} },
		"large statuses":     func(r *UserListRequest) { r.Filters.Statuses = make([]Status, 17) },
		"missing namespace":  func(r *UserListRequest) { r.Filters.CanonicalIdentifier = "person@example.test" },
		"unknown namespace":  func(r *UserListRequest) { r.Filters.IdentifierKind = "other"; r.Filters.CanonicalIdentifier = "value" },
		"missing identifier": func(r *UserListRequest) { r.Filters.IdentifierKind = IdentifierEmail },
		"large identifier": func(r *UserListRequest) {
			r.Filters.IdentifierKind = IdentifierUsername
			r.Filters.CanonicalIdentifier = strings.Repeat("a", 513)
		},
		"invalid UTF8": func(r *UserListRequest) {
			r.Filters.IdentifierKind = IdentifierUsername
			r.Filters.CanonicalIdentifier = "\xff"
		},
		"bad cursor": func(r *UserListRequest) { r.Cursor = "not-a-cursor" },
		"full attributes": func(r *UserListRequest) {
			r.Context.Request.Resource.Attributes = authorization.Attributes{}
			for i := 0; i < 128; i++ {
				r.Context.Request.Resource.Attributes[authorization.AttributeName(strings.Repeat("a", i+1))] = authorization.BoolValue(true)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, repo, req := newListFixture(t)
			change(&req)
			got, err := s.UserList(context.Background(), req)
			requireNoListOutput(t, got, err)
			if repo.calls != 0 {
				t.Fatal("invalid input reached storage")
			}
		})
	}
}

func TestUserListCollectionDenialPreventsRead(t *testing.T) {
	for _, decision := range []authorization.Decision{{Outcome: authorization.Deny, Revision: 1}, {Outcome: authorization.NotApplicable, Revision: 1}, {Outcome: authorization.Allow, Revision: 2}} {
		s, repo, req := newListFixture(t)
		s.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return decision, nil
		})
		got, err := s.UserList(context.Background(), req)
		requireNoListOutput(t, got, err)
		var forbidden ForbiddenError
		if !errors.As(err, &forbidden) || repo.calls != 0 {
			t.Fatal("collection denial reached storage")
		}
	}
}

func TestUserListRejectsMalformedRepositoryPages(t *testing.T) {
	base := User{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}
	next, _ := NewCursor("AQEBAQEBAQEBAQEBAQEBAQ", 1)
	for name, change := range map[string]func(*UserPage){
		"cross tenant":      func(p *UserPage) { p.Users[0].TenantID = "other" },
		"zero version":      func(p *UserPage) { p.Users[0].Version = 0 },
		"invalid id":        func(p *UserPage) { p.Users[0].ID = "bad id" },
		"wrong status":      func(p *UserPage) { p.Users[0].Status = StatusBanned },
		"large page":        func(p *UserPage) { p.Users = append(p.Users, base) },
		"empty nonterminal": func(p *UserPage) { p.Users = nil },
		"bad cursor":        func(p *UserPage) { p.Next.snapshot = "invalid" },
		"bad position":      func(p *UserPage) { p.Next.position = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			s, repo, req := newListFixture(t)
			repo.fn = func(context.Context, ListUsersQuery) (UserPage, error) {
				p := UserPage{Users: []User{base}, Next: next}
				change(&p)
				return p, nil
			}
			got, err := s.UserList(context.Background(), req)
			requireNoListOutput(t, got, err)
		})
	}
	for _, ids := range [][]UserID{{"user-a", "user-a"}, {"user-b", "user-a"}} {
		s, repo, req := newListFixture(t)
		req.Limit = 2
		repo.fn = func(context.Context, ListUsersQuery) (UserPage, error) {
			a, b := base, base
			a.ID, b.ID = ids[0], ids[1]
			return UserPage{Users: []User{a, b}}, nil
		}
		got, err := s.UserList(context.Background(), req)
		requireNoListOutput(t, got, err)
	}
}

func TestUserListCursorBindingAndExpiryCannotBeRenewed(t *testing.T) {
	s, repo, req := newListFixture(t)
	first, err := s.UserList(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*UserListRequest){
		"tenant": func(r *UserListRequest) {
			r.TenantID = "tenant-b"
			r.Context.Request.Tenant = "tenant-b"
			r.Context.Request.Resource.ID = "tenant-b"
		},
		"viewer": func(r *UserListRequest) { r.Context.Request.Subject.ID = "other" },
		"kind":   func(r *UserListRequest) { r.Context.Request.Subject.Kind = authorization.SubjectAPIKey },
		"limit":  func(r *UserListRequest) { r.Limit = 2 },
		"filter": func(r *UserListRequest) { r.Filters.Statuses = []Status{StatusBanned} },
	} {
		t.Run(name, func(t *testing.T) {
			r := req
			r.Cursor = first.NextCursor
			change(&r)
			got, err := s.UserList(context.Background(), r)
			requireNoListOutput(t, got, err)
			if repo.calls != 1 {
				t.Fatal("mismatched cursor reached storage")
			}
		})
	}
	binding := listBinding(req, s.config)
	original, err := s.listConfig.openCursor(first.NextCursor, binding, queryClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	s.config.Clock = queryClockFunc(func() time.Time { return queryClock{}.Now().Add(30 * time.Second) })
	repo.fn = func(_ context.Context, q ListUsersQuery) (UserPage, error) {
		if q.ExpiresAt.UnixNano() != original.Expires {
			t.Fatal("snapshot expiry renewed")
		}
		next, _ := NewCursor(q.Cursor.snapshot, 2)
		return UserPage{Users: []User{{ID: "user-b", TenantID: "tenant-a", Status: StatusActive, Version: 1}}, Next: next}, nil
	}
	req.Cursor = first.NextCursor
	second, err := s.UserList(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := s.listConfig.openCursor(second.NextCursor, binding, queryClock{}.Now().Add(30*time.Second))
	if err != nil || continued.Expires != original.Expires || continued.Issued != original.Issued {
		t.Fatal("continuation renewed freshness")
	}
	s.config.Clock = queryClockFunc(func() time.Time { return queryClock{}.Now().Add(time.Minute) })
	req.Cursor = second.NextCursor
	got, err := s.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
	if repo.calls != 2 {
		t.Fatal("expired cursor reached storage")
	}
}

func TestUserListRowDenialAndRedactionAdvanceWithoutDisclosure(t *testing.T) {
	for _, hide := range []string{"authorization", "redaction"} {
		s, repo, req := newListFixture(t)
		if hide == "authorization" {
			s.authorize = queryDecisionFunc(func(_ context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
				outcome := authorization.Allow
				if in.Request.Resource.Type == "identity.user" && in.Request.Resource.ID == "user-a" {
					outcome = authorization.Deny
				}
				return authorization.Decision{Outcome: outcome, Revision: 1}, nil
			})
		} else {
			s.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
				d, err := queryRedact(ctx, in)
				if in.Resource.ID == "user-a" {
					d.VisibleFields = nil
					d.RedactedFields = in.Fields
				}
				return d, err
			}
		}
		got, err := s.UserList(context.Background(), req)
		if err != nil || len(got.Users) != 0 || got.NextCursor == "" {
			t.Fatal("hidden row disclosed or lost continuation")
		}
		req.Cursor = got.NextCursor
		got, err = s.UserList(context.Background(), req)
		if err != nil || len(got.Users) != 1 || got.Users[0].ID != "user-b" || repo.calls != 2 {
			t.Fatal("hidden row prevented continuation")
		}
	}
}

func TestUserListRejectsCrossPageDuplicationAndSnapshotSwitch(t *testing.T) {
	for _, bad := range []string{"duplicate", "snapshot"} {
		s, repo, req := newListFixture(t)
		first, err := s.UserList(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		req.Cursor = first.NextCursor
		repo.fn = func(_ context.Context, q ListUsersQuery) (UserPage, error) {
			id := UserID("user-b")
			next, _ := NewCursor(q.Cursor.snapshot, 2)
			if bad == "duplicate" {
				id = "user-a"
			} else {
				next, _ = NewCursor("AgICAgICAgICAgICAgICAg", 2)
			}
			return UserPage{Users: []User{{ID: id, TenantID: "tenant-a", Status: StatusActive, Version: 1}}, Next: next}, nil
		}
		got, err := s.UserList(context.Background(), req)
		requireNoListOutput(t, got, err)
	}
}

func TestUserListFailuresReturnNoPartialResult(t *testing.T) {
	for name, install := range map[string]func(*UserQueryService, *listStore){
		"authorization error": func(s *UserQueryService, _ *listStore) {
			s.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{}, errors.New("private detail")
			})
		},
		"authorization panic": func(s *UserQueryService, _ *listStore) {
			s.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				panic("private detail")
			})
		},
		"repository error": func(_ *UserQueryService, r *listStore) {
			r.fn = func(context.Context, ListUsersQuery) (UserPage, error) {
				return UserPage{}, errors.New("private detail")
			}
		},
		"repository panic": func(_ *UserQueryService, r *listStore) {
			r.fn = func(context.Context, ListUsersQuery) (UserPage, error) { panic("private detail") }
		},
		"canonical id error": func(s *UserQueryService, _ *listStore) {
			s.config.ValidateCanonicalUserID = func(context.Context, UserID) error { return errors.New("private detail") }
		},
		"clock zero": func(s *UserQueryService, _ *listStore) {
			s.config.Clock = queryClockFunc(func() time.Time { return time.Time{} })
		},
		"clock overflow": func(s *UserQueryService, _ *listStore) {
			s.config.Clock = queryClockFunc(func() time.Time { return time.Date(2263, 1, 1, 0, 0, 0, 0, time.UTC) })
		},
		"row error": func(s *UserQueryService, _ *listStore) {
			s.authorize = queryDecisionFunc(func(_ context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
				if in.Request.Resource.Type == "identity.user" {
					return authorization.Decision{}, errors.New("private detail")
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
		},
		"row stale": func(s *UserQueryService, _ *listStore) {
			s.authorize = queryDecisionFunc(func(_ context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
				rev := authorization.Revision(1)
				if in.Request.Resource.Type == "identity.user" {
					rev = 2
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: rev}, nil
			})
		},
		"redaction error": func(s *UserQueryService, _ *listStore) {
			s.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
				return RedactionPolicyDecision{}, errors.New("private detail")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, repo, req := newListFixture(t)
			install(s, repo)
			got, err := s.UserList(context.Background(), req)
			requireNoListOutput(t, got, err)
			if strings.Contains(err.Error(), "private") {
				t.Fatal("failure leaked")
			}
		})
	}
	// The second row fails after the first was assembled internally.
	s, repo, req := newListFixture(t)
	req.Limit = 2
	repo.fn = func(context.Context, ListUsersQuery) (UserPage, error) {
		return UserPage{Users: []User{{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}, {ID: "user-b", TenantID: "tenant-a", Status: StatusActive, Version: 1}}}, nil
	}
	s.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		if in.Resource.ID == "user-b" {
			panic("private")
		}
		return queryRedact(ctx, in)
	}
	got, err := s.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
}

func TestUserListCancellationAtEveryDependency(t *testing.T) {
	for _, stage := range []string{"initial", "identifier failure", "identifier success", "collection", "repository", "user id failure", "user id success", "row", "redaction"} {
		t.Run(stage, func(t *testing.T) {
			s, repo, req := newListFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "initial" {
				cancel()
			}
			if strings.HasPrefix(stage, "identifier") {
				req.Filters.IdentifierKind = IdentifierEmail
				req.Filters.CanonicalIdentifier = "person@example.test"
				s.listConfig.ValidateCanonicalIdentifier = func(context.Context, IdentifierKind, string) error {
					cancel()
					if stage == "identifier failure" {
						return errors.New("private")
					}
					return nil
				}
			}
			if stage == "collection" || stage == "row" {
				s.authorize = queryDecisionFunc(func(_ context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
					if (stage == "collection" && in.Request.Resource.Type == "identity.user.collection") || (stage == "row" && in.Request.Resource.Type == "identity.user") {
						cancel()
					}
					return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
				})
			}
			if stage == "repository" {
				repo.fn = func(context.Context, ListUsersQuery) (UserPage, error) { cancel(); return UserPage{}, nil }
			}
			if strings.HasPrefix(stage, "user id") {
				s.config.ValidateCanonicalUserID = func(context.Context, UserID) error {
					cancel()
					if stage == "user id failure" {
						return errors.New("private")
					}
					return nil
				}
			}
			if stage == "redaction" {
				s.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
					cancel()
					return queryRedact(ctx, in)
				}
			}
			got, err := s.UserList(ctx, req)
			requireNoListOutput(t, got, err)
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation classification lost")
			}
		})
	}
}

func TestUserListConfigurationAndCursorValues(t *testing.T) {
	s, repo, req := newListFixture(t)
	for _, change := range []func(*UserListConfig){func(c *UserListConfig) { c.CursorKey = [32]byte{} }, func(c *UserListConfig) { c.CursorTTL = 0 }, func(c *UserListConfig) { c.CursorTTL = 16 * time.Minute }, func(c *UserListConfig) { c.ValidateCanonicalIdentifier = nil }} {
		c := s.listConfig
		change(&c)
		if got, err := NewUserDirectoryService(repo, s.authorize, s.redact, s.config, c); got != nil || err == nil {
			t.Fatal("invalid list configuration admitted")
		}
	}
	var nilRepo *listStore
	if got, err := NewUserDirectoryService(nilRepo, s.authorize, s.redact, s.config, s.listConfig); got != nil || err == nil {
		t.Fatal("nil directory admitted")
	}
	for _, c := range []Cursor{{snapshot: "invalid", position: 1}, {snapshot: "AQEBAQEBAQEBAQEBAQEBAQ", position: 0}, {snapshot: "AQEBAQEBAQEBAQEBAQEBAQ", position: math.MaxUint64}} {
		if got, err := NewCursor(c.snapshot, c.position); got != (Cursor{}) || err == nil {
			t.Fatal("invalid cursor value admitted")
		}
	}
	got, err := s.UserList(nil, req)
	requireNoListOutput(t, got, err)
	got, err = (*UserQueryService)(nil).UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
	getOnly := newQueryFixture(t).service
	got, err = getOnly.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
	// The pre-existing get-only constructor remains compatible.
	if _, err := s.UserGet(context.Background(), newQueryFixture(t).request); err != nil {
		t.Fatal("directory composition broke get")
	}
}

func TestUserListCanonicalFilterAndPolicyBindings(t *testing.T) {
	s, repo, req := newListFixture(t)
	req.Filters.IdentifierKind = IdentifierEmail
	req.Filters.CanonicalIdentifier = "person@example.test"
	req.Context.Request.Resource.Attributes = authorization.Attributes{"identity.query.identifier": authorization.StringValue("forged")}
	clockCalls := 0
	s.config.Clock = queryClockFunc(func() time.Time { clockCalls++; return queryClock{}.Now() })
	s.listConfig.ValidateCanonicalIdentifier = func(_ context.Context, kind IdentifierKind, value string) error {
		if kind != IdentifierEmail || value != req.Filters.CanonicalIdentifier {
			t.Fatal("canonical filter rewritten")
		}
		return nil
	}
	s.authorize = queryDecisionFunc(func(_ context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
		value, _ := in.Request.Resource.Attributes["identity.query.identifier"].String()
		if value != req.Filters.CanonicalIdentifier {
			t.Fatal("dishonest filter reached policy")
		}
		if in.Request.Resource.Type == "identity.user" {
			version, _ := in.Request.Resource.Attributes["identity.user.version"].String()
			if version != "18446744073709551615" {
				t.Fatal("version narrowed")
			}
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	repo.fn = func(_ context.Context, q ListUsersQuery) (UserPage, error) {
		if q.Filters.CanonicalIdentifier != req.Filters.CanonicalIdentifier {
			t.Fatal("filter lost")
		}
		q.Filters.Statuses[0] = StatusBanned
		return UserPage{Users: []User{{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: math.MaxUint64}}}, nil
	}
	got, err := s.UserList(context.Background(), req)
	if err != nil || len(got.Users) != 1 || clockCalls != 1 || req.Filters.Statuses[0] != StatusActive {
		t.Fatal("binding or alias isolation failed", err)
	}
	s.listConfig.ValidateCanonicalIdentifier = func(context.Context, IdentifierKind, string) error { return errors.New("private") }
	got, err = s.UserList(context.Background(), req)
	requireNoListOutput(t, got, err)
}
