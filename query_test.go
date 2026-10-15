package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

func TestUserQueryAuthorizesExactTenantAndTargetBeforeRead(t *testing.T) {
	fixture := newQueryFixture(t)
	got, err := fixture.service.UserGet(context.Background(), fixture.request)
	if err != nil || got.User != fixture.repo.user || fixture.repo.reads != 1 {
		t.Fatalf("authorized read = %+v, %v", got, err)
	}
	fixture.request.Context.Request.Tenant = "other"
	got, err = fixture.service.UserGet(context.Background(), fixture.request)
	var invalid InvalidInputError
	if !errors.As(err, &invalid) || got != (UserGetResult{}) || fixture.repo.reads != 1 {
		t.Fatal("mismatched authorization context reached storage")
	}
}

func TestUserQueryRejectsMissingRedactionReason(t *testing.T) {
	f := newQueryFixture(t)
	f.service.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "identity-read", PolicyVersion: 1}, nil
	}
	got, err := f.service.UserGet(context.Background(), f.request)
	var forbidden ForbiddenError
	if got != (UserGetResult{}) || !errors.As(err, &forbidden) {
		t.Fatal("redaction without a registered reason disclosed user data")
	}
}

type queryFixture struct {
	service *UserQueryService
	request UserGetRequest
	repo    *queryStore
}

func newQueryFixture(t *testing.T) queryFixture {
	t.Helper()
	repo := &queryStore{user: User{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", TenantID: "tenant-a", Status: StatusActive, Version: 2}}
	authorize, err := authorization.NewDecisionService(queryAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewUserQueryService(repo, authorize, queryRedact, UserQueryConfig{
		Clock: queryClock{}, MaximumDuration: time.Second,
		PolicyID: "identity-read", PolicyVersion: 1,
		RedactionReasons:        []PolicyReason{"projection-visible"},
		ValidateCanonicalUserID: func(context.Context, UserID) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	r := UserGetRequest{TenantID: repo.user.TenantID, UserID: repo.user.ID, Context: authorization.DecisionContext{
		PolicyRevision: 1,
		Request: authorization.Request{
			Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "actor-a"},
			Action:  "identity.user.get", Tenant: "tenant-a",
			Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(repo.user.ID)},
		},
	}}
	return queryFixture{s, r, repo}
}

type queryStore struct {
	user  User
	reads int
	err   error
}

func (r *queryStore) Get(ctx context.Context, q GetUserQuery) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded read")
	}
	if q.UserID != r.user.ID || q.TenantID != r.user.TenantID {
		panic("changed scope")
	}
	r.reads++
	return r.user, r.err
}

type queryAuthorizer struct{}

func (queryAuthorizer) Decide(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded authorization")
	}
	if r.Environment.Time.IsZero() {
		panic("missing clock sample")
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

type queryClock struct{}

func (queryClock) Now() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }

func queryRedact(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded redaction")
	}
	return RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "identity-read", PolicyVersion: 1, Reason: "projection-visible"}, nil
}

func TestUserQueryReasonRegistrationIsBoundedAndCopied(t *testing.T) {
	f := newQueryFixture(t)
	for _, reasons := range [][]PolicyReason{nil, {}, {""}, {"a", "a"}, {PolicyReason(strings.Repeat("a", 65))}, {"bad\x00"}, make([]PolicyReason, 33)} {
		config := f.service.config
		config.RedactionReasons = reasons
		if service, err := NewUserQueryService(f.repo, f.service.authorize, queryRedact, config); service != nil || err == nil {
			t.Fatal("invalid reason registration admitted")
		}
	}
	config := f.service.config
	config.RedactionReasons = []PolicyReason{"projection-visible"}
	service, err := NewUserQueryService(f.repo, f.service.authorize, queryRedact, config)
	if err != nil {
		t.Fatal(err)
	}
	config.RedactionReasons[0] = "changed"
	if _, err := service.UserGet(context.Background(), f.request); err != nil {
		t.Fatal("caller mutation changed registered policy")
	}
	service.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		d, err := queryRedact(ctx, in)
		d.Reason = "changed"
		return d, err
	}
	if got, err := service.UserGet(context.Background(), f.request); got != (UserGetResult{}) || err == nil {
		t.Fatal("unregistered reason disclosed user")
	}
}

type queryDecisionFunc func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f queryDecisionFunc) Decide(ctx context.Context, r authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, r)
}

type queryClockFunc func() time.Time

func (f queryClockFunc) Now() time.Time { return f() }

type queryReadFunc func(context.Context, GetUserQuery) (User, error)

func (f queryReadFunc) Get(ctx context.Context, q GetUserQuery) (User, error) { return f(ctx, q) }

func TestUserQueryFailsClosedAcrossDependencies(t *testing.T) {
	for _, change := range []func(*queryFixture){
		func(f *queryFixture) {
			f.service.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
		},
		func(f *queryFixture) {
			f.service.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
			})
		},
		func(f *queryFixture) {
			f.service.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{}, errors.New("private provider detail")
			})
		},
		func(f *queryFixture) {
			f.service.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				panic("private provider detail")
			})
		},
		func(f *queryFixture) {
			f.service.config.Clock = queryClockFunc(func() time.Time { return time.Time{} })
		},
		func(f *queryFixture) {
			f.service.config.ValidateCanonicalUserID = func(context.Context, UserID) error { return errors.New("private source detail") }
		},
		func(f *queryFixture) { f.repo.err = ErrUserAbsent },
		func(f *queryFixture) { f.repo.err = errors.New("private database detail") },
		func(f *queryFixture) {
			f.service.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) {
				u := f.repo.user
				u.TenantID = "other"
				return u, nil
			})
		},
		func(f *queryFixture) {
			f.service.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) { u := f.repo.user; u.ID = "other"; return u, nil })
		},
		func(f *queryFixture) {
			f.service.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
				return RedactionPolicyDecision{}, errors.New("private policy detail")
			}
		},
		func(f *queryFixture) {
			f.service.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
				panic("private policy detail")
			}
		},
	} {
		f := newQueryFixture(t)
		change(&f)
		got, err := f.service.UserGet(context.Background(), f.request)
		if got != (UserGetResult{}) || err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("failure disclosed result/diagnostic: %v", err)
		}
	}
}

func TestUserQueryRejectsInvalidAdmissionAndConfiguration(t *testing.T) {
	for _, change := range []func(*UserGetRequest){
		func(r *UserGetRequest) { r.Context.Request.Subject.Kind = "invented" },
		func(r *UserGetRequest) { r.Context.Request.Subject.Groups = make([]authorization.SubjectID, 33) },
		func(r *UserGetRequest) { r.Context.Request.Subject.Groups = []authorization.SubjectID{""} },
		func(r *UserGetRequest) { r.Context.CorrelationID = strings.Repeat("a", 129) },
		func(r *UserGetRequest) { r.Context.Request.Action = "identity.user.delete" },
		func(r *UserGetRequest) { r.Context.Request.Resource.ID = "other" },
		func(r *UserGetRequest) {
			r.Context.Request.Attributes = authorization.Attributes{"bad name": authorization.StringValue("x")}
		},
		func(r *UserGetRequest) { r.Context.Request.Attributes = authorization.Attributes{"name": {}} },
		func(r *UserGetRequest) {
			r.Context.Request.Attributes = authorization.Attributes{"name": authorization.StringValue(strings.Repeat("x", 4097))}
		},
		func(r *UserGetRequest) {
			r.Context.Request.Attributes = authorization.Attributes{"name": authorization.StringSetValue([]string{strings.Repeat("x", 4097)})}
		},
		func(r *UserGetRequest) {
			r.Context.Request.Attributes = make(authorization.Attributes)
			for i := 0; i < 129; i++ {
				r.Context.Request.Attributes[authorization.AttributeName(strings.Repeat("x", i+1))] = authorization.BoolValue(true)
			}
		},
		func(r *UserGetRequest) {
			values := make([]string, 65)
			for i := range values {
				values[i] = strings.Repeat("x", i)
			}
			r.Context.Request.Attributes = authorization.Attributes{"name": authorization.StringSetValue(values)}
		},
	} {
		f := newQueryFixture(t)
		change(&f.request)
		got, err := f.service.UserGet(context.Background(), f.request)
		var invalid InvalidInputError
		if got != (UserGetResult{}) || !errors.As(err, &invalid) || f.repo.reads != 0 {
			t.Fatal("invalid admission reached a read")
		}
	}
	f := newQueryFixture(t)
	for _, change := range []func(*UserQueryConfig){
		func(c *UserQueryConfig) { c.Clock = nil },
		func(c *UserQueryConfig) { c.MaximumDuration = 0 },
		func(c *UserQueryConfig) { c.MaximumDuration = time.Minute + 1 },
		func(c *UserQueryConfig) { c.PolicyID = "" },
		func(c *UserQueryConfig) { c.PolicyVersion = 0 },
		func(c *UserQueryConfig) { c.ValidateCanonicalUserID = nil },
	} {
		c := f.service.config
		change(&c)
		if s, err := NewUserQueryService(f.repo, f.service.authorize, f.service.redact, c); s != nil || err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	var typedNil *queryStore
	if s, err := NewUserQueryService(typedNil, f.service.authorize, f.service.redact, f.service.config); s != nil || err == nil {
		t.Fatal("typed-nil store accepted")
	}
	if s, err := NewUserQueryService(nil, f.service.authorize, f.service.redact, f.service.config); s != nil || err == nil {
		t.Fatal("nil store accepted")
	}
	if s, err := NewUserQueryService(f.repo, nil, f.service.redact, f.service.config); s != nil || err == nil {
		t.Fatal("nil policy accepted")
	}
	if s, err := NewUserQueryService(f.repo, f.service.authorize, nil, f.service.config); s != nil || err == nil {
		t.Fatal("nil redactor accepted")
	}
	if got, err := f.service.UserGet(nil, f.request); got != (UserGetResult{}) || err == nil {
		t.Fatal("nil context accepted")
	}
	var nilService *UserQueryService
	if got, err := nilService.UserGet(context.Background(), f.request); got != (UserGetResult{}) || err == nil {
		t.Fatal("nil service accepted")
	}
}

func TestUserQueryCancellationNeverDisclosesPartialData(t *testing.T) {
	for _, stage := range []string{"initial", "canonical-error", "canonical-success", "authorization", "repository", "redaction"} {
		f := newQueryFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		switch stage {
		case "initial":
			cancel()
		case "canonical-error":
			f.service.config.ValidateCanonicalUserID = func(context.Context, UserID) error { cancel(); return errors.New("private") }
		case "canonical-success":
			f.service.config.ValidateCanonicalUserID = func(context.Context, UserID) error { cancel(); return nil }
		case "authorization":
			f.service.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				cancel()
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
		case "repository":
			f.service.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) { cancel(); return f.repo.user, nil })
		case "redaction":
			f.service.redact = func(c context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
				cancel()
				return queryRedact(c, in)
			}
		}
		got, err := f.service.UserGet(ctx, f.request)
		cancel()
		if got != (UserGetResult{}) || !errors.Is(err, context.Canceled) || err.Error() != "identity: cancelled" {
			t.Fatalf("cancelled %s disclosed data: %v", stage, err)
		}
	}
	f := newQueryFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got, err := f.service.UserGet(ctx, f.request); got != (UserGetResult{}) || !errors.Is(err, context.DeadlineExceeded) || err.Error() != "identity: deadline exceeded" {
		t.Fatal("expired deadline disclosed data")
	}
}

func TestUserQueryUsesOneTrustedClockSample(t *testing.T) {
	f := newQueryFixture(t)
	calls := 0
	f.service.config.Clock = queryClockFunc(func() time.Time { calls++; return queryClock{}.Now() })
	f.request.Context.Request.Environment.Time = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := f.service.UserGet(context.Background(), f.request); err != nil || calls != 1 {
		t.Fatal("query did not use one trusted clock sample")
	}
}

func TestUserQueryComposesWithRealAuthorizationEngine(t *testing.T) {
	f := newQueryFixture(t)
	snapshot, err := authorization.NewSnapshot(1, authorization.DenyOverrides)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	f.service.authorize, err = authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.service.UserGet(context.Background(), f.request)
	var forbidden ForbiddenError
	if got != (UserGetResult{}) || !errors.As(err, &forbidden) || f.repo.reads != 0 {
		t.Fatal("empty real authorization policy admitted storage access")
	}
}

func FuzzUserQueryAttributeAdmission(f *testing.F) {
	for _, raw := range []string{"", "bounded", "\xff", "secret\x00", strings.Repeat("a", 4096), strings.Repeat("a", 4097)} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r := UserGetRequest{TenantID: "tenant-a", UserID: "user-a", Context: authorization.DecisionContext{
			PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "actor-a"}, Action: "identity.user.get", Tenant: "tenant-a", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}, Attributes: authorization.Attributes{"tag": authorization.StringValue(raw)}},
		}}
		err := r.validate(1)
		if len(raw) > 4096 && err == nil {
			t.Fatal("oversized attribute admitted")
		}
		if err != nil && err.Error() != "identity: invalid input" {
			t.Fatal("attribute diagnostic leaked")
		}
	})
}

func TestUserQueryRedactionIsClosedAndBindingsAreCopied(t *testing.T) {
	f := newQueryFixture(t)
	for _, change := range []func(*RedactionPolicyDecision){
		func(d *RedactionPolicyDecision) { d.PolicyID = "other" },
		func(d *RedactionPolicyDecision) { d.PolicyVersion = 2 },
		func(d *RedactionPolicyDecision) { d.VisibleFields = nil },
		func(d *RedactionPolicyDecision) { d.RedactedFields = []FieldName{{"id"}} },
		func(d *RedactionPolicyDecision) { d.VisibleFields[0].Value = "secret" },
		func(d *RedactionPolicyDecision) { d.VisibleFields[0].Value = "version" },
	} {
		f.service.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
			d, _ := queryRedact(ctx, in)
			change(&d)
			return d, nil
		}
		if got, err := f.service.UserGet(context.Background(), f.request); got != (UserGetResult{}) || err == nil {
			t.Fatal("invalid redaction disclosed data")
		}
	}
	f = newQueryFixture(t)
	f.request.Context.Request.Subject.Groups = []authorization.SubjectID{"group-a"}
	f.request.Context.Request.Attributes = authorization.Attributes{"tag": authorization.StringSetValue([]string{"a", "b"})}
	f.service.authorize = queryDecisionFunc(func(ctx context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
		in.Request.Subject.Groups[0] = "changed"
		in.Request.Attributes["tag"] = authorization.StringValue("changed")
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	f.service.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		if in.ViewerID != "actor-a" || in.TenantID != "tenant-a" || in.Resource.ID != string(f.request.UserID) || in.OperationID != "identity.user.get" || in.PolicyVersion != 1 || in.Deadline.IsZero() {
			t.Fatal("redaction binding lost")
		}
		return queryRedact(ctx, in)
	}
	if _, err := f.service.UserGet(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	if f.request.Context.Request.Subject.Groups[0] != "group-a" || f.request.Context.Request.Attributes["tag"].Kind() != authorization.ValueStringSet {
		t.Fatal("dependency mutated caller input")
	}
}
