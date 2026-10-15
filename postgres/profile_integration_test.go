//go:build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testProfileReads(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, owner *CreationUnitOfWork, creation *identity.UserCreationService, request func() identity.UserCreateRequest) {
	req := request()
	req.Fields[5].Value.List = []identity.AttributeScalar{{Kind: identity.AttributeString, String: "profile-tag"}}
	if result, err := creation.UserCreate(ctx, req); err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("public typed profile creation failed", err)
	}
	query := identity.ProfileQuery{TenantID: req.TenantID, UserID: req.UserID}
	first, err := repo.GetProfile(ctx, query)
	if err != nil || first.Profile.Version != 1 || first.User.Version != 1 || !reflect.DeepEqual(first.Profile.AdditionalFields, req.Fields) {
		t.Fatal("public creation values not projected losslessly", err)
	}
	first.Profile.AdditionalFields[5].Value.List[0].String = "changed"
	again, err := repo.GetProfile(ctx, query)
	if err != nil || !reflect.DeepEqual(again.Profile.AdditionalFields, req.Fields) {
		t.Fatal("profile read retained aliases", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.user_profiles VALUES($1,$2,'Profile name','https://images.example.test/avatar.png')`, string(req.TenantID), string(req.UserID)); err != nil {
		t.Fatal(err)
	}
	var hide bool
	service, err := identity.NewProfileService(repo, owner, queryDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		outcome := authorization.Deny
		if dc.Request.Subject.Kind == authorization.SubjectUser && string(dc.Request.Subject.ID) == string(req.UserID) && dc.Request.Action == "identity.profile.get" {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: 1}, nil
	}), func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		d := identity.RedactionPolicyDecision{PolicyID: "policy", PolicyVersion: 1, Reason: "visible"}
		for _, f := range in.Fields {
			if f.Value == "flag" || hide && f.Value == "name" {
				d.RedactedFields = append(d.RedactedFields, f)
			} else {
				d.VisibleFields = append(d.VisibleFields, f)
			}
		}
		return d, nil
	}, identity.ProfileConfig{AllowedImageOrigins: []string{"https://images.example.test"}, Fields: identity.UserCreationConfig{Query: identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "policy", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }}, Schema: storageSchema(), Normalize: func(context.Context, identity.NormalizationPolicy, identity.AttributeScalar) (identity.AttributeScalar, error) {
		panic("unexpected normalization")
	}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	current := identity.ProfileGetRequest{TenantID: req.TenantID, Context: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(req.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(req.UserID)}, Action: "identity.profile.get", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(req.UserID)}}}}
	public, err := service.ProfileGet(ctx, current)
	if err != nil || public.User.Name != "Profile name" || public.User.Image != "https://images.example.test/avatar.png" || len(public.User.AdditionalFields) != 5 || public.User.AdditionalFields[1].Name != "minimum" {
		t.Fatal("public profile authorization/redaction did not compose", err)
	}
	hide = true
	public, err = service.ProfileGet(ctx, current)
	hide = false
	if err != nil || public.User.Name != "" {
		t.Fatal("current redaction did not withhold name", err)
	}
	t.Run("selection permission and exact schema", func(t *testing.T) {
		q := query
		q.Fields = []identity.FieldName{{Value: "tags"}}
		result, err := repo.GetProfile(ctx, q)
		if err != nil || result.Profile.Name != "" || result.Profile.Image != "" || len(result.Profile.AdditionalFields) != 1 || result.Profile.AdditionalFields[0].Name != "tags" {
			t.Fatal("subset projection leaked other fields", err)
		}
		denied := storageSchema()
		denied.Fields[1].OutputPermission = identity.FieldDenied
		mismatched, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{denied}, ProfileSchema: ProfileSchemaRef{ID: "fields", Version: 1}})
		if err != nil {
			t.Fatal(err)
		}
		result, err = mismatched.GetProfile(ctx, query)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || result.Profile.ID != "" {
			t.Fatal("immutable schema mismatch disclosed profile", err)
		}
		disabled, err := NewRepository(pool, Config{MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := disabled.GetProfile(ctx, query); err == nil {
			t.Fatal("unselected profile feature enabled")
		}
	})
	t.Run("scope absence cancellation and corruption", func(t *testing.T) {
		q := query
		q.TenantID = "foreign-profile"
		if result, err := repo.GetProfile(ctx, q); !errors.Is(err, identity.ErrUserAbsent) || result.Profile.ID != "" {
			t.Fatal("tenant absence changed", err)
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if result, err := repo.GetProfile(cancelled, query); !errors.Is(err, context.Canceled) || result.Profile.ID != "" {
			t.Fatal("cancelled profile disclosed data", err)
		}
		var original []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT document FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.user_attributes SET document=$3 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID), append(append([]byte(nil), original...), 0)); err != nil {
			t.Fatal(err)
		}
		q = query
		q.Fields = []identity.FieldName{{Value: "id"}}
		result, err := repo.GetProfile(ctx, q)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || result.Profile.ID != "" || len(result.Profile.AdditionalFields) != 0 {
			t.Fatal("corrupt unselected document returned prefix", err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.user_attributes SET document=$3 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID), original); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("blocked primary read honors deadline and releases pool", func(t *testing.T) {
		lock, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, `LOCK TABLE identity.user_profiles IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		record, err := repo.GetProfile(short, query)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) || record.Profile.ID != "" {
			t.Fatal("blocked profile ignored deadline", err)
		}
		if err := lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := pool.Ping(ctx); err != nil {
			t.Fatal("profile query leaked pool ownership", err)
		}
	})
	t.Run("one aggregate snapshot under concurrent commits", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.user_profiles SET name='1' WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)); err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		failures := make(chan error, 1)
		group.Go(func() {
			for i := 2; i <= 30; i++ {
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					failures <- err
					return
				}
				_, err = tx.Exec(ctx, `UPDATE identity.users SET version=$3 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID), strconv.Itoa(i))
				if err == nil {
					_, err = tx.Exec(ctx, `UPDATE identity.user_profiles SET name=$3 WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID), strconv.Itoa(i))
				}
				if err == nil {
					err = tx.Commit(ctx)
				}
				if err != nil {
					_ = tx.Rollback(ctx)
					failures <- err
					return
				}
			}
		})
		defer group.Wait()
		for range 50 {
			record, err := repo.GetProfile(ctx, query)
			if err != nil || record.Profile.Name != strconv.FormatUint(record.User.Version, 10) || record.Profile.Version != record.User.Version {
				t.Fatal("torn aggregate profile snapshot", err)
			}
		}
		group.Wait()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
	})
	t.Run("blocked self and unsupported image remain withheld", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)); err != nil {
			t.Fatal(err)
		}
		var forbidden identity.ForbiddenError
		if result, err := service.ProfileGet(ctx, current); !errors.As(err, &forbidden) || result.User.ID != "" {
			t.Fatal("blocked profile self-service disclosed data", err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.user_profiles SET image='https://unselected.example.test/x' WHERE tenant_id=$1 AND user_id=$2`, string(req.TenantID), string(req.UserID)); err != nil {
			t.Fatal(err)
		}
		if result, err := service.ProfileGet(ctx, current); err == nil || result.User.ID != "" {
			t.Fatal("stored image bypassed public origin policy")
		}
	})
}
