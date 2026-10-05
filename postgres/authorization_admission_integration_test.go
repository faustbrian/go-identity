//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type authorizationExecutionPhase struct {
	featureExecutionPhase
	expected      UserAuthorizationAdmission
	provisional   bool
	shortDeadline bool
	after         func(context.Context, Work) error
}

// Fixture-only encoding freezes all admission dimensions into the existing
// one-field synthetic command. Production adapters own their typed native codec.
func authorizationFixtureIntent(a UserAuthorizationAdmission) string {
	return fmt.Sprintf("%q/%q/%q/%d", a.Scope.TenantID, a.Scope.PolicyNamespace, a.Scope.SubjectID, a.Version)
}

func (p *authorizationExecutionPhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	if err := p.featureExecutionPhase.ValidateFeatureCommand(c, plan); err != nil {
		return err
	}
	s, _ := c.Feature()
	if s.Fields[0].Value.Text != authorizationFixtureIntent(p.expected) {
		return invalidPlan()
	}
	return nil
}

func (p *authorizationExecutionPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	s, _ := c.Feature()
	if s.Fields[0].Value.Text != authorizationFixtureIntent(p.expected) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.provisional {
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,'provisional')`, string(s.Binding.TenantID), s.Binding.RecordID, string(s.Binding.CommandID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	admissionCtx := ctx
	if p.shortDeadline {
		var cancel context.CancelFunc
		admissionCtx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
	}
	if err := w.RequireActiveUserAuthorization(admissionCtx, p, p.expected); err != nil {
		// An otherwise valid receipt cannot hide admission failure or commit
		// the provisional effect. Work, not this fixture, enforces that rule.
		return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
	}
	if p.after != nil {
		if err := p.after(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return p.featureExecutionPhase.ApplyFeature(ctx, w, c)
}

func rollbackAuthorizationFixture(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func testUserAuthorizationAdmission(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	migration, err := authority.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, migration.Up); err != nil {
		t.Fatal(err)
	}
	scope := authority.AuthorityScope{TenantID: "authorization", PolicyNamespace: "user-policy", SubjectID: "effective-user"}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('authorization','effective-user','active',1)`); err != nil {
		t.Fatal(err)
	}
	for _, s := range []authority.AuthorityScope{scope, {TenantID: "foreign", PolicyNamespace: scope.PolicyNamespace, SubjectID: scope.SubjectID}, {TenantID: scope.TenantID, PolicyNamespace: "decoy-policy", SubjectID: scope.SubjectID}, {TenantID: scope.TenantID, PolicyNamespace: scope.PolicyNamespace, SubjectID: "human-actor"}} {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackAuthorizationFixture(tx)
		if _, err := authority.InitializeAuthority(ctx, tx, s, time.Second); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.AdvanceAuthority(ctx, tx, s, 1, time.Second); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	phase := &authorizationExecutionPhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, phase})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		version uint64
		allowed bool
	}{
		{"current", 2, true}, {"stale", 1, false}, {"future", 3, false}, {"missing", 2, false}, {"foreign tenant", 2, false}, {"actor substitution", 2, false}, {"lock deadline", 2, false}, {"changed command", 2, false}, {"writer first", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase.expected = UserAuthorizationAdmission{Scope: scope, Version: tc.version}
			if tc.name == "missing" {
				phase.expected.Scope.PolicyNamespace = "absent-policy"
			}
			if tc.name == "foreign tenant" {
				phase.expected.Scope.TenantID = "foreign"
			}
			if tc.name == "actor substitution" {
				phase.expected.Scope.SubjectID = "human-actor"
			}
			phase.provisional = !tc.allowed
			phase.shortDeadline = tc.name == "lock deadline"
			lock := func(call context.Context) error {
				tx, err := pool.Raw().Begin(call)
				if err != nil {
					return err
				}
				defer rollbackAuthorizationFixture(tx)
				_, err = tx.Exec(call, `SELECT subject_id FROM authorization_subject_authorities WHERE tenant_id='authorization' AND policy_namespace='user-policy' AND subject_id='effective-user' FOR UPDATE NOWAIT`)
				var blocked *pgconn.PgError
				if !errors.As(err, &blocked) || blocked.Code != "55P03" {
					return fmt.Errorf("admission share lock was released")
				}
				return nil
			}
			phase.after = func(call context.Context, _ Work) error { return lock(call) }
			s := featureCodecSpec()
			s.Binding.TenantID = "authorization"
			s.Binding.UserID = "effective-user"
			s.Binding.ActorID = "human-actor"
			s.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			s.Binding.RecordID = string(s.Binding.CommandID)
			s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: authorizationFixtureIntent(phase.expected)}}}
			command := featureCodecCommand(t, s)
			_, _, plan := featurePlanFixture(t)
			plan.Contributors = registry.Descriptors()
			plan.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: s.Operation}
			plan.SubjectType = "session"
			seed, err := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].RetentionClass = "standard"
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(s.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, s.Binding, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if tc.allowed {
				original := phase.expected
				for _, change := range []func(*UserAuthorizationAdmission){
					func(a *UserAuthorizationAdmission) { a.Scope.TenantID = "foreign" },
					func(a *UserAuthorizationAdmission) { a.Scope.PolicyNamespace = "decoy-policy" },
					func(a *UserAuthorizationAdmission) { a.Scope.SubjectID = "human-actor" },
					func(a *UserAuthorizationAdmission) { a.Version++ },
				} {
					phase.expected = original
					change(&phase.expected)
					changed := s
					changed.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: authorizationFixtureIntent(phase.expected)}}}
					changedCommand := featureCodecCommand(t, changed)
					changedPlan, e := coordinator.PrepareCommandPlan(changed.Binding, changedCommand, plan)
					if e != nil {
						t.Fatal(e)
					}
					_, _, e = coordinator.ReserveCommand(ctx, changed.Binding, changedCommand, changedPlan)
					var conflict identity.ConflictError
					if !errors.As(e, &conflict) {
						t.Fatal("authority intent substitution reused reservation", e)
					}
				}
				phase.expected = original
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			var lockedWriter pgx.Tx
			if tc.name == "writer first" || phase.shortDeadline {
				writer, e := pool.Raw().Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				defer rollbackAuthorizationFixture(writer)
				if tc.name == "writer first" {
					if _, e = authority.AdvanceAuthority(ctx, writer, scope, 2, time.Second); e != nil {
						t.Fatal(e)
					}
					if e = writer.Commit(ctx); e != nil {
						t.Fatal(e)
					}
				} else {
					if _, e = writer.Exec(ctx, `SELECT subject_id FROM authorization_subject_authorities WHERE tenant_id='authorization' AND policy_namespace='user-policy' AND subject_id='effective-user' FOR UPDATE`); e != nil {
						t.Fatal(e)
					}
					// This writer stays locked until Apply returns its bounded denial.
					lockedWriter = writer
				}
			}
			applying := command
			if tc.name == "changed command" {
				changed := s
				changed.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "changed"}}}
				applying = featureCodecCommand(t, changed)
			}
			result, err := coordinator.ApplyFeature(ctx, work, applying)
			if lockedWriter != nil {
				rollbackAuthorizationFixture(lockedWriter)
			}
			if tc.allowed {
				if err != nil {
					t.Fatal("exact admission failed", err)
				}
				if err = lock(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				var denied identity.ForbiddenError
				var invalid identity.InvalidInputError
				var conflict identity.ConflictError
				matches := errors.As(err, &denied)
				switch tc.name {
				case "foreign tenant", "actor substitution":
					matches = errors.As(err, &invalid)
				case "lock deadline":
					matches = errors.Is(err, context.DeadlineExceeded)
				case "changed command":
					matches = errors.As(err, &conflict)
				}
				if !matches {
					t.Fatal("ignored denial was not preserved", err)
				}
				if _, err = work.Scope(); err == nil {
					t.Fatal("denied Work remained usable")
				}
			}
			result, err = coordinator.Commit(work, result)
			want := identity.CommitOutcomeNotCommitted
			if tc.allowed {
				want = identity.CommitOutcomeCommitted
			}
			if tc.name == "changed command" {
				// Existing coordinator rejects changed intent before preparing
				// failure audit. Preserve its recoverable Unknown, not a fabricated
				// terminal noncommit acknowledgement.
				want = identity.CommitOutcomeUnknown
			}
			if result.Outcome != want && !(phase.shortDeadline && result.Outcome == identity.CommitOutcomeUnknown) {
				t.Fatal("incorrect terminal outcome", err)
			}
			for _, table := range []string{"identity_test_feature", "identity_test_feature_audits", "identity_test_lifecycle"} {
				var count int
				wantCount := map[bool]int{true: 1, false: 0}[tc.allowed]
				if table == "identity_test_feature_audits" {
					// The original coordinator owns a required denial audit after
					// rollback. It is not a committed protected mutation.
					wantCount = 1
					if result.Outcome == identity.CommitOutcomeUnknown {
						wantCount = 0
					}
				}
				if err := pool.Raw().QueryRow(ctx, "SELECT count(*) FROM public."+table+" WHERE command_id=$1", string(s.Binding.CommandID)).Scan(&count); err != nil || count != wantCount {
					t.Fatal("atomic protected effects changed", table, err)
				}
			}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackAuthorizationFixture(tx)
			currentEpoch := uint64(2)
			if tc.name == "writer first" {
				currentEpoch = 3
			}
			if _, err := authority.AdvanceAuthority(ctx, tx, scope, currentEpoch, time.Second); err != nil {
				t.Fatal("terminal lock leaked or authority changed", err)
			}
			rollbackAuthorizationFixture(tx) // Keep epoch two for the next case.
		})
	}
}
