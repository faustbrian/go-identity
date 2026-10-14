//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

type directoryExecutionPhase struct {
	featureExecutionPhase
	expected      DirectoryAuthorityAdmission
	provisional   bool
	shortDeadline bool
	after         func(context.Context, Work) error
}

func (p *directoryExecutionPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	s, _ := command.Feature()
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
	if err := w.RequireActiveDirectoryAuthority(admissionCtx, p, p.expected); err != nil {
		// Deliberately ignore denial. Coordinator must still abort prior effects.
		return identity.FeatureReceipt{}, nil
	}
	if p.after != nil {
		if err := p.after(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return p.featureExecutionPhase.ApplyFeature(ctx, w, command)
}

func testDirectoryAuthority(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	q := DirectoryAuthorityQuery{GlobalAuthorityID: "deployment'\\opaque", TenantID: "directory"}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('directory','user','active',1)`); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetDirectoryAuthority(ctx, q)
	if err != nil || got.GlobalVersion != 1 || got.TenantVersion != 1 || !got.Enabled {
		t.Fatal("explicit bootstrap scope changed", err)
	}
	for _, query := range []DirectoryAuthorityQuery{{GlobalAuthorityID: "missing", TenantID: q.TenantID}, {GlobalAuthorityID: q.GlobalAuthorityID, TenantID: "tenant-a"}} {
		var denied identity.ForbiddenError
		if _, err := repo.GetDirectoryAuthority(ctx, query); !errors.As(err, &denied) {
			t.Fatal("authority inferred/defaulted from user", err)
		}
	}
	phase := &directoryExecutionPhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, phase})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, change                   string
		expectedGlobal, expectedTenant uint64
		allowed                        bool
	}{
		{"exact", "", 1, 1, true},
		{"global advanced", `UPDATE identity.global_authorities SET version=2`, 1, 1, false},
		{"global expected newer", "", 2, 1, false},
		{"tenant advanced", `UPDATE identity.tenant_authorities SET version=2 WHERE tenant_id='directory'`, 1, 1, false},
		{"tenant expected newer", "", 1, 2, false},
		{"disabled", `UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id='directory'`, 1, 1, false},
		{"missing global", "", 1, 1, false},
		{"missing tenant", `DELETE FROM identity.tenant_authorities WHERE tenant_id='directory'`, 1, 1, false},
		{"global writer first", "", 1, 1, false},
		{"tenant writer first", "", 1, 1, false},
		{"global lock deadline", "", 1, 1, false},
		{"tenant lock deadline", "", 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.global_authorities SET version=1; INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('directory',1,true) ON CONFLICT(tenant_id) DO UPDATE SET version=1,enabled=true`); err != nil {
				t.Fatal(err)
			}
			if tc.change != "" {
				if _, err := pool.Raw().Exec(ctx, tc.change); err != nil {
					t.Fatal(err)
				}
			}
			phase.expected = DirectoryAuthorityAdmission{Query: q, GlobalVersion: tc.expectedGlobal, TenantVersion: tc.expectedTenant}
			if tc.name == "missing global" {
				phase.expected.Query.GlobalAuthorityID = "missing"
			}
			phase.provisional = !tc.allowed
			phase.shortDeadline = tc.name == "global lock deadline" || tc.name == "tenant lock deadline"
			var writerDone chan struct{}
			var writerErr error
			if tc.name == "global writer first" || tc.name == "tenant writer first" || phase.shortDeadline {
				writer, e := pool.Raw().Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				sql := `UPDATE identity.global_authorities SET version=2`
				if tc.name == "tenant writer first" || tc.name == "tenant lock deadline" {
					sql = `UPDATE identity.tenant_authorities SET version=2 WHERE tenant_id='directory'`
				}
				if _, e = writer.Exec(ctx, sql); e != nil {
					writer.Rollback(ctx)
					t.Fatal(e)
				}
				writerDone = make(chan struct{})
				go func() {
					defer close(writerDone)
					timer := time.NewTimer(100 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
						writerErr = writer.Commit(ctx)
					case <-ctx.Done():
						cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						writerErr = writer.Rollback(cleanup)
					}
				}()
				defer func() {
					<-writerDone
					if writerErr != nil {
						t.Error("writer cleanup", writerErr)
					}
				}()
			}
			phase.after = func(call context.Context, w Work) error {
				for _, sql := range []string{`SELECT authority_id FROM identity.global_authorities FOR UPDATE NOWAIT`, `SELECT tenant_id FROM identity.tenant_authorities WHERE tenant_id='directory' FOR UPDATE NOWAIT`} {
					tx, err := pool.Raw().Begin(call)
					if err != nil {
						return err
					}
					_, err = tx.Exec(call, sql)
					tx.Rollback(call)
					var locked *pgconn.PgError
					if !errors.As(err, &locked) || locked.Code != "55P03" {
						t.Fatal("authority lock not retained")
					}
				}
				return nil
			}
			s := featureCodecSpec()
			s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic"}}}
			s.Binding.TenantID = "directory"
			s.Binding.UserID = "user"
			s.Binding.ActorID = "user"
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.RecordID = string(s.Binding.CommandID)
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
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, err := coordinator.ApplyFeature(ctx, work, command)
			if tc.allowed {
				if err != nil {
					t.Fatal("exact authority denied", err)
				}
				result, err = coordinator.Commit(work, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("admission did not commit", err)
				}
			} else {
				var denied identity.ForbiddenError
				if phase.shortDeadline && !errors.Is(err, context.DeadlineExceeded) || !phase.shortDeadline && !errors.As(err, &denied) {
					t.Fatal("unsafe authority admitted", err)
				}
				result, err = coordinator.Commit(work, result)
				// Driver cancellation can close the connection before rollback
				// acknowledgement. Preserve Unknown, not invented noncommit proof.
				if result.Outcome != identity.CommitOutcomeNotCommitted && (!phase.shortDeadline || result.Outcome != identity.CommitOutcomeUnknown) {
					t.Fatal("ignored denial committed", err)
				}
			}
			var effects int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1`, string(s.Binding.CommandID)).Scan(&effects); err != nil || effects != map[bool]int{true: 1, false: 0}[tc.allowed] {
				t.Fatal("provisional effects escaped", err)
			}
			if writerDone != nil {
				<-writerDone
			}
			for _, sql := range []string{`SELECT authority_id FROM identity.global_authorities FOR UPDATE NOWAIT`, `SELECT tenant_id FROM identity.tenant_authorities FOR UPDATE NOWAIT`} {
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(ctx, sql)
				tx.Rollback(ctx)
				if err != nil {
					t.Fatal("terminal authority lock leaked", err)
				}
			}
		})
	}
}
