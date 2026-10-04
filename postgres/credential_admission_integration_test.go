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

// This seam proves the kernel's locked eligibility check under the original
// coordinator. It is not a session issuer or a complete authority vector.
func testLockedCredentialAdmission(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('admission','user','active',101,11,13,17); INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('admission','user','ref',1,'identity/password',7,true)`); err != nil {
		t.Fatal(err)
	}
	expected := CredentialAdmission{Credential: identity.CredentialRef{ID: "ref", TenantID: "admission", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17}
	phase := &featureExecutionPhase{admission: &expected}
	auditing, lifecycle := &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, phase})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, change string
		allowed      bool
	}{
		{"exact independent epochs", "", true},
		{"absent reference", "", false},
		{"foreign reference", "", false},
		{"aggregate is not authority", `UPDATE identity.users SET version=102 WHERE tenant_id='admission'`, true},
		{"user epoch", `UPDATE identity.users SET authority_version=12 WHERE tenant_id='admission'`, false},
		{"identifier epoch", `UPDATE identity.users SET identifier_version=14 WHERE tenant_id='admission'`, false},
		{"credential epoch", `UPDATE identity.users SET credential_version=18 WHERE tenant_id='admission'`, false},
		{"record version", `UPDATE identity.credential_references SET version=8 WHERE tenant_id='admission'`, false},
		{"suspended", `UPDATE identity.users SET status='suspended' WHERE tenant_id='admission'`, false},
		{"disabled", `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='admission'`, false},
		{"expired", `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id='admission'`, false},
		{"expiry during lock wait", `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '200 milliseconds' WHERE tenant_id='admission'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',version=101,authority_version=11,identifier_version=13,credential_version=17 WHERE tenant_id='admission'; UPDATE identity.credential_references SET version=7,enabled=true,expires_at=NULL WHERE tenant_id='admission'`); err != nil {
				t.Fatal(err)
			}
			if tc.change != "" {
				if _, err := pool.Raw().Exec(ctx, tc.change); err != nil {
					t.Fatal(err)
				}
			}
			admission := expected
			if tc.name == "absent reference" || tc.name == "foreign reference" {
				admission.Credential.ID = "missing"
			}
			if tc.name == "foreign reference" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('other','user','active',101,11,13,17); INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('other','user','missing',1,'identity/password',7,true)`); err != nil {
					t.Fatal(err)
				}
			}
			phase.admission = &admission
			phase.ignoreAdmissionDenial = !tc.allowed
			phase.beforeAdmission = nil
			var blockerDone chan error
			if tc.name == "expiry during lock wait" {
				blocker, e := pool.Raw().Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = blocker.Exec(ctx, `SELECT user_id FROM identity.users WHERE tenant_id='admission' FOR UPDATE`); e != nil {
					blocker.Rollback(ctx)
					t.Fatal(e)
				}
				blockerDone = make(chan error, 1)
				go func() {
					timer := time.NewTimer(300 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
					}
					blockerDone <- blocker.Rollback(ctx)
				}()
				defer func() {
					if e := <-blockerDone; e != nil {
						t.Error("blocker cleanup", e)
					}
				}()
			}
			s := featureCodecSpec()
			s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-private-value"}}}
			s.Binding.TenantID = "admission"
			s.Binding.UserID = "user"
			s.Binding.ActorID = "user"
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.RecordID = string(s.Binding.CommandID)
			command := featureCodecCommand(t, s)
			_, _, plan := featurePlanFixture(t)
			plan.Contributors = registry.Descriptors()
			plan.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: s.Operation}
			plan.SubjectType = "session"
			seed, e := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
			if e != nil {
				t.Fatal(e)
			}
			plan.Audits[0].RetentionClass = "standard"
			plan.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
			if e != nil {
				t.Fatal(e)
			}
			plan, e = coordinator.PrepareCommandPlan(s.Binding, command, plan)
			if e != nil {
				t.Fatal(e)
			}
			reservation, _, e := coordinator.ReserveCommand(ctx, s.Binding, command, plan)
			if e != nil {
				t.Fatal(e)
			}
			work, e := coordinator.Begin(ctx, reservation)
			if e != nil {
				t.Fatal(e)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			if !tc.allowed {
				phase.beforeAdmission = func(call context.Context, w Work) error {
					_, err := w.Exec(call, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,'provisional')`, string(s.Binding.TenantID), s.Binding.RecordID, string(s.Binding.CommandID))
					return err
				}
			}
			phase.afterAdmission = func(call context.Context, w Work) error {
				for _, sql := range []string{`SELECT user_id FROM identity.users WHERE tenant_id='admission' FOR UPDATE NOWAIT`, `SELECT credential_id FROM identity.credential_references WHERE tenant_id='admission' FOR UPDATE NOWAIT`} {
					tx, e := pool.Raw().Begin(call)
					if e != nil {
						return e
					}
					_, e = tx.Exec(call, sql)
					tx.Rollback(call)
					var locked *pgconn.PgError
					if !errors.As(e, &locked) || locked.Code != "55P03" {
						t.Fatal("admission did not retain authority lock")
					}
				}
				return nil
			}
			result, e := coordinator.ApplyFeature(ctx, work, command)
			if tc.allowed {
				if e != nil {
					t.Fatal("active credential denied", e)
				}
				result, e = coordinator.Commit(work, result)
				if e != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("admitted command failed", e)
				}
			} else {
				var denied identity.ForbiddenError
				if !errors.As(e, &denied) {
					t.Fatal("unsafe credential admitted", e)
				}
				if _, ignored := work.Exec(ctx, "SELECT 1"); !errors.As(ignored, &denied) {
					t.Fatal("ignored admission denial left Work usable", ignored)
				}
				result, e = coordinator.Commit(work, result)
				if result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("denial did not abort", e)
				}
			}
			var effects int
			if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1`, string(s.Binding.CommandID)).Scan(&effects); e != nil || effects != map[bool]int{true: 1, false: 0}[tc.allowed] {
				t.Fatal("unsafe provisional effect escaped", e)
			}
			tx, e := pool.Raw().Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			_, e = tx.Exec(ctx, `SELECT user_id FROM identity.users WHERE tenant_id='admission' FOR UPDATE NOWAIT`)
			tx.Rollback(ctx)
			if e != nil {
				t.Fatal("authority locks retained after terminalization", e)
			}
		})
	}
}
