//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func statusFixtureConfig() StatusUnitOfWorkConfig {
	contracts := make(map[string]StatusConsumerContract)
	for _, id := range []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "oauth-server/device", "oauth-server/oidc", "authorization", "authorization/valkey", "identity/risk", "audit"} {
		contracts[id] = StatusConsumerContract{Version: 1, Fingerprint: [32]byte{1}}
	}
	return StatusUnitOfWorkConfig{RetentionPolicyVersion: 1, PolicyVersion: 1, Reasons: []string{"security"}, MaximumCascadeDuration: time.Hour, ConsumerContracts: contracts, Policy: identity.StatusPolicy{MaximumSuspension: time.Hour, BanRequiresReason: true, AllowedTransitions: []identity.StatusTransition{{From: identity.StatusActive, To: identity.StatusSuspended}, {From: identity.StatusActive, To: identity.StatusBanned}, {From: identity.StatusSuspended, To: identity.StatusActive}, {From: identity.StatusBanned, To: identity.StatusActive}}}}
}

func testStatusLifecycle(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	var err error
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('status','user','active',7),('status-other','user','banned',11)`); err != nil {
		t.Fatal(err)
	}
	phase, outbox := &domainAuditPhase{}, &domainLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, phase, outbox})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewStatusUnitOfWork(coordinator, repo, statusFixtureConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("creation and ordinary attributes keep separate security epoch", func(t *testing.T) {
		creation, e := NewCreationUnitOfWork(coordinator, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		b := codecBinding()
		b.CommandID, _ = identity.NewCommandID()
		b.UserID = "status-profile"
		cmd, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive, Attributes: storageValues()})
		if e != nil {
			t.Fatal(e)
		}
		if result, e := creation.Execute(ctx, cmd); e != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("creation failed", e)
		}
		state, e := repo.GetStatus(ctx, identity.UserStatusQuery{TenantID: b.TenantID, UserID: b.UserID})
		if e != nil || state.User.Version != 1 || state.AuthorityVersion != 1 {
			t.Fatal("creation epoch absent", e)
		}
		update, e := NewUserUpdateUnitOfWork(coordinator, repo, CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		b.CommandID, _ = identity.NewCommandID()
		b.OperationID = "identity.user.update-admin"
		value := storageValues()[1]
		value.Value.Scalar.Bool = true
		cmd, e = identity.NewUserUpdateCommand(identity.UpdateUserCommand{Binding: b, ExpectedVersion: 1, Attributes: []identity.AttributeUpdate{value}})
		if e != nil {
			t.Fatal(e)
		}
		if result, e := update.Execute(ctx, cmd); e != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("attribute update failed", e)
		}
		state, e = repo.GetStatus(ctx, identity.UserStatusQuery{TenantID: b.TenantID, UserID: b.UserID})
		if e != nil || state.User.Version != 2 || state.AuthorityVersion != 1 {
			t.Fatal("ordinary write invalidated security", e)
		}
		ids, e := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 1})
		if e != nil || ids.AuthorityVersion != 1 {
			t.Fatal("unrelated identifier dimension changed", e)
		}
	})
	command := func(op string, version, authority uint64) identity.Command {
		b := codecBinding()
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		b.TenantID, b.UserID, b.OperationID, b.SchemaID, b.SchemaVersion = "status", "user", op, "identity-lifecycle", 1
		target, reason := identity.StatusSuspended, "security"
		switch op {
		case "identity.admin.user-ban":
			target = identity.StatusBanned
		case "identity.user.restore", "identity.admin.user-unban":
			target, reason = identity.StatusActive, ""
		}
		cmd, e := identity.NewUserStatusCommand(identity.UserStatusCommand{Binding: b, ExpectedVersion: version, ExpectedAuthorityVersion: authority, StatusPolicyVersion: 1, TargetStatus: target, Reason: reason})
		if e != nil {
			t.Fatal(e)
		}
		return cmd
	}
	read := func(tenant identity.TenantID, version, authority uint64, status identity.Status) {
		t.Helper()
		got, e := repo.GetStatus(ctx, identity.UserStatusQuery{TenantID: tenant, UserID: "user"})
		if e != nil || got.User.Version != version || got.AuthorityVersion != authority || got.User.Status != status {
			t.Fatal("wrong primary authority", got, e)
		}
	}
	read("status", 7, 1, identity.StatusActive)
	read("status-other", 11, 1, identity.StatusBanned)
	if _, e := repo.GetStatus(ctx, identity.UserStatusQuery{TenantID: "missing", UserID: "user"}); !errors.Is(e, identity.ErrUserAbsent) {
		t.Fatal("absence classification", e)
	}
	suspend := command("identity.user.suspend", 7, 1)
	serviceConfig := statusFixtureConfig()
	service, e := identity.NewUserStatusService(repo, owner, queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}), func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "policy", PolicyVersion: 1, Reason: "visible"}, nil
	}, identity.UserStatusConfig{Query: identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "policy", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }}, Policy: serviceConfig.Policy, PolicyVersion: 1, Reasons: serviceConfig.Reasons})
	if e != nil {
		t.Fatal("public status service could not compose", e)
	}
	intent, _ := suspend.UserStatus()
	_, caller := queryInputs(intent.Binding)
	caller.PolicyRevision = 1
	public, e := service.UserSuspend(ctx, identity.UserStatusRequest{CommandID: intent.Binding.CommandID, TenantID: intent.Binding.TenantID, UserID: intent.Binding.UserID, ExpectedVersion: 7, ExpectedAuthorityVersion: 1, Reason: "security", ActorScope: caller, CorrelationID: intent.Binding.CorrelationID})
	if e != nil || public.CommitOutcome != identity.CommitOutcomeCommitted || public.User.Status.AllowsAuthentication() || public.Revocation.Status != identity.RevocationPending {
		t.Fatal("public status service did not deny authority", e)
	}
	first, e := owner.Execute(ctx, suspend)
	if e != nil || first.Outcome != identity.CommitOutcomeCommitted || first.Revocation == nil || first.Revocation.Status != identity.RevocationPending || first.Revocation.AuthorityVersion != 2 || len(first.Revocation.Owners) != 12 {
		t.Fatal("durable suspend absent", first, e)
	}
	read("status", 8, 2, identity.StatusSuspended)
	assertEffects := func(id identity.CommandID, admissions, members, events int) {
		t.Helper()
		var gotAdmissions, gotMembers, gotEvents int
		if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.status_cascades WHERE command_id=$1),(SELECT count(*) FROM identity.status_consumers c JOIN identity.status_cascades s USING(tenant_id,cascade_id) WHERE s.command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(id)).Scan(&gotAdmissions, &gotMembers, &gotEvents); e != nil || gotAdmissions != admissions || gotMembers != members || gotEvents != events {
			t.Fatal("partial admission effects", gotAdmissions, gotMembers, gotEvents, e)
		}
	}
	assertConsumers := func(r identity.CommandResult, expected []string) {
		t.Helper()
		rows, e := pool.Raw().Query(ctx, `SELECT ordinal,consumer_id,contract_version,contract_fingerprint,state FROM identity.status_consumers WHERE tenant_id=$1 AND cascade_id=$2 ORDER BY ordinal`, string(r.Binding.TenantID), string(r.Revocation.CascadeID))
		if e != nil {
			t.Fatal(e)
		}
		defer rows.Close()
		i := 0
		for rows.Next() {
			var ordinal int
			var id, state string
			var version int64
			var fingerprint []byte
			if e := rows.Scan(&ordinal, &id, &version, &fingerprint, &state); e != nil || i >= len(expected) || ordinal != i || id != expected[i] || version != 1 || state != "pending" || !reflect.DeepEqual(fingerprint, append([]byte{1}, make([]byte, 31)...)) {
				t.Fatal("wrong immutable consumer binding", e)
			}
			i++
		}
		if rows.Err() != nil || i != len(expected) {
			t.Fatal("incomplete consumer snapshot")
		}
		var auditID string
		if e := pool.Raw().QueryRow(ctx, `SELECT event_id FROM public.identity_test_audits WHERE command_id=$1`, string(r.Binding.CommandID)).Scan(&auditID); e != nil || auditID != r.AuditEventID {
			t.Fatal("success audit absent or changed", e)
		}
	}
	assertConsumers(first, []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "oauth-server/device", "oauth-server/oidc", "authorization", "authorization/valkey", "identity/risk", "audit"})
	var cascades, consumers, effects int
	if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.status_cascades WHERE command_id=$1),(SELECT count(*) FROM identity.status_consumers WHERE cascade_id=$2),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(first.Binding.CommandID), string(first.Revocation.CascadeID)).Scan(&cascades, &consumers, &effects); e != nil || cascades != 1 || consumers != 12 || effects != 1 {
		t.Fatal("cascade not atomically persisted", e)
	}
	wrong, e := owner.Execute(ctx, command("identity.admin.user-unban", 8, 2))
	if e != nil || wrong.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("unban restored suspension", wrong, e)
	}
	read("status", 8, 2, identity.StatusSuspended)
	restored, e := owner.Execute(ctx, command("identity.user.restore", 8, 2))
	if e != nil || restored.Outcome != identity.CommitOutcomeCommitted || len(restored.Revocation.Owners) != 9 {
		t.Fatal("restore admission failed", e)
	}
	read("status", 9, 3, identity.StatusActive)
	assertConsumers(restored, []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "authorization", "authorization/valkey", "audit"})
	for _, versions := range [][2]uint64{{9, 2}, {8, 3}} {
		cmd := command("identity.admin.user-ban", versions[0], versions[1])
		spec, _ := cmd.UserStatus()
		r, e := owner.Execute(ctx, cmd)
		if e != nil || r.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("independent version fence omitted", e)
		}
		read("status", 9, 3, identity.StatusActive)
		assertEffects(spec.Binding.CommandID, 0, 0, 0)
	}
	for _, expiry := range []time.Time{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Hour)} {
		base := command("identity.user.suspend", 9, 3)
		spec, _ := base.UserStatus()
		spec.ExpiresAt = expiry
		cmd, e := identity.NewUserStatusCommand(spec)
		if e != nil {
			t.Fatal(e)
		}
		r, e := owner.Execute(ctx, cmd)
		if e != nil || r.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("invalid expiry admitted", e)
		}
		read("status", 9, 3, identity.StatusActive)
		assertEffects(spec.Binding.CommandID, 0, 0, 0)
	}
	t.Run("absolute expiry remains denied and preserves legal hold", func(t *testing.T) {
		if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,legal_hold,legal_hold_version) VALUES('status','expiry-user','active',1,true,7)`); e != nil {
			t.Fatal(e)
		}
		base := command("identity.user.suspend", 1, 1)
		spec, _ := base.UserStatus()
		spec.Binding.UserID = "expiry-user"
		var now time.Time
		if e := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			t.Fatal(e)
		}
		spec.ExpiresAt = now.UTC().Add(time.Hour)
		cmd, e := identity.NewUserStatusCommand(spec)
		if e != nil {
			t.Fatal(e)
		}
		r, e := owner.Execute(ctx, cmd)
		if e != nil || r.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("valid absolute expiry denied", e)
		}
		var expires time.Time
		var held bool
		var holdVersion string
		if e := pool.Raw().QueryRow(ctx, `SELECT u.status_expires_at,c.legal_hold,c.legal_hold_version::text FROM identity.users u JOIN identity.status_cascades c USING(tenant_id,user_id) WHERE c.command_id=$1`, string(spec.Binding.CommandID)).Scan(&expires, &held, &holdVersion); e != nil || !expires.Equal(spec.ExpiresAt) || !held || holdVersion != "7" {
			t.Fatal("expiry or hold snapshot changed", e)
		}
		// Model a historical expired restriction without a restore command.
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status_expires_at='2000-01-01+00' WHERE tenant_id='status' AND user_id='expiry-user'`); e != nil {
			t.Fatal(e)
		}
		current, e := repo.GetStatus(ctx, identity.UserStatusQuery{TenantID: "status", UserID: "expiry-user"})
		if e != nil || current.User.Status.AllowsAuthentication() || current.AuthorityVersion != 2 {
			t.Fatal("elapsed expiry restored authority", e)
		}
	})
	changedConfig := statusFixtureConfig()
	t.Run("expiry is rechecked after the user row lock", func(t *testing.T) {
		blocker, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		release := func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = blocker.Rollback(cleanup)
		}
		defer release()
		var locked string
		if e := blocker.QueryRow(ctx, `SELECT user_id FROM identity.users WHERE tenant_id='status' AND user_id='user' FOR UPDATE`).Scan(&locked); e != nil {
			t.Fatal(e)
		}
		var now time.Time
		if e := blocker.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			t.Fatal(e)
		}
		base := command("identity.user.suspend", 9, 3)
		spec, _ := base.UserStatus()
		spec.ExpiresAt = now.UTC().Add(500 * time.Millisecond)
		cmd, e := identity.NewUserStatusCommand(spec)
		if e != nil {
			t.Fatal(e)
		}
		type completion struct {
			result identity.CommandResult
			err    error
		}
		done := make(chan completion, 1)
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			r, e := owner.Execute(ctx, cmd)
			done <- completion{r, e}
		}()
		defer func() {
			release()
			select {
			case <-finished:
			case <-ctx.Done():
				t.Error("bounded status contender did not stop")
			}
		}()
		// Observe the actual row-lock wait before advancing database time; a
		// sleep alone could pass without exercising the stale pre-lock clock.
		wait, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		defer cancel()
		waiting := false
		for !waiting && wait.Err() == nil {
			if _, e := blocker.Exec(wait, `SELECT pg_stat_clear_snapshot()`); e != nil {
				t.Fatal(e)
			}
			if e := blocker.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT tenant_id,user_id,status,version::text,authority_version::text,%')`).Scan(&waiting); e != nil {
				t.Fatal(e)
			}
		}
		if !waiting {
			t.Fatal("status contender did not reach user lock")
		}
		if _, e := blocker.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.01)`, spec.ExpiresAt); e != nil {
			t.Fatal(e)
		}
		if e := blocker.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		select {
		case got := <-done:
			if got.err != nil || got.result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("elapsed lock-wait expiry admitted", got.err)
			}
		case <-ctx.Done():
			t.Fatal("status contender timed out")
		}
		read("status", 9, 3, identity.StatusActive)
		assertEffects(spec.Binding.CommandID, 0, 0, 0)
	})
	changedConfig.ConsumerContracts["identity/session"] = StatusConsumerContract{Version: 2, Fingerprint: [32]byte{2}}
	changedOwner, e := NewStatusUnitOfWork(coordinator, repo, changedConfig)
	if e != nil {
		t.Fatal(e)
	}
	conflicted, e := changedOwner.Execute(ctx, command("identity.admin.user-ban", 9, 3))
	if e != nil || conflicted.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("same-version contract changed policy", e)
	}
	read("status", 9, 3, identity.StatusActive)
	replay, e := owner.Execute(ctx, suspend)
	if e != nil || !reflect.DeepEqual(replay, first) {
		t.Fatal("replay changed original cascade", e)
	}
	mutated, e := changedOwner.Execute(ctx, suspend)
	if e != nil || !reflect.DeepEqual(mutated, first) {
		t.Fatal("new composition changed historical snapshot", e)
	}
	var fingerprint []byte
	if e := pool.Raw().QueryRow(ctx, `SELECT contract_fingerprint FROM identity.status_consumers WHERE cascade_id=$1 AND consumer_id='identity/session'`, string(first.Revocation.CascadeID)).Scan(&fingerprint); e != nil || !reflect.DeepEqual(fingerprint, append([]byte{1}, make([]byte, 31)...)) {
		t.Fatal("persisted snapshot changed", e)
	}
	q := creationRecoveryQuery(first.Binding)
	recovered, e := owner.Recover(ctx, q)
	if e != nil || !reflect.DeepEqual(recovered, first) {
		t.Fatal("lost response recovery changed original receipt", e)
	}
	t.Run("expired pending status requires retained negative evidence", func(t *testing.T) {
		auditing, lifecycle := &recoveryAuditPhase{}, &recoveryLifecyclePhase{}
		participants, e := NewContributorRegistry([]Contributor{repo, auditing, lifecycle})
		if e != nil {
			t.Fatal(e)
		}
		c, e := NewCoordinator(pool, participants, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
		if e != nil {
			t.Fatal(e)
		}
		recoveryOwner, e := NewStatusUnitOfWork(c, repo, statusFixtureConfig())
		if e != nil {
			t.Fatal(e)
		}
		for _, evidence := range []string{"absent", "present", "unavailable"} {
			t.Run(evidence, func(t *testing.T) {
				cmd := command("identity.user.suspend", 9, 3)
				spec, _ := cmd.UserStatus()
				b := spec.Binding
				record, e := kernelMutationAudit(ctx, b, 9, time.Now().UTC().Truncate(time.Microsecond), "committed")
				if e != nil {
					t.Fatal(e)
				}
				digest, e := AuditBindingDigest(b, record)
				if e != nil {
					t.Fatal(e)
				}
				plan, e := c.PrepareCommandPlan(b, cmd, CommandPlan{Contributors: participants.Descriptors(), Audits: []AuditPlan{{EventType: kernelCommandAudit(b.OperationID), SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), BeforeVersion: 9, AfterVersion: 10}})
				if e != nil {
					t.Fatal(e)
				}
				_, pending, e := c.ReserveCommand(ctx, b, cmd, plan)
				if e != nil || pending.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("status reservation failed", e)
				}
				key, e := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if e != nil {
					t.Fatal(e)
				}
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); e != nil {
					t.Fatal(e)
				}
				if evidence == "present" {
					// Model retained effects beside an inconsistent pending journal;
					// recovery must not infer success from either the user or cascade.
					cascade, e := identity.NewCommandID()
					if e != nil {
						t.Fatal(e)
					}
					if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.status_cascades SELECT $1,tenant_id,user_id,$2,$3,operation,generation,manifest_version,policy_version,authority_version,aggregate_version,trigger_event_id,trigger_event_type,trigger_schema_version,requested_at,deadline,legal_hold,legal_hold_version,state FROM identity.status_cascades WHERE command_id=$4`, string(cascade), string(b.CommandID), key, string(first.Binding.CommandID)); e != nil {
						t.Fatal(e)
					}
				}
				if evidence == "unavailable" {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE identity.status_cascades RENAME TO status_cascades_unavailable`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						cleanup, stop := context.WithTimeout(context.Background(), time.Second)
						defer stop()
						if _, e := pool.Raw().Exec(cleanup, `ALTER TABLE identity.status_cascades_unavailable RENAME TO status_cascades`); e != nil {
							t.Error("restore isolated fixture table", e)
						}
					}()
				}
				snapshot := func() string {
					t.Helper()
					var row string
					if e := pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1`, key).Scan(&row); e != nil {
						t.Fatal(e)
					}
					return row
				}
				before := snapshot()
				r, e := recoveryOwner.Recover(ctx, creationRecoveryQuery(b))
				if evidence == "absent" {
					if e != nil || r.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("negative evidence failed to close status", e)
					}
					assertEffects(b.CommandID, 0, 0, 0)
				} else if r.Outcome != identity.CommitOutcomeInProgress || snapshot() != before {
					t.Fatal("uncertain evidence changed historical ownership", e)
				}
				read("status", 9, 3, identity.StatusActive)
			})
		}
	})
	phase.fail = true
	failing := command("identity.admin.user-ban", 9, 3)
	failingSpec, _ := failing.UserStatus()
	failed, _ := owner.Execute(ctx, failing)
	phase.fail = false
	if failed.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("failed audit claimed commitment")
	}
	read("status", 9, 3, identity.StatusActive)
	assertEffects(failingSpec.Binding.CommandID, 0, 0, 0)
	var failedAudits int
	if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1`, string(failingSpec.Binding.CommandID)).Scan(&failedAudits); e != nil || failedAudits != 0 {
		t.Fatal("failed audit transaction leaked records", e)
	}
	var wg sync.WaitGroup
	results := make(chan identity.CommitOutcome, 2)
	for range 2 {
		cmd := command("identity.admin.user-ban", 9, 3)
		wg.Go(func() { r, _ := owner.Execute(ctx, cmd); results <- r.Outcome })
	}
	wg.Wait()
	close(results)
	wins := 0
	for r := range results {
		if r == identity.CommitOutcomeCommitted {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal("CAS did not select one winner", wins)
	}
	read("status", 10, 4, identity.StatusBanned)
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET version=$1::numeric,authority_version=$1::numeric WHERE tenant_id='status' AND user_id='user'`, strconv.FormatUint(math.MaxUint64-1, 10)); err != nil {
		t.Fatal(err)
	}
	max, e := owner.Execute(ctx, command("identity.admin.user-unban", math.MaxUint64-1, math.MaxUint64-1))
	if e != nil || max.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("full-width transition failed", e)
	}
	read("status", math.MaxUint64, math.MaxUint64, identity.StatusActive)
	read("status-other", 11, 1, identity.StatusBanned)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := repo.GetStatus(cancelled, identity.UserStatusQuery{TenantID: "status", UserID: "user"}); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored", e)
	}
}
