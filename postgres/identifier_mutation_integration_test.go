//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This package-private harness exercises production persistence and Work SQL,
// not public authorization or capability consumption. Begin remains closed.
func TestIdentifierMutationIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if admin.Close(c) != nil {
			t.Error("admin cleanup")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identifier_mutation_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(c, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = base.Up(ctx); err != nil {
		t.Fatal(err)
	}
	// Populated migration-9 state must remain usable by existing readers.
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1),('tenant-a','other','active',1),('tenant-b','user-a','active',1)`); err != nil {
		t.Fatal(err)
	}
	forward, err := migrations.NewRunner(IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = forward.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = forward.Up(ctx); err != nil {
		t.Fatal("migration replay", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(p *database.PoolConfig) error { p.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(c) != nil {
			t.Error("pool cleanup")
		}
	}()
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	policy := identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {1}}, reuseCooldown: time.Hour}
	var ownedWorks []Work
	var ownedTransactions []pgx.Tx
	defer func() {
		for _, w := range ownedWorks {
			invalidateWork(w)
		}
		for _, tx := range ownedTransactions {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_ = tx.Rollback(cleanup)
			stop()
		}
	}()
	read := func(t *testing.T, tenant, user string) identity.IdentifierState {
		t.Helper()
		s, e := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: identity.TenantID(tenant), UserID: identity.UserID(user), MaximumIdentifiers: 128})
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	command := func(t *testing.T, action identity.IdentifierAction, identifier, value string) identity.Command {
		t.Helper()
		state := read(t, "tenant-a", "user-a")
		return recordIdentifier(t, action, func(s *identity.IdentifierCommand) {
			s.Binding.TenantID = "tenant-a"
			s.Binding.UserID = "user-a"
			s.Binding.ActorID = "user-a"
			s.Change.TenantID = "tenant-a"
			s.Change.UserID = "user-a"
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.RecordID = identifier
			s.Change.ID = identity.IdentifierID(identifier)
			s.Change.ExpectedUserVersion = state.User.Version
			s.Change.ExpectedAuthorityVersion = state.AuthorityVersion
			if action == identity.IdentifierAttach || action == identity.IdentifierReplace {
				s.Change.CanonicalValue = value
				s.Change.DisplayValue = value
			}
			for i, record := range state.Identifiers {
				if record.ID == s.Change.ID {
					s.Change.ExpectedIdentifierVersion = record.Version
					s.Change.ExpectedVerificationVersion = state.Verifications[i].Version
				}
			}
		}, nil)
	}
	var admission *identifierAdmissionProbe
	prepare := func(t *testing.T, cmd identity.Command) (Work, pgx.Tx) {
		t.Helper()
		probe := &capabilityExecutionProbe{}
		c, _, plan := reservationPlanFixture(t, probe)
		entries := make([]Contributor, len(c.registry.state.entries))
		for i, e := range c.registry.state.entries {
			entries[i] = e.contributor
		}
		entries[0] = repo
		if admission != nil {
			entries = append(entries, admission)
			d := admission.Descriptor()
			plan.IdentifierAdmission = &d
		}
		registry, e := NewContributorRegistry(entries)
		if e != nil {
			t.Fatal(e)
		}
		c.registry = registry
		c.pool = pool
		spec, _ := cmd.ChangeIdentifier()
		payload := spec.Proof.Payload()
		plan.Capability.CapabilityID = payload.ID
		plan.Capability.ExpiresAt = payload.ExpiresAt
		plan.Capability.Purpose = capability.Purpose(spec.Binding.OperationID)
		plan.Capability.ProofFingerprint = spec.Proof.EnvelopeDigest()
		plan.Lifecycle.EventType = kernelLifecycleEvent(spec.Binding.OperationID)
		plan.Lifecycle.BeforeVersion = spec.Change.ExpectedIdentifierVersion
		plan.Lifecycle.AfterVersion = spec.Change.ExpectedIdentifierVersion + 1
		wirePlan, e := decodeKernelPlan(spec.Binding, [32]byte{1}, queryFrozenPlan(t, spec.Binding))
		if e != nil {
			t.Fatal(e)
		}
		plan.Audits = wirePlan.Audits
		prepared, e := c.PrepareCommandPlan(spec.Binding, cmd, plan)
		if e != nil {
			t.Fatal("prepare", e)
		}
		q, _, admitted, e := c.prepare(spec.Binding, cmd, prepared)
		if e != nil {
			t.Fatal(e)
		}
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		ownedTransactions = append(ownedTransactions, tx)
		t.Cleanup(func() {
			c, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = tx.Rollback(c)
		})
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		w := Work{state: &workState{tx: tx, ctx: bounded, cancel: stop, binding: spec.Binding, generation: 1, registry: c.registry.state}}
		w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, request: q}}
		ownedWorks = append(ownedWorks, w)
		t.Cleanup(func() { invalidateWork(w) })
		return w, tx
	}
	open := func(t *testing.T, cmd identity.Command) (Work, pgx.Tx) {
		t.Helper()
		w, tx := prepare(t, cmd)
		if e := configureKernelWork(w.state.ctx, w); e != nil {
			t.Fatal(e)
		}
		return w, tx
	}
	apply := func(t *testing.T, cmd identity.Command) identity.IdentifierMutation {
		t.Helper()
		w, tx := open(t, cmd)
		result, e := repo.applyIdentifierMutation(ctx, w, cmd, policy)
		if e != nil {
			t.Fatal("apply", e)
		}
		var consumed bool
		for _, entry := range w.state.execution.reservation.plan.contributors {
			if p, ok := entry.contributor.(*capabilityExecutionProbe); ok {
				consumed = p.apply.state != nil
			}
		}
		if !consumed {
			t.Fatal("identifier write omitted provisional proof consumption")
		}
		invalidateWork(w)
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		return result
	}
	deny := func(t *testing.T, cmd identity.Command, expected any, selected identifierMutationPolicy) {
		t.Helper()
		before := read(t, "tenant-a", "user-a")
		w, tx := open(t, cmd)
		_, err := repo.applyIdentifierMutation(ctx, w, cmd, selected)
		if err == nil || w.usable() == nil {
			t.Fatal("denial did not poison", err)
		}
		if expected != nil && !errors.As(err, expected) {
			t.Fatalf("denial classification %T", err)
		}
		invalidateWork(w)
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		after := read(t, "tenant-a", "user-a")
		if after.User != before.User || after.AuthorityVersion != before.AuthorityVersion || len(after.Identifiers) != len(before.Identifiers) {
			t.Fatal("denial left prefix")
		}
	}
	t.Run("admission brackets mutation and denial rolls back", func(t *testing.T) {
		defer func() { admission = nil }()
		for _, denial := range []string{"initial", "final", "none"} {
			t.Run(denial, func(t *testing.T) {
				before := read(t, "tenant-a", "user-a")
				cmd := command(t, identity.IdentifierAttach, "admission-"+denial, denial+"@example.test")
				initial, final := false, false
				admission = &identifierAdmissionProbe{}
				admission.inspect = func(h IdentifierAdmissionWork) error {
					spec, terminal, err := h.Command(admission)
					if err != nil {
						return err
					}
					version, err := h.IdentifierAuthorityVersion(admission)
					if err != nil {
						return err
					}
					if terminal {
						final = true
						if !initial || version != before.AuthorityVersion+1 {
							t.Fatal("final did not own successor")
						}
					} else {
						initial = true
						if version != before.AuthorityVersion || h.state.work.state.identifier != nil {
							t.Fatal("initial ran after mutation")
						}
					}
					rows, err := h.Query(ctx, `SELECT identifier_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(spec.Binding.TenantID), string(spec.Binding.UserID))
					if err != nil {
						return err
					}
					var stored string
					if !rows.Next() || rows.Scan(&stored) != nil {
						rows.Close()
						t.Fatal("missing primary epoch")
					}
					rows.Close()
					if stored != fmt.Sprint(version) {
						t.Fatal("epoch not persisted in borrowed transaction")
					}
					if denial == "initial" && !terminal || denial == "final" && terminal {
						return identity.ForbiddenError{}
					}
					return nil
				}
				w, tx := open(t, cmd)
				_, err := repo.applyIdentifierMutation(ctx, w, cmd, policy)
				if denial == "initial" {
					if err == nil || w.usable() == nil || !initial || final || w.state.identifier != nil {
						t.Fatal("initial denial bypassed")
					}
					for _, e := range w.state.execution.reservation.plan.contributors {
						if p, ok := e.contributor.(*capabilityExecutionProbe); ok && p.apply.state != nil {
							t.Fatal("denied initial consumed proof")
						}
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					err = w.state.execution.coordinator.finalizeIdentifierCapability(w)
					if !initial || !final {
						t.Fatal("pipeline omitted admission")
					}
					if denial == "final" {
						if err == nil || w.usable() == nil || w.state.identifier.proofFinalized {
							t.Fatal("final denial bypassed")
						}
						for _, e := range w.state.execution.reservation.plan.contributors {
							if p, ok := e.contributor.(*capabilityExecutionProbe); ok && p.finalize.state != nil {
								t.Fatal("denied final finalized proof")
							}
						}
					} else if err != nil || !w.state.identifier.proofFinalized {
						t.Fatal("successful finalization denied", err)
					}
				}
				invalidateWork(w)
				if tx.Rollback(ctx) != nil {
					t.Fatal("rollback")
				}
				after := read(t, "tenant-a", "user-a")
				if after.User != before.User || after.AuthorityVersion != before.AuthorityVersion || len(after.Identifiers) != len(before.Identifiers) {
					t.Fatal("admission left durable prefix")
				}
			})
		}
	})
	t.Run("proof phase failure preserves identifier state", func(t *testing.T) {
		for _, panics := range []bool{false, true} {
			cmd := command(t, identity.IdentifierAttach, "proof-failure", "proof-failure@example.test")
			before := read(t, "tenant-a", "user-a")
			w, tx := open(t, cmd)
			for _, entry := range w.state.execution.reservation.plan.contributors {
				if p, ok := entry.contributor.(*capabilityExecutionProbe); ok {
					p.failure = identity.ConflictError{}
					p.panicPhase = panics
				}
			}
			if _, err := repo.applyIdentifierMutation(ctx, w, cmd, policy); err == nil || w.usable() == nil || w.state.identifier != nil {
				t.Fatal("proof failure accepted", err)
			}
			invalidateWork(w)
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			after := read(t, "tenant-a", "user-a")
			if before.User != after.User || before.AuthorityVersion != after.AuthorityVersion || len(before.Identifiers) != len(after.Identifiers) {
				t.Fatal("proof failure left mutation prefix")
			}
		}
	})
	t.Run("native email removal storage", func(t *testing.T) {
		history := IdentifierRemovalCascadeMigrationSource{Base: StatusMigrationSource{Base: IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
		runner, err := migrations.NewRunner(history, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("forward identifier cascade migration", err)
		}
		testNativeEmailRemovalStorage(t, ctx, pool, repo, policy)
	})
	t.Run("all transitions and preserved verification", func(t *testing.T) {
		apply(t, command(t, identity.IdentifierAttach, "a", "first@example.test"))
		state := read(t, "tenant-a", "user-a")
		if state.User.Version != 2 || state.AuthorityVersion != 2 || state.Identifiers[0].Version != 1 || state.Identifiers[0].Verified || state.Verifications[0].State != identity.VerificationPending {
			t.Fatal("attach mapping")
		}
		apply(t, command(t, identity.IdentifierVerify, "a", ""))
		state = read(t, "tenant-a", "user-a")
		at := state.Verifications[0].VerifiedAt
		if at.IsZero() || at.Nanosecond()%1000 != 0 || state.Identifiers[0].Version != 2 || state.Verifications[0].Version != 2 {
			t.Fatal("verify mapping")
		}
		apply(t, command(t, identity.IdentifierMakePrimary, "a", ""))
		apply(t, command(t, identity.IdentifierAttach, "b", "second@example.test"))
		apply(t, command(t, identity.IdentifierVerify, "b", ""))
		apply(t, command(t, identity.IdentifierMakePrimary, "b", ""))
		state = read(t, "tenant-a", "user-a")
		if state.Identifiers[0].Primary || !state.Identifiers[1].Primary || state.Identifiers[0].Version != 4 || !state.Verifications[0].VerifiedAt.Equal(at) || state.Verifications[0].Version != 2 {
			t.Fatal("primary switch renewed or failed demotion")
		}
		apply(t, command(t, identity.IdentifierReplace, "b", "replacement@example.test"))
		state = read(t, "tenant-a", "user-a")
		if state.Identifiers[1].Verified || state.Identifiers[1].Primary || state.Verifications[1].State != identity.VerificationPending || !state.Verifications[1].VerifiedAt.IsZero() {
			t.Fatal("replacement retained verification")
		}
		apply(t, command(t, identity.IdentifierVerify, "b", ""))
		apply(t, command(t, identity.IdentifierRemove, "b", ""))
		state = read(t, "tenant-a", "user-a")
		if len(state.Identifiers) != 1 || state.User.Version != 10 || state.AuthorityVersion != 10 {
			t.Fatal("remove/version mapping")
		}
		var retired int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifier_retirements WHERE tenant_id='tenant-a' AND identifier_id='b'`).Scan(&retired); err != nil || retired != 2 {
			t.Fatal("retirement history", err)
		}
	})
	t.Run("rollback and repeated apply", func(t *testing.T) {
		cmd := command(t, identity.IdentifierAttach, "rollback", "rollback@example.test")
		before := read(t, "tenant-a", "user-a")
		w, tx := open(t, cmd)
		if _, err := repo.applyIdentifierMutation(ctx, w, cmd, policy); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.applyIdentifierMutation(ctx, w, cmd, policy); err == nil || w.usable() == nil {
			t.Fatal("repeated apply allowed")
		}
		invalidateWork(w)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		after := read(t, "tenant-a", "user-a")
		if after.User != before.User || after.AuthorityVersion != before.AuthorityVersion || len(after.Identifiers) != len(before.Identifiers) {
			t.Fatal("rollback left prefix")
		}
	})
	t.Run("retired ID and value cannot resurrect", func(t *testing.T) {
		for _, cmd := range []identity.Command{command(t, identity.IdentifierAttach, "b", "new@example.test"), command(t, identity.IdentifierAttach, "new", "second@example.test")} {
			w, tx := open(t, cmd)
			var conflict identity.ConflictError
			if _, err := repo.applyIdentifierMutation(ctx, w, cmd, policy); !errors.As(err, &conflict) || w.usable() == nil {
				t.Fatal("retirement bypass", err)
			}
			invalidateWork(w)
			if tx.Rollback(ctx) != nil {
				t.Fatal("rollback")
			}
		}
	})
	t.Run("tenant canonical collision is conflict", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES('tenant-a','other','other-id','email','occupied@example.test',1,1,1)`); err != nil {
			t.Fatal(err)
		}
		var conflict identity.ConflictError
		deny(t, command(t, identity.IdentifierAttach, "collision", "occupied@example.test"), &conflict, policy)
		deny(t, command(t, identity.IdentifierAttach, "other-id", "distinct@example.test"), &conflict, policy)
	})
	t.Run("every optimistic fence denies stale state", func(t *testing.T) {
		base := command(t, identity.IdentifierRemove, "a", "")
		spec, _ := base.ChangeIdentifier()
		for _, alter := range []func(*identity.IdentifierCommand){func(s *identity.IdentifierCommand) { s.Change.ExpectedUserVersion-- }, func(s *identity.IdentifierCommand) { s.Change.ExpectedUserVersion++ }, func(s *identity.IdentifierCommand) { s.Change.ExpectedAuthorityVersion-- }, func(s *identity.IdentifierCommand) { s.Change.ExpectedIdentifierVersion-- }, func(s *identity.IdentifierCommand) { s.Change.ExpectedVerificationVersion-- }} {
			cmd := recordIdentifier(t, identity.IdentifierRemove, func(s *identity.IdentifierCommand) { *s = spec; s.Proof = capability.Grant{}; alter(s) }, nil)
			var conflict identity.ConflictError
			deny(t, cmd, &conflict, policy)
		}
	})
	t.Run("retained keys and exclusive cooldown", func(t *testing.T) {
		var until time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT reuse_until FROM identity.identifier_retirements WHERE tenant_id='tenant-a' AND identifier_id='b' AND removed=false`).Scan(&until); err != nil {
			t.Fatal(err)
		}
		cmd := command(t, identity.IdentifierAttach, "cooldown", "second@example.test")
		spec, _ := cmd.ChangeIdentifier()
		for _, at := range []time.Time{until.Add(-time.Microsecond), until, until.Add(time.Microsecond)} {
			w, tx := open(t, cmd)
			err := checkIdentifierReuse(ctx, w, spec.Change, policy, at)
			if (err != nil) != at.Before(until) {
				t.Fatal("exclusive cooldown boundary", err)
			}
			invalidateWork(w)
			if tx.Rollback(ctx) != nil {
				t.Fatal("rollback")
			}
		}
		rotated := identifierMutationPolicy{currentKeyVersion: 2, keys: map[uint32][32]byte{1: {1}, 2: {2}}, reuseCooldown: 0}
		var conflict identity.ConflictError
		deny(t, cmd, &conflict, rotated)
		missing := identifierMutationPolicy{currentKeyVersion: 2, keys: map[uint32][32]byte{2: {2}}, reuseCooldown: 0}
		var unavailable identity.UnavailableError
		deny(t, command(t, identity.IdentifierAttach, "missing-key", "fresh@example.test"), &unavailable, missing)
		var lastExpiry time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT max(reuse_until) FROM identity.identifier_retirements WHERE tenant_id='tenant-a'`).Scan(&lastExpiry); err != nil {
			t.Fatal(err)
		}
		w, tx := open(t, cmd)
		if err := checkIdentifierReuse(ctx, w, spec.Change, missing, lastExpiry); err != nil {
			t.Fatal("expired reuse evidence requires retired key", err)
		}
		invalidateWork(w)
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		var plaintext bool
		if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifier_retirements r WHERE row_to_json(r)::text LIKE '%second@example.test%' OR row_to_json(r)::text LIKE '%replacement@example.test%')`).Scan(&plaintext); err != nil || plaintext {
			t.Fatal("plaintext retirement", err)
		}
	})
	t.Run("retirement and mutation roll back together", func(t *testing.T) {
		cmd := command(t, identity.IdentifierReplace, "a", "rolled-back@example.test")
		before := read(t, "tenant-a", "user-a")
		w, tx := open(t, cmd)
		if _, err := repo.applyIdentifierMutation(ctx, w, cmd, policy); err != nil {
			t.Fatal(err)
		}
		invalidateWork(w)
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		after := read(t, "tenant-a", "user-a")
		if after.User != before.User || after.Identifiers[0] != before.Identifiers[0] || after.Verifications[0] != before.Verifications[0] {
			t.Fatal("retirement rollback changed active state")
		}
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifier_retirements WHERE tenant_id='tenant-a' AND identifier_id='a'`).Scan(&n); err != nil || n != 0 {
			t.Fatal("retirement prefix", err)
		}
	})
	t.Run("foreign owner and changed frozen input deny before mutation", func(t *testing.T) {
		cmd := command(t, identity.IdentifierAttach, "foreign", "foreign@example.test")
		w, tx := open(t, cmd)
		copyRepo := *repo
		if _, err := copyRepo.applyIdentifierMutation(ctx, w, cmd, policy); err == nil || w.usable() == nil {
			t.Fatal("foreign owner")
		}
		invalidateWork(w)
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
		w, tx = open(t, cmd)
		spec, _ := cmd.ChangeIdentifier()
		changed := recordIdentifier(t, identity.IdentifierAttach, func(s *identity.IdentifierCommand) {
			*s = spec
			s.Proof = capability.Grant{}
			s.Change.CanonicalValue = "substituted@example.test"
		}, nil)
		if _, err := repo.applyIdentifierMutation(ctx, w, changed, policy); err == nil || w.usable() == nil {
			t.Fatal("changed frozen intent")
		}
		invalidateWork(w)
		if tx.Rollback(ctx) != nil {
			t.Fatal("rollback")
		}
	})
	t.Run("complete partition capacity is not truncated", func(t *testing.T) {
		for _, count := range []int{128, 129} {
			cmd := command(t, identity.IdentifierAttach, "over-capacity", "capacity@example.test")
			w, tx := open(t, cmd)
			for i := 1; i < count; i++ {
				id := fmt.Sprintf("capacity-%03d", i)
				if _, err := tx.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES('tenant-a','user-a',$1,'email',$2,1,1,1)`, id, id+"@example.test"); err != nil {
					t.Fatal(err)
				}
			}
			_, err := repo.applyIdentifierMutation(ctx, w, cmd, policy)
			var conflict identity.ConflictError
			var unavailable identity.UnavailableError
			if (count == 128 && !errors.As(err, &conflict)) || (count == 129 && !errors.As(err, &unavailable)) || w.usable() == nil {
				t.Fatal("partition capacity bypass", count, err)
			}
			invalidateWork(w)
			if tx.Rollback(ctx) != nil {
				t.Fatal("rollback")
			}
		}
		if state := read(t, "tenant-a", "user-a"); len(state.Identifiers) != 1 || state.User.Version != 10 {
			t.Fatal("capacity denial left prefix")
		}
	})
	t.Run("tenant exclusion serializes different users before partition reads", func(t *testing.T) {
		cmd := command(t, identity.IdentifierAttach, "tenant-lock", "tenant-lock@example.test")
		first, firstTx := open(t, cmd)
		spec, _ := cmd.ChangeIdentifier()
		other := recordIdentifier(t, identity.IdentifierAttach, func(s *identity.IdentifierCommand) {
			*s = spec
			s.Proof = capability.Grant{}
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.UserID = "other"
			s.Binding.ActorID = "other"
			s.Change.UserID = "other"
			s.Change.ExpectedUserVersion = 1
			s.Change.ExpectedAuthorityVersion = 1
		}, nil)
		second, secondTx := prepare(t, other)
		call, stop := context.WithTimeout(ctx, 50*time.Millisecond)
		defer stop()
		if err := configureKernelWork(call, second); !errors.Is(err, context.DeadlineExceeded) || second.usable() == nil {
			t.Fatal("different-user tenant exclusion bypass", err)
		}
		invalidateWork(second)
		rollbackErr := secondTx.Rollback(ctx)
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && !secondTx.Conn().IsClosed() {
			t.Fatal("blocked transaction cleanup")
		}
		// After the original writer commits, the next admitted writer sees its
		// durable state rather than the previously observed absence.
		if _, err := repo.applyIdentifierMutation(ctx, first, cmd, policy); err != nil {
			t.Fatal(err)
		}
		invalidateWork(first)
		if firstTx.Commit(ctx) != nil {
			t.Fatal("first writer commit")
		}
		second, secondTx = open(t, other)
		var conflict identity.ConflictError
		if _, err := repo.applyIdentifierMutation(ctx, second, other, policy); !errors.As(err, &conflict) || second.usable() == nil {
			t.Fatal("serialized canonical collision classification", err)
		}
		invalidateWork(second)
		if secondTx.Rollback(ctx) != nil {
			t.Fatal("second writer rollback")
		}
		// Keep the shared fixture unchanged for remaining independent cases.
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity.identifiers WHERE tenant_id='tenant-a' AND identifier_id='tenant-lock'; UPDATE identity.users SET version=10,identifier_version=10 WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			t.Fatal("fixture reset")
		}
	})
	t.Run("caller deadline interrupts a contended user lock", func(t *testing.T) {
		cmd := command(t, identity.IdentifierAttach, "contended", "contended@example.test")
		w, tx := open(t, cmd)
		blocker, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = blocker.Rollback(cleanup)
		})
		if _, err := blocker.Exec(ctx, `SELECT user_id FROM identity.users WHERE tenant_id='tenant-a' AND user_id='user-a' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		call, stop := context.WithTimeout(ctx, 50*time.Millisecond)
		defer stop()
		_, err = repo.applyIdentifierMutation(call, w, cmd, policy)
		if !errors.Is(err, context.DeadlineExceeded) || w.usable() == nil || w.state.identifier != nil {
			t.Fatal("contended cancellation did not poison", err)
		}
		invalidateWork(w)
		// A cancelled PostgreSQL read may discard its connection; that is also
		// an authoritative rollback, not an owned transaction left running.
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && !tx.Conn().IsClosed() {
			t.Fatal("cancelled transaction cleanup")
		}
		if blocker.Rollback(ctx) != nil {
			t.Fatal("blocking transaction cleanup")
		}
		if state := read(t, "tenant-a", "user-a"); len(state.Identifiers) != 1 || state.User.Version != 10 {
			t.Fatal("cancelled mutation left prefix")
		}
	})
	t.Run("blocked and full-width aggregate cannot mutate", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			t.Fatal(err)
		}
		var forbidden identity.ForbiddenError
		deny(t, command(t, identity.IdentifierAttach, "banned", "blocked@example.test"), &forbidden, policy)
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',version=18446744073709551615 WHERE tenant_id='tenant-a' AND user_id='user-a'`); err != nil {
			t.Fatal(err)
		}
		cmd := recordIdentifier(t, identity.IdentifierAttach, func(s *identity.IdentifierCommand) {
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.TenantID = "tenant-a"
			s.Binding.UserID = "user-a"
			s.Binding.ActorID = "user-a"
			s.Change.TenantID = "tenant-a"
			s.Change.UserID = "user-a"
			s.Change.ExpectedUserVersion = math.MaxUint64 - 1
			s.Change.ExpectedAuthorityVersion = 10
		}, nil)
		var conflict identity.ConflictError
		deny(t, cmd, &conflict, policy)
	})
}
