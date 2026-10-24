//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// A trusted test participant exercises the kernel's transaction/identity seam,
// not production OTP encryption or session admission interoperability.
type preparedFeaturePhase struct {
	owner           FeaturePreparationContributor
	generated       atomic.Int64
	restored        atomic.Int64
	deny, fail      bool
	declaration     CommandPlan
	beforeGenerate  func(context.Context, identity.Command, uint64) error
	afterApply      func()
	requestOriginal identity.CommandBinding
}

func (p *preparedFeaturePhase) preparationOwner() FeaturePreparationContributor {
	if p.owner != nil {
		return p.owner
	}
	return p
}

func (*preparedFeaturePhase) Descriptor() ContributorDescriptor {
	return (&featureExecutionPhase{}).Descriptor()
}
func (*preparedFeaturePhase) FeatureOperations() []identity.FeatureOperation {
	return (&featureExecutionPhase{}).FeatureOperations()
}
func (*preparedFeaturePhase) ValidateFeatureCommand(c identity.Command, p CommandPlan) error {
	return (&featureExecutionPhase{}).ValidateFeatureCommand(c, p)
}
func (*preparedFeaturePhase) ValidateFeaturePreparation(c identity.Command, p CommandPlan) error {
	return (&featureExecutionPhase{}).ValidateFeatureCommand(c, p)
}
func (p *preparedFeaturePhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	if wire, generation, err := w.FeaturePreparationOutput(p.preparationOwner()); err == nil || wire != nil || generation != 0 {
		return invalidWork()
	}
	s, _ := c.Feature()
	b, _, _, err := w.FeatureScope(p.preparationOwner())
	if err != nil || b != s.Binding {
		return invalidWork()
	}
	if p.deny {
		return identity.ForbiddenError{}
	}
	_, err = w.DatabaseTime(ctx)
	return err
}
func (p *preparedFeaturePhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.generated.Add(1)
	if p.beforeGenerate != nil {
		if err := p.beforeGenerate(ctx, c, generation); err != nil {
			return nil, err
		}
	}
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		return nil, err
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	wire := append(binary.BigEndian.AppendUint64(nil, generation), fp[:]...)
	return append(wire, make([]byte, 17000-len(wire))...), nil
}
func (p *preparedFeaturePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	p.restored.Add(1)
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	if len(wire) != 17000 || binary.BigEndian.Uint64(wire[:8]) != generation || !bytes.Equal(wire[8:40], fp[:]) || !bytes.Equal(wire[40:], make([]byte, 16960)) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	s, _ := c.Feature()
	s.Fields[0].Value.Text = "original-generated-output"
	command, err := identity.NewFeatureCommand(s)
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	final := p.declaration
	final.Audits = append([]AuditPlan(nil), final.Audits...)
	seed, err := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", final.Audits[0].EventType, final.SubjectType, s.Binding.RecordID, final.Audits[0].RetentionClass, true)
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	final.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, final.SubjectType, seed)
	return command, final, err
}
func (p *preparedFeaturePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, _, _, err := w.FeatureScope(p.preparationOwner()); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	if s.Fields[0].Value.Text != "original-generated-output" {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	// Reconstruct only this test participant's original public intent. Production
	// OTP restores its existing authenticated envelope instead of retaining a
	// request-specific participant or embedding ciphertext in bounded fields.
	original := s
	original.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-intent"}}}
	originalCommand, err := identity.NewFeatureCommand(original)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	q, err := prepareClaim(originalCommand, [32]byte{1})
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	wire, generation, err := w.FeaturePreparationOutput(p.preparationOwner())
	if err != nil || len(wire) != 17000 || generation == 0 || binary.BigEndian.Uint64(wire[:8]) != generation || !bytes.Equal(wire[8:40], fp[:]) || !bytes.Equal(wire[40:], make([]byte, 16960)) {
		return identity.FeatureReceipt{}, invalidPreparation()
	}
	wire[0] ^= 1
	fresh, provenance, err := w.FeaturePreparationOutput(p.preparationOwner())
	if err != nil || provenance != generation || binary.BigEndian.Uint64(fresh[:8]) != generation || !bytes.Equal(fresh[8:40], fp[:]) || !bytes.Equal(fresh[40:], make([]byte, 16960)) {
		return identity.FeatureReceipt{}, invalidPreparation()
	}
	if leaked, provenance, err := w.FeaturePreparationOutput(&preparedFeaturePhase{}); err == nil || leaked != nil || provenance != 0 {
		return identity.FeatureReceipt{}, invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,$4)`, string(s.Binding.TenantID), s.Binding.RecordID, string(s.Binding.CommandID), s.Fields[0].Value.Text)
	if p.afterApply != nil {
		p.afterApply()
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, err
}
func (p *preparedFeaturePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, _, _, err := w.FeatureScope(p.preparationOwner()); err != nil {
		return RecoveryUnknown, err
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_feature")
}

func testPreparedFeature(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_feature_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index));CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE IF NOT EXISTS public.identity_test_feature(tenant_id text,record_id text,command_id text UNIQUE,value text,PRIMARY KEY(tenant_id,record_id));`); err != nil {
		t.Fatal(err)
	}
	newCase := func(t *testing.T, wrap ...func(*preparedFeaturePhase) FeaturePreparationContributor) (*Coordinator, *preparedFeaturePhase, identity.Command, CommandPlan) {
		t.Helper()
		phase := &preparedFeaturePhase{}
		var registered FeaturePreparationContributor = phase
		if len(wrap) != 0 {
			registered = wrap[0](phase)
			phase.owner = registered
		}
		registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, registered})
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
		if err != nil {
			t.Fatal(err)
		}
		s := featureCodecSpec()
		s.Operation = phase.FeatureOperations()[0]
		s.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.RecordID = string(id)
		s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-intent"}}}
		command := featureCodecCommand(t, s)
		_, _, p := featurePlanFixture(t)
		p.Contributors = registry.Descriptors()
		p.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: s.Operation}
		p.SubjectType = "session"
		p.Audits[0].RetentionClass = "standard"
		seed, err := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
		if err != nil {
			t.Fatal(err)
		}
		p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
		if err != nil {
			t.Fatal(err)
		}
		phase.declaration = p
		return c, phase, command, p
	}
	expire := func(command identity.Command) {
		s, _ := command.Feature()
		id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("original custody query", func(t *testing.T) {
		c, phase, command, plan := newCase(t)
		testPreparedFeatureQuery(t, ctx, c, phase, command, plan)
	})
	// Upgrade populated profile-1 history; admission must not reinterpret it.
	legacyCoordinator, legacyPhase, legacyCommand, legacyPlan := newCase(t)
	legacyResult, err := legacyCoordinator.ExecutePreparedFeature(ctx, legacyCommand, legacyPlan)
	if err != nil || legacyResult.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("legacy preparation", err)
	}
	if _, err := pool.Raw().Exec(ctx, admissionPreparationSchemaSQL); err != nil {
		t.Fatal("admission upgrade", err)
	}
	legacyReplay, err := legacyCoordinator.ExecutePreparedFeature(ctx, legacyCommand, legacyPlan)
	if err != nil || legacyReplay.Outcome != identity.CommitOutcomeCommitted || legacyPhase.generated.Load() != 1 {
		t.Fatal("upgrade rewrote legacy preparation", err)
	}
	newGatedCase := func(t *testing.T) (*Coordinator, *preparedFeaturePhase, identity.Command, CommandPlan, *gatedPreparedFeaturePhase) {
		var gated *gatedPreparedFeaturePhase
		c, p, command, plan := newCase(t, func(p *preparedFeaturePhase) FeaturePreparationContributor {
			gated = &gatedPreparedFeaturePhase{preparedFeaturePhase: p}
			return gated
		})
		gated.prepare = func(_ context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			return &testPreparationAdmission{phase: p, original: original}, nil
		}
		gated.restore = func(_ context.Context, original identity.Command, _ uint64, _ []byte) (FeaturePreparationAdmission, error) {
			return &testPreparationAdmission{phase: p, original: original}, nil
		}
		return c, p, command, plan, gated
	}
	t.Run("external failure never marks generation", func(t *testing.T) {
		for _, kind := range []string{"deny", "unavailable", "nil", "panic", "canceled", "deadline"} {
			t.Run(kind, func(t *testing.T) {
				c, p, command, plan, g := newGatedCase(t)
				call, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				if kind == "deadline" {
					cancel()
					call, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
					defer cancel()
				}
				g.prepare = func(ctx context.Context, _ identity.Command) (FeaturePreparationAdmission, error) {
					switch kind {
					case "deny":
						return nil, identity.ForbiddenError{}
					case "unavailable":
						return nil, errors.New("private external diagnostic")
					case "nil":
						return nil, nil
					case "panic":
						panic("private external diagnostic")
					case "canceled":
						cancel()
						return nil, ctx.Err()
					default:
						<-ctx.Done()
						return nil, ctx.Err()
					}
				}
				_, err := c.ExecutePreparedFeature(call, command, plan)
				if err == nil || strings.Contains(err.Error(), "private") || p.generated.Load() != 0 {
					t.Fatal("failed external admission generated or disclosed", err)
				}
				if kind == "canceled" && !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation attribution lost", err)
				}
				if kind == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("deadline attribution lost", err)
				}
				spec, _ := command.Feature()
				id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
				var marked *string
				if err := pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&marked); err != nil || marked != nil {
					t.Fatal("failed external admission retained a start marker", err)
				}
			})
		}
	})
	t.Run("gated lost start acknowledgement stays unresolved", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		commits := 0
		c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
			commits++
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			if commits == 2 {
				return identity.UnavailableError{}
			}
			return nil
		}
		_, err := c.ExecutePreparedFeature(ctx, command, plan)
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || p.generated.Load() != 0 {
			t.Fatal("unacknowledged gated start generated", err)
		}
		c.preparationCommit = nil
		expire(command)
		g.prepare = func(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
			t.Fatal("uncertain start assessed again")
			return nil, identity.UnavailableError{}
		}
		result, err := c.ExecutePreparedFeature(ctx, command, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress || p.generated.Load() != 0 {
			t.Fatal("uncertain start resumed generation", err)
		}
	})
	t.Run("retained admitted output cannot downgrade", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		commits := 0
		c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
			commits++
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			if commits == 3 {
				return identity.UnavailableError{}
			}
			return nil
		}
		_, err := c.ExecutePreparedFeature(ctx, command, plan)
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || p.generated.Load() != 1 {
			t.Fatal("retention failure fixture", err)
		}
		expire(command)
		fresh := *c
		fresh.preparationCommit = nil
		legacy := &preparedFeaturePhase{declaration: plan}
		registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, legacy})
		if err != nil {
			t.Fatal(err)
		}
		fresh.registry = registry
		_, err = fresh.ExecutePreparedFeature(ctx, command, plan)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || legacy.generated.Load() != 0 || legacy.restored.Load() != 0 {
			t.Fatal("admitted output silently downgraded", err)
		}
		fresh.registry = c.registry
		g.prepare = func(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
			t.Fatal("retained output assessed again")
			return nil, identity.UnavailableError{}
		}
		result, err := fresh.ExecutePreparedFeature(ctx, command, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || p.generated.Load() != 1 {
			t.Fatal("retained output did not restore without external IO", err)
		}
	})
	t.Run("expired admission rolls back generated effects", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		var expired atomic.Bool
		g.prepare = func(_ context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			return &testPreparationAdmission{phase: p, original: original, check: func(context.Context) error {
				if expired.Load() {
					return identity.ForbiddenError{}
				}
				return nil
			}}, nil
		}
		p.beforeGenerate = func(context.Context, identity.Command, uint64) error { expired.Store(true); return nil }
		result, err := c.ExecutePreparedFeature(ctx, command, plan)
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || result.Outcome != identity.CommitOutcomeNotCommitted || p.generated.Load() != 1 {
			t.Fatal("expired generated admission committed", result.Outcome, err)
		}
		spec, _ := command.Feature()
		var effects int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&effects); err != nil || effects != 0 {
			t.Fatal("expired admission left effects", err)
		}
	})
	t.Run("expiry after domain write rolls back before commit", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		var expired atomic.Bool
		g.prepare = func(_ context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			return &testPreparationAdmission{phase: p, original: original, check: func(context.Context) error {
				if expired.Load() {
					return identity.ForbiddenError{}
				}
				return nil
			}}, nil
		}
		p.afterApply = func() { expired.Store(true) }
		result, err := c.ExecutePreparedFeature(ctx, command, plan)
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || result.Outcome != identity.CommitOutcomeNotCommitted || p.generated.Load() != 1 {
			t.Fatal("expiry after domain write was committed", result.Outcome, err)
		}
		spec, _ := command.Feature()
		var effects, lifecycle int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(spec.Binding.CommandID)).Scan(&effects, &lifecycle); err != nil || effects != 0 || lifecycle != 0 {
			t.Fatal("expired admission retained atomic success effects", err)
		}
	})
	t.Run("expired lease during external work cannot mark", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		g.prepare = func(_ context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			expire(command)
			return &testPreparationAdmission{phase: p, original: original}, nil
		}
		_, err := c.ExecutePreparedFeature(ctx, command, plan)
		if err == nil || p.generated.Load() != 0 {
			t.Fatal("lost preparation lease generated", err)
		}
	})
	t.Run("expiry after start acknowledgement never generates", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		var expired atomic.Bool
		g.prepare = func(_ context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			return &testPreparationAdmission{phase: p, original: original, check: func(context.Context) error {
				if expired.Load() {
					return identity.ForbiddenError{}
				}
				return nil
			}}, nil
		}
		commits := 0
		c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
			commits++
			err := tx.Commit(ctx)
			if commits == 2 {
				expired.Store(true)
			}
			return err
		}
		result, err := c.ExecutePreparedFeature(ctx, command, plan)
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || result.Outcome != identity.CommitOutcomeUnknown || p.generated.Load() != 0 {
			t.Fatal("late acknowledgement admitted expired generation", result.Outcome, err)
		}
	})
	t.Run("external admission excludes matching concurrent work", func(t *testing.T) {
		c, p, command, plan, g := newGatedCase(t)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		g.prepare = func(ctx context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			close(entered)
			select {
			case <-release:
				return &testPreparationAdmission{phase: p, original: original}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		type outcome struct {
			result identity.CommandResult
			err    error
		}
		finished := make(chan outcome, 1)
		var worker sync.WaitGroup
		worker.Add(1)
		defer func() { unblock(); worker.Wait() }()
		go func() {
			defer worker.Done()
			result, err := c.ExecutePreparedFeature(ctx, command, plan)
			finished <- outcome{result, err}
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("external admission did not start")
		}
		concurrent, err := c.ExecutePreparedFeature(ctx, command, plan)
		unblock()
		first := <-finished
		if err != nil || concurrent.Outcome != identity.CommitOutcomeInProgress || first.err != nil || first.result.Outcome != identity.CommitOutcomeCommitted || p.generated.Load() != 1 {
			t.Fatal("matching external admission duplicated work", err, first.err)
		}
	})
	t.Run("original admission expiry is rechecked after SQL wait", func(t *testing.T) {
		for _, instant := range []int64{9, 10, 11} {
			t.Run(strconv.FormatInt(instant, 10), func(t *testing.T) {
				c, p, command, plan, g := newGatedCase(t)
				connection, err := pgx.ConnectConfig(ctx, pool.Raw().Config().ConnConfig.Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close(ctx)
				blocker, err := connection.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(ctx)
				var clock atomic.Int64
				clock.Store(1)
				entered := make(chan struct{})
				g.prepare = func(ctx context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
					spec, _ := original.Feature()
					id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
					if _, err := blocker.Exec(ctx, `SELECT command_id FROM identity.commands WHERE command_id=$1 FOR UPDATE`, id); err != nil {
						return nil, err
					}
					close(entered)
					return &testPreparationAdmission{phase: p, original: original, check: func(context.Context) error {
						if clock.Load() >= 10 {
							return identity.ForbiddenError{}
						}
						return nil
					}}, nil
				}
				type outcome struct {
					result identity.CommandResult
					err    error
				}
				finished := make(chan outcome, 1)
				var worker sync.WaitGroup
				worker.Add(1)
				defer func() { blocker.Rollback(ctx); worker.Wait() }()
				go func() {
					defer worker.Done()
					result, err := c.ExecutePreparedFeature(ctx, command, plan)
					finished <- outcome{result, err}
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("admission never entered")
				}
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					var waiting bool
					if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%identity.commands%')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case <-ticker.C:
					case <-ctx.Done():
						t.Fatal("authoritative SQL wait not observed")
					}
				}
				clock.Store(instant)
				if err := blocker.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				got := <-finished
				if instant < 10 {
					if got.err != nil || got.result.Outcome != identity.CommitOutcomeCommitted || p.generated.Load() != 1 {
						t.Fatal("fresh admission rejected after wait", got.err)
					}
				} else {
					if got.err == nil || p.generated.Load() != 0 {
						t.Fatal("expired admission passed SQL wait", got.err)
					}
				}
			})
		}
	})
	t.Run("external admission closes SQL before generation", func(t *testing.T) {
		var assessed atomic.Int64
		var gated *gatedPreparedFeaturePhase
		c, phase, command, plan := newCase(t, func(p *preparedFeaturePhase) FeaturePreparationContributor {
			gated = &gatedPreparedFeaturePhase{preparedFeaturePhase: p}
			return gated
		})
		gated.prepare = func(ctx context.Context, original identity.Command) (FeaturePreparationAdmission, error) {
			assessed.Add(1)
			if _, bounded := ctx.Deadline(); !bounded {
				t.Fatal("unbounded external admission")
			}
			spec, _ := original.Feature()
			id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				return nil, err
			}
			defer tx.Rollback(ctx)
			var marked *string
			if err := tx.QueryRow(ctx, `SELECT preparation_started_generation::text FROM identity.commands WHERE command_id=$1 FOR UPDATE NOWAIT`, id).Scan(&marked); err != nil {
				return nil, err
			}
			if marked != nil {
				t.Fatal("external admission followed generation marker")
			}
			if _, err := tx.Exec(ctx, `SELECT command_id FROM identity.identity_command_id_claims WHERE command_id=$1 FOR UPDATE NOWAIT`, id); err != nil {
				return nil, err
			}
			return &testPreparationAdmission{phase: phase, original: original}, nil
		}
		result, err := c.ExecutePreparedFeature(ctx, command, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || assessed.Load() != 1 || phase.generated.Load() != 1 {
			t.Fatal("external admission absent or ran under SQL", result.Outcome, err)
		}
		gated.prepare = func(context.Context, identity.Command) (FeaturePreparationAdmission, error) {
			t.Fatal("terminal replay assessed again")
			return nil, identity.UnavailableError{}
		}
		replay, err := c.ExecutePreparedFeature(ctx, command, plan)
		if err != nil || replay.Outcome != result.Outcome || phase.generated.Load() != 1 {
			t.Fatal("terminal replay repeated work", err)
		}
	})
	t.Run("original intent commits generated effects and replays", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		s, _ := command.Feature()
		phase.beforeGenerate = func(ctx context.Context, command identity.Command, generation uint64) error {
			var marked bool
			id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
			if err := pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation=$2::numeric FROM identity.commands WHERE command_id=$1`, id, generation).Scan(&marked); err != nil {
				return err
			}
			if !marked {
				return identity.UnavailableError{}
			}
			return nil
		}
		result, err := c.ExecutePreparedFeature(ctx, command, p)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("prepared commit", result.Outcome, err)
		}
		q, _ := prepareClaim(command, [32]byte{1})
		fp := claimFingerprint([32]byte{1}, q.canonical)
		id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
		var retained []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT fingerprint FROM identity.identity_command_id_claims WHERE command_id=$1`, id).Scan(&retained); err != nil || !bytes.Equal(retained, fp[:]) {
			t.Fatal("original claim replaced", err)
		}
		var domain, audits, outbox int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1 AND value='original-generated-output'),(SELECT count(*) FROM public.identity_test_feature_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(s.Binding.CommandID)).Scan(&domain, &audits, &outbox); err != nil || domain != 1 || audits != 1 || outbox != 1 {
			t.Fatal("incomplete atomic effects", err, domain, audits, outbox)
		}
		replayed, err := c.ExecutePreparedFeature(ctx, command, p)
		if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || phase.generated.Load() != 1 || phase.restored.Load() != 1 {
			t.Fatal("terminal replay regenerated", err)
		}
		s.Fields[0].Value.Text = "changed-intent"
		changed := featureCodecCommand(t, s)
		_, err = c.ExecutePreparedFeature(ctx, changed, p)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatal("changed intent adopted output", err)
		}
	})
	t.Run("denial before generation", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		phase.deny = true
		_, err := c.ExecutePreparedFeature(ctx, command, p)
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || phase.generated.Load() != 0 {
			t.Fatal("denied preparation generated", err)
		}
		s, _ := command.Feature()
		id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, id).Scan(&count); err != nil || count != 0 {
			t.Fatal("denied preparation retained a journal", err)
		}
	})
	t.Run("matching concurrent request cannot generate", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		entered, release := make(chan struct{}), make(chan struct{})
		phase.beforeGenerate = func(ctx context.Context, _ identity.Command, _ uint64) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		type outcome struct {
			result identity.CommandResult
			err    error
		}
		finished := make(chan outcome, 1)
		go func() { result, err := c.ExecutePreparedFeature(ctx, command, p); finished <- outcome{result, err} }()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("generation owner did not start")
		}
		result, err := c.ExecutePreparedFeature(ctx, command, p)
		close(release)
		first := <-finished
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress || first.err != nil || first.result.Outcome != identity.CommitOutcomeCommitted || phase.generated.Load() != 1 {
			t.Fatal("concurrent request duplicated preparation", err, first.err)
		}
	})
	t.Run("one stable owner keeps independent concurrent outputs", func(t *testing.T) {
		c, phase, first, declaration := newCase(t)
		s, _ := first.Feature()
		s.Binding.CommandID, _ = identity.NewCommandID()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.RecordID = string(id)
		second := featureCodecCommand(t, s)
		secondDeclaration := declaration
		secondDeclaration.Audits = append([]AuditPlan(nil), declaration.Audits...)
		seed, err := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
		if err != nil {
			t.Fatal(err)
		}
		secondDeclaration.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
		if err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}, 2), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		phase.beforeGenerate = func(ctx context.Context, _ identity.Command, _ uint64) error {
			entered <- struct{}{}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		type outcome struct {
			result identity.CommandResult
			err    error
		}
		finished := make(chan outcome, 2)
		var workers sync.WaitGroup
		defer func() { unblock(); workers.Wait() }()
		for i, command := range []identity.Command{first, second} {
			plan := declaration
			if i == 1 {
				plan = secondDeclaration
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				result, err := c.ExecutePreparedFeature(ctx, command, plan)
				finished <- outcome{result, err}
			}()
		}
		for range 2 {
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("independent preparation never overlapped")
			}
		}
		unblock()
		for range 2 {
			result := <-finished
			if result.err != nil || result.result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("independent output failed its own invocation", result.err)
			}
		}
		for i, command := range []identity.Command{first, second} {
			spec, _ := command.Feature()
			plan := declaration
			if i == 1 {
				plan = secondDeclaration
			}
			result, err := c.ExecutePreparedFeature(ctx, command, plan)
			var effects int
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("independent terminal replay", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1 AND record_id=$2 AND value='original-generated-output'`, string(spec.Binding.CommandID), spec.Binding.RecordID).Scan(&effects); err != nil || effects != 1 {
				t.Fatal("invocation effects crossed", err)
			}
		}
		if phase.generated.Load() != 2 || phase.restored.Load() != 2 {
			t.Fatal("independent terminal replay regenerated")
		}
	})
	t.Run("changed final declaration cannot attach", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		changed := *p.Lifecycle
		changed.EventType = "session.changed.v1"
		phase.declaration.Lifecycle = &changed
		result, err := c.ExecutePreparedFeature(ctx, command, p)
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || result.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("changed final plan executed", err)
		}
		s, _ := command.Feature()
		id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
		var attached bool
		if err := pool.Raw().QueryRow(ctx, `SELECT command_plan IS NOT NULL FROM identity.commands WHERE command_id=$1`, id).Scan(&attached); err != nil || attached {
			t.Fatal("changed declaration was attached", err)
		}
		phase.declaration = p
		expire(command)
		result, err = c.ExecutePreparedFeature(ctx, command, p)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || phase.generated.Load() != 1 {
			t.Fatal("plan retry regenerated", err)
		}
	})
	t.Run("lost start acknowledgement never generates", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			return identity.UnavailableError{}
		}
		result, err := c.ExecutePreparedFeature(ctx, command, p)
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || result.Outcome != identity.CommitOutcomeUnknown || phase.generated.Load() != 0 {
			t.Fatal("lost start generated", err)
		}
		c.preparationCommit = nil
		expire(command)
		result, err = c.ExecutePreparedFeature(ctx, command, p)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress || phase.generated.Load() != 0 {
			t.Fatal("missing output regenerated", err)
		}
	})
	t.Run("lost retention acknowledgement restores original generation", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		commits := 0
		c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
			commits++
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			if commits == 2 {
				return identity.UnavailableError{}
			}
			return nil
		}
		_, err := c.ExecutePreparedFeature(ctx, command, p)
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || phase.generated.Load() != 1 {
			t.Fatal("retention ambiguity lost", err)
		}
		expire(command)
		fresh := *c
		fresh.preparationCommit = nil
		// Root claim keys can rotate independently of retained native custody.
		fresh.keys = claimKeys{current: 2, retained: map[uint32][32]byte{1: {1}, 2: {2}}}
		replacement := &preparedFeaturePhase{declaration: p}
		registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, replacement})
		if err != nil {
			t.Fatal(err)
		}
		fresh.registry = registry
		result, err := fresh.ExecutePreparedFeature(ctx, command, p)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || replacement.generated.Load() != 0 || replacement.restored.Load() != 1 {
			t.Fatal("restart remapped original output", err)
		}
	})
	t.Run("native failure rolls back generated effects", func(t *testing.T) {
		c, phase, command, p := newCase(t)
		phase.fail = true
		result, err := c.ExecutePreparedFeature(ctx, command, p)
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("failed apply outcome", result.Outcome, err)
		}
		s, _ := command.Feature()
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1`, string(s.Binding.CommandID)).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial generated effect", err)
		}
	})
}
