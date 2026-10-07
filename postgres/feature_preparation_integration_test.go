//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
	generated      atomic.Int64
	restored       atomic.Int64
	deny, fail     bool
	declaration    CommandPlan
	beforeGenerate func(context.Context, identity.Command, uint64) error
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
	s, _ := c.Feature()
	b, _, _, err := w.FeatureScope(p)
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
	return append(binary.BigEndian.AppendUint64(nil, generation), fp[:]...), nil
}
func (p *preparedFeaturePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	p.restored.Add(1)
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	if len(wire) != 40 || binary.BigEndian.Uint64(wire[:8]) != generation || !bytes.Equal(wire[8:], fp[:]) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	s, _ := c.Feature()
	s.Fields[0].Value.Text = "original-generated-output"
	command, err := identity.NewFeatureCommand(s)
	return command, p.declaration, err
}
func (p *preparedFeaturePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	if s.Fields[0].Value.Text != "original-generated-output" {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,$4)`, string(s.Binding.TenantID), s.Binding.RecordID, string(s.Binding.CommandID), s.Fields[0].Value.Text)
	if p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, err
}
func (p *preparedFeaturePhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return RecoveryUnknown, err
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_feature")
}

func testPreparedFeature(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, preparationSchemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_feature_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index));CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE IF NOT EXISTS public.identity_test_feature(tenant_id text,record_id text,command_id text UNIQUE,value text,PRIMARY KEY(tenant_id,record_id));`); err != nil {
		t.Fatal(err)
	}
	newCase := func(t *testing.T) (*Coordinator, *preparedFeaturePhase, identity.Command, CommandPlan) {
		t.Helper()
		phase := &preparedFeaturePhase{}
		registry, err := NewContributorRegistry([]Contributor{repo, &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}, phase})
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
