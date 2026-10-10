//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Bounded risk plan: real primary reservation/commit/replay; native schema
// mismatch before SQL; mutation+audit+outbox+receipt atomicity; phase failure,
// forged receipt, cancellation, ambiguous commit and lease loss; unanimous
// negative recovery and conflicting retained evidence. Typed SQL seams prove
// the coordinator, not a real session issuer or production adapter composition.
type featureExecutionPhase struct {
	anonymous                                       bool
	fail, wrongReceipt, panicApply, unknownRecovery bool
	panicValidate                                   bool
	calls                                           int
	admission                                       *CredentialAdmission
	selectedRecipient                               *RecipientRecord
	beforeAdmission                                 func(context.Context, Work) error
	ignoreAdmissionDenial                           bool
	afterAdmission                                  func(context.Context, Work) error
}

func (*featureExecutionPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session", Version: 1}
}
func (phase *featureExecutionPhase) FeatureOperations() []identity.FeatureOperation {
	operations := featureRegistryInput().operations
	if phase.anonymous {
		operations[0].SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return operations
}
func (phase *featureExecutionPhase) ValidateFeatureCommand(command identity.Command, p CommandPlan) error {
	if phase.panicValidate {
		panic("private validation diagnostic")
	}
	s, ok := command.Feature()
	if !ok || s.Operation != phase.FeatureOperations()[0] || len(s.Fields) != 1 || s.Fields[0].Name != "value" || s.Fields[0].Value.Kind != identity.FeatureText || s.Fields[0].Value.Text == "" || p.SubjectType != "session" || len(p.Audits) < 1 || len(p.Audits) > 2 || p.Audits[0].EventType != "session.issue" || p.Lifecycle == nil || p.Lifecycle.EventType != "session.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 1 {
		return invalidPlan()
	}
	if len(p.Audits) == 2 && (p.Audits[1].EventType != "session.authority" || p.Audits[1].RetentionClass != "protected") {
		return invalidPlan()
	}
	return nil
}

// This seam records every slot and selected retention class on the real primary;
// it does not replace the production audit adapter's interoperability gate.
type featureExecutionAuditPhase struct{ fail, anonymous bool }

func (*featureExecutionAuditPhase) Descriptor() ContributorDescriptor {
	return (&domainAuditPhase{}).Descriptor()
}
func (p *featureExecutionAuditPhase) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Feature != (&featureExecutionPhase{anonymous: p.anonymous}).FeatureOperations()[0] || record.SubjectType != "session" {
			return identity.InvalidInputError{Field: "staged_feature_scope"}
		}
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_feature_audits(event_id,command_id,event_index,retention_class) VALUES($1,$2,$3,$4)`, record.Record.ID(), string(w.state.binding.CommandID), int64(record.Plan.EventIndex), record.Record.Attributes()["retention.class"]); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*featureExecutionAuditPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, err := w.AuditPlans(); err != nil {
		return RecoveryUnknown, err
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_feature_audits")
}
func (p *featureExecutionPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.calls++
	if p.admission != nil {
		if p.beforeAdmission != nil {
			if err := p.beforeAdmission(ctx, w); err != nil {
				return identity.FeatureReceipt{}, err
			}
		}
		var admissionErr error
		originalBinding := w.state.binding
		originalDeadline, originalBounded := w.state.ctx.Deadline()
		if p.selectedRecipient != nil {
			reader, ok := any(w).(interface {
				RequireRecipientCredential(context.Context, FeatureExecutionContributor, RecipientRecord, CredentialAdmission) (time.Time, error)
			})
			if !ok {
				return identity.FeatureReceipt{}, invalidWork()
			}
			_, admissionErr = reader.RequireRecipientCredential(ctx, p, *p.selectedRecipient, *p.admission)
		} else {
			_, admissionErr = w.RequireActiveCredential(ctx, p, *p.admission)
		}
		deadline, bounded := w.state.ctx.Deadline()
		if w.state.binding != originalBinding || deadline != originalDeadline || bounded != originalBounded {
			return identity.FeatureReceipt{}, invalidWork()
		}
		if err := admissionErr; err != nil {
			if p.ignoreAdmissionDenial {
				return identity.FeatureReceipt{}, nil
			}
			return identity.FeatureReceipt{}, err
		}
		if p.afterAdmission != nil {
			if err := p.afterAdmission(ctx, w); err != nil {
				return identity.FeatureReceipt{}, err
			}
		}
	}
	s, _ := command.Feature()
	n, err := w.Exec(ctx, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, string(s.Binding.TenantID), s.Binding.RecordID, string(s.Binding.CommandID), s.Fields[0].Value.Text)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.panicApply {
		panic("private native diagnostic")
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	result := identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}
	if p.wrongReceipt {
		result.BeforeVersion, result.AfterVersion = 1, 2
	}
	return result, nil
}
func (p *featureExecutionPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if p.unknownRecovery {
		return RecoveryUnknown, nil
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_feature")
}

func testFeatureExecution(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_feature_audits(event_id text PRIMARY KEY,command_id text NOT NULL,event_index integer NOT NULL,retention_class text NOT NULL,UNIQUE(command_id,event_index));CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE public.identity_test_feature(tenant_id text,record_id text,command_id text UNIQUE,value text,PRIMARY KEY(tenant_id,record_id));`); err != nil {
		t.Fatal(err)
	}
	phase := &featureExecutionPhase{}
	auditing, lifecycle := &featureExecutionAuditPhase{}, &recoveryLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, phase})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(t *testing.T) (identity.CommandBinding, identity.Command, CommandPlan) {
		t.Helper()
		s := featureCodecSpec()
		s.Operation = phase.FeatureOperations()[0]
		if phase.anonymous {
			s.Binding.UserID, s.Binding.AnonymousFlowID = "", "anonymous-flow"
		}
		s.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		s.Binding.RecordID = string(id)
		s.Fields = []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-private-value"}}}
		command := featureCodecCommand(t, s)
		_, _, base := featurePlanFixture(t)
		base.Contributors = registry.Descriptors()
		base.Audits[0].RetentionClass = "standard"
		base.SubjectType = "session"
		base.Feature = &FeatureRegistration{Contributor: phase.Descriptor(), Operation: s.Operation}
		seed, e := securityMutationAudit(ctx, s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
		if e != nil {
			t.Fatal(e)
		}
		base.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := c.PrepareCommandPlan(s.Binding, command, base)
		if e != nil {
			t.Fatal("feature preparation", e)
		}
		return s.Binding, command, plan
	}
	reserve := func(t *testing.T, b identity.CommandBinding, command identity.Command, p CommandPlan) Reservation {
		t.Helper()
		r, result, e := c.ReserveCommand(ctx, b, command, p)
		if e != nil || r.state == nil || result.Outcome != identity.CommitOutcomeInProgress || result.Validate() != nil {
			t.Fatal("feature reserve", e)
		}
		return r
	}
	counts := func(t *testing.T, b identity.CommandBinding, wantDomain, wantAudit, wantOutbox int) {
		t.Helper()
		var d, a, o int
		err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_feature WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_feature_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(b.CommandID)).Scan(&d, &a, &o)
		if err != nil || d != wantDomain || a != wantAudit || o != wantOutbox {
			t.Fatalf("feature atomic state %d/%d/%d: %v", d, a, o, err)
		}
	}
	t.Run("multiple audit slots and recovery", func(t *testing.T) {
		for _, recoverOnly := range []bool{false, true} {
			b, command, p := prepare(t)
			second := p.Audits[0]
			second.EventIndex++
			second.EventType, second.RetentionClass = "session.authority", "protected"
			p.Audits = append(p.Audits, second)
			p, e := c.PrepareCommandPlan(b, command, p)
			if e != nil {
				t.Fatal(e)
			}
			r := reserve(t, b, command, p)
			if recoverOnly {
				id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
					t.Fatal(e)
				}
				q, caller := queryInputs(b)
				record, e := c.RecoverCommand(ctx, q, caller)
				var unavailable identity.UnavailableError
				if !errors.As(e, &unavailable) || record.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("multi-slot recovery", e)
				}
				counts(t, b, 0, 2, 0)
			} else {
				w, e := c.Begin(ctx, r)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Abort(w, identity.UnavailableError{})
				result, e := c.ApplyFeature(ctx, w, command)
				if e != nil {
					t.Fatal(e)
				}
				result, e = c.Commit(w, result)
				if e != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("multi-slot commit", e)
				}
				counts(t, b, 1, 2, 1)
			}
			var standard, protected int
			if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE retention_class='standard'),count(*) FILTER(WHERE retention_class='protected') FROM public.identity_test_feature_audits WHERE command_id=$1`, string(b.CommandID)).Scan(&standard, &protected); e != nil || standard != 1 || protected != 1 {
				t.Fatal("selected retention not persisted", e)
			}
		}
	})
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit and exact replay", true: "anonymous commit and exact replay"}[anonymous], func(t *testing.T) {
			originalRegistry := c.registry
			phase.anonymous, auditing.anonymous = anonymous, anonymous
			defer func() { c.registry = originalRegistry; phase.anonymous, auditing.anonymous = false, false }()
			var e error
			c.registry, e = NewContributorRegistry([]Contributor{repo, auditing, lifecycle, phase})
			if e != nil {
				t.Fatal(e)
			}
			b, command, p := prepare(t)
			r := reserve(t, b, command, p)
			w, e := c.Begin(ctx, r)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Abort(w, identity.UnavailableError{})
			provisional, e := c.ApplyFeature(ctx, w, command)
			if e != nil {
				t.Fatal(e)
			}
			result, e := c.Commit(w, provisional)
			if e != nil || result.Validate() != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("feature commit", e)
			}
			counts(t, b, 1, 1, 1)
			before := phase.calls
			copy, replay, e := c.ReserveCommand(ctx, b, command, p)
			if e != nil || copy.state != nil || replay.AuditEventID != result.AuditEventID || replay.Feature == nil || *replay.Feature != *result.Feature || phase.calls != before {
				t.Fatal("feature replay reminted or changed receipt", e)
			}
			query, caller := queryInputs(b)
			observed, e := c.QueryCommand(ctx, query, caller)
			if e != nil || observed.Validate() != nil || observed.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("committed feature query", e)
			}
			full, e := c.RecoverFeatureCommand(ctx, query, caller)
			if e != nil || full.Binding != b || full.Feature == nil || *full.Feature != *result.Feature || full.AuditEventID != result.AuditEventID {
				t.Fatal("primary recovery lost original feature scope/receipt", e)
			}
			if anonymous {
				query.UserID, query.AnonymousFlowID = identity.UserID(b.AnonymousFlowID), ""
				wrong, e := c.RecoverFeatureCommand(ctx, query, callerForQuery(caller, query))
				var forbidden identity.ForbiddenError
				if !errors.As(e, &forbidden) || wrong.Binding.CommandID != "" || wrong.Feature != nil {
					t.Fatal("user namespace disclosed anonymous result", e)
				}
			}
		})
	}
	t.Run("validator panic before reservation", func(t *testing.T) {
		b, command, p := prepare(t)
		phase.panicValidate = true
		defer func() {
			phase.panicValidate = false
			if recover() != nil {
				t.Fatal("validator panic escaped before reservation")
			}
		}()
		if _, e := c.PrepareCommandPlan(b, command, p); e == nil {
			t.Fatal("panicking validator prepared")
		}
		if r, _, e := c.ReserveCommand(ctx, b, command, p); e == nil || r.state != nil {
			t.Fatal("panicking validator reserved")
		}
		counts(t, b, 0, 0, 0)
	})
	for _, mode := range []string{"native denial", "forged receipt", "phase panic", "validator panic", "audit failure", "outbox failure", "repeat apply", "changed command", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			b, command, p := prepare(t)
			r := reserve(t, b, command, p)
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			w, e := c.Begin(call, r)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Abort(w, identity.UnavailableError{})
			phase.fail, phase.wrongReceipt, phase.panicApply = mode == "native denial", mode == "forged receipt", mode == "phase panic"
			phase.panicValidate = mode == "validator panic"
			auditing.fail, lifecycle.fail = mode == "audit failure", mode == "outbox failure"
			defer func() {
				phase.panicValidate = false
				phase.fail, phase.wrongReceipt, phase.panicApply = false, false, false
				auditing.fail, lifecycle.fail = false, false
				if recover() != nil {
					t.Fatal("validator panic escaped open Work")
				}
			}()
			applying := command
			if mode == "changed command" {
				s, _ := command.Feature()
				s.Fields[0].Value.Text = "changed"
				applying = featureCodecCommand(t, s)
			}
			provisional, e := c.ApplyFeature(call, w, applying)
			if mode == "repeat apply" {
				_, e = c.ApplyFeature(call, w, command)
			}
			if mode == "cancelled" {
				cancel()
			}
			var result identity.CommandResult
			if e != nil {
				result, e = c.Abort(w, e)
			} else {
				result, e = c.Commit(w, provisional)
			}
			if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed feature committed")
			}
			wantAudit := 0
			if result.Outcome == identity.CommitOutcomeNotCommitted {
				wantAudit = 1
				if result.Validate() != nil {
					t.Fatal("invalid feature failure receipt")
				}
			}
			counts(t, b, 0, wantAudit, 0)
		})
	}
	t.Run("abandoned reservation recovery", func(t *testing.T) {
		b, command, p := prepare(t)
		_ = reserve(t, b, command, p)
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
			t.Fatal(e)
		}
		q, caller := queryInputs(b)
		record, e := c.RecoverCommand(ctx, q, caller)
		var unavailable identity.UnavailableError
		if !errors.As(e, &unavailable) || record.Outcome != identity.CommitOutcomeNotCommitted || record.Validate() != nil {
			t.Fatal("feature recovery", e)
		}
		counts(t, b, 0, 1, 0)
	})
	for _, unknown := range []bool{false, true} {
		t.Run("recovery veto", func(t *testing.T) {
			b, command, p := prepare(t)
			r := reserve(t, b, command, p)
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
				t.Fatal(e)
			}
			if !unknown {
				if _, e := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_feature(tenant_id,record_id,command_id,value) VALUES($1,$2,$3,'retained evidence')`, string(b.TenantID), b.RecordID, string(b.CommandID)); e != nil {
					t.Fatal(e)
				}
			}
			phase.unknownRecovery = unknown
			defer func() { phase.unknownRecovery = false }()
			q, caller := queryInputs(b)
			observed, e := c.RecoverCommand(ctx, q, caller)
			var unavailable identity.UnavailableError
			if !errors.As(e, &unavailable) || observed.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("inconclusive feature evidence terminalized", e)
			}
			if _, e := c.Begin(ctx, r); e == nil {
				t.Fatal("expired predecessor got Work")
			}
			var generation string
			if e := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&generation); e != nil || generation != "1" {
				t.Fatal("failed recovery persisted a takeover", e)
			}
		})
	}
	t.Run("commit ambiguity", func(t *testing.T) {
		b, command, p := prepare(t)
		r := reserve(t, b, command, p)
		if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.identity_test_feature_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='private deferred feature failure'; END $$;CREATE CONSTRAINT TRIGGER identity_test_feature_commit AFTER INSERT ON public.identity_test_feature DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.identity_test_feature_commit();`); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER identity_test_feature_commit ON public.identity_test_feature;DROP FUNCTION public.identity_test_feature_commit();`); e != nil {
				t.Error(e)
			}
		}()
		w, e := c.Begin(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Abort(w, identity.UnavailableError{})
		provisional, e := c.ApplyFeature(ctx, w, command)
		if e != nil {
			t.Fatal(e)
		}
		result, e := c.Commit(w, provisional)
		if e == nil || result.Outcome != identity.CommitOutcomeUnknown || result.Validate() != nil {
			t.Fatal("ambiguous commit fabricated rollback/success", e)
		}
		counts(t, b, 0, 0, 0)
		q, caller := queryInputs(b)
		record, e := c.QueryCommand(ctx, q, caller)
		if e != nil || record.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("ambiguous feature lost durable pending", e)
		}
	})
}
