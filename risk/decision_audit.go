package risk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-identity"
)

// ErrDecisionAuditUnavailable means required delivery was not acknowledged
// cleanly. It never exposes sink/observer diagnostics or grants permission.
var ErrDecisionAuditUnavailable = errors.New("risk: decision audit unavailable")

// DecisionAttribution is trusted server workflow input, not authentication.
// Tenant and policy version come from the owned evaluation; decision and clocks
// cannot be supplied here. Attempt subjects must match Context.Attempt exactly.
// User subjects must be authoritative internal IDs; when a user counter dimension
// exists it must match that same user. Caller must not mutate attribution while
// Evaluate is copying it. Delegation requires its original impersonation grant.
type DecisionAttribution struct {
	CommandID, CorrelationID, CausationID identity.CommandID
	Actor                                 audit.ActorInput
	Subject                               identity.SecuritySubject
	SubjectID, ImpersonationGrantID       string
}

// DecisionAuditConfig selects required non-issuing delivery. Nil configuration
// leaves the existing evaluator explicitly unaudited. Delivery uses the existing
// recorder; its Redactor must be nil so required profile fields cannot be removed.
// Timeout is explicit, 1ms..5s, and cannot exceed the evaluator's total budget.
// Recorder recovery, when selected, must fit Timeout. OnLoss is a required bounded
// operational handoff for alerting and command-keyed reconciliation; it must use
// platform-owned operational storage, not a replacement domain journal. A nil
// error from this callback does not prove durable reconciliation. The official
// durable recovery composition remains separate required implementation work.
// Callbacks and borrowed sink/buffer owners must honor context and be concurrency
// safe. No goroutines, retry loops, stores or transaction ownership are added.
type DecisionAuditConfig struct {
	PolicyID string
	Timeout  time.Duration
	Delivery audit.RecorderConfig
	OnLoss   func(context.Context, DecisionDelivery) error
}

// DecisionDelivery retains the original immutable canonical record and command
// for existing audit reconciliation. Rebuild/re-evaluate is not a safe retry:
// it changes event identity and may increment counters again. Zero is unobserved.
// Returned metadata is not authentication, state-commit or reconciliation proof.
type DecisionDelivery struct {
	record      audit.Record
	commandID   identity.CommandID
	outcome     audit.AppendOutcome
	disposition audit.DeliveryDisposition
}

// Record returns the immutable original record; zero means construction failed.
func (d DecisionDelivery) Record() audit.Record { return d.record }

// CommandID identifies the original operation, not a resubmission command.
func (d DecisionDelivery) CommandID() identity.CommandID { return d.commandID }

// Outcome retains commitment, rejection or ambiguity across delivery attempts.
// Unknown also describes zero/unobserved delivery; inspect Record before recovery.
func (d DecisionDelivery) Outcome() audit.AppendOutcome { return d.outcome }

// Disposition identifies actual recorder handling, not protected-operation success.
func (d DecisionDelivery) Disposition() audit.DeliveryDisposition { return d.disposition }

// Format omits record identifiers and correlated attribution.
func (DecisionDelivery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.DecisionDelivery(redacted)")
}

type decisionAuditState struct {
	config   DecisionAuditConfig
	builder  *identity.IdentitySecurityEventV1
	recorder *audit.Recorder
}
type decisionAuditClock func() time.Time

func (c decisionAuditClock) Now() time.Time { return c() }

func newDecisionAudit(c DecisionAuditConfig, p Policy, wall func() time.Time, total time.Duration) (*decisionAuditState, error) {
	if c.Timeout < time.Millisecond || c.Timeout > 5*time.Second || c.Timeout > total || c.OnLoss == nil || c.Delivery.Redactor != nil || c.Delivery.RecoveryTimeout > c.Timeout {
		return nil, ErrInvalidPolicy
	}
	// Validate policy attribution through its canonical owner, without calling
	// configured clocks, sources, sinks or loss observers during construction.
	t := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	validation, _ := identity.NewIdentitySecurityEventV1(decisionAuditClock(func() time.Time { return t }))
	_, err := validation.BuildRiskDecision(context.Background(), identity.RiskSecurityEventInput{Decision: identity.RiskSecurityAllow, OccurredAt: t, TenantID: "AAAAAAAAAAAAAAAAAAAAAQ", CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", CorrelationID: "AAAAAAAAAAAAAAAAAAAAAQ", Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: "AAAAAAAAAAAAAAAAAAAAAQ", PolicyID: c.PolicyID, PolicyVersion: p.state.version})
	if err != nil {
		return nil, ErrInvalidPolicy
	}
	builder, err := identity.NewIdentitySecurityEventV1(decisionAuditClock(wall))
	if err != nil {
		return nil, ErrInvalidPolicy
	}
	delivery := c.Delivery
	delivery.Redactor = decisionProfilePreserver{}
	delivery.Observer = decisionAuditObserver{next: delivery.Observer}
	recorder, err := audit.NewRecorder(delivery)
	if err != nil {
		return nil, ErrInvalidPolicy
	}
	return &decisionAuditState{config: c, builder: builder, recorder: recorder}, nil
}

func (s *decisionAuditState) input(r EvaluateRequest, now time.Time, version uint64, decision DecisionAction) identity.RiskSecurityEventInput {
	a := r.Attribution
	return identity.RiskSecurityEventInput{Decision: identity.RiskSecurityDecision(decision), OccurredAt: now.UTC(), TenantID: identity.TenantID(r.Context.Tenant), CommandID: a.CommandID, CorrelationID: a.CorrelationID, CausationID: a.CausationID, Actor: a.Actor, Subject: a.Subject, SubjectID: a.SubjectID, PolicyID: s.config.PolicyID, PolicyVersion: version, ImpersonationGrantID: a.ImpersonationGrantID}
}

func (s *decisionAuditState) prepare(ctx context.Context, r *EvaluateRequest, now time.Time, version uint64) error {
	if r.Attribution == nil {
		return ErrInvalidContext
	}
	a := *r.Attribution
	if a.Subject == identity.SecurityAuthenticationAttempt && a.SubjectID != r.Context.Attempt || a.Subject == identity.SecurityUser && r.Subject.User != "" && a.SubjectID != r.Subject.User {
		return ErrInvalidContext
	}
	_, err := s.builder.BuildRiskDecision(ctx, s.input(*r, now, version, Allow))
	if err != nil {
		return errors.Join(ErrInvalidContext, ctx.Err())
	}
	if a.Actor.DelegatedBy != nil {
		actor := *a.Actor.DelegatedBy
		a.Actor.DelegatedBy = &actor
	}
	r.Attribution = &a
	return nil
}

func (s *decisionAuditState) submit(ctx context.Context, r EvaluateRequest, now time.Time, v uint64, decision DecisionAction) (DecisionDelivery, error) {
	d := DecisionDelivery{commandID: r.Attribution.CommandID, outcome: audit.AppendUnknown}
	record, err := s.builder.BuildRiskDecision(ctx, s.input(r, now, v, decision))
	if err == nil {
		d.record = record
		bounded, cancel := context.WithTimeout(ctx, s.config.Timeout)
		result, outcome, submitErr := s.deliver(bounded, record)
		deadlineErr := bounded.Err()
		cancel()
		d.outcome, d.disposition = outcome, result.Disposition
		if submitErr == nil && (result.Disposition == audit.DeliveryPersisted || result.Disposition == audit.DeliveryBuffered) {
			d.outcome = audit.AppendCommitted
			if deadlineErr != nil {
				return d, errors.Join(ErrDecisionAuditUnavailable, deadlineErr)
			}
			return d, nil
		}
	}
	// A known audit commit is preserved even if an ancillary error prevents a
	// usable result. Only actual loss/ambiguity triggers the operational handoff.
	if d.outcome != audit.AppendCommitted {
		loss, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.Timeout)
		func() { defer func() { _ = recover() }(); _ = s.config.OnLoss(loss, d) }()
		cancel()
	}
	return d, ErrDecisionAuditUnavailable
}

func (s *decisionAuditState) deliver(ctx context.Context, record audit.Record) (audit.DeliveryResult, audit.AppendOutcome, error) {
	recorder := s.recorder
	outcome := audit.AppendUnknown
	primary := &decisionPrimaryOutcome{}
	ctx = context.WithValue(ctx, decisionPrimaryOutcomeKey{}, primary)
	if s.config.Delivery.Mode == audit.DeliveryFailOpenWithAlert {
		// Recorder intentionally clears the primary error after a successful
		// alert. Capture its typed outcome per invocation, never in shared state.
		delivery := s.config.Delivery
		delivery.Redactor = decisionProfilePreserver{}
		delivery.Alerter = audit.AlertFunc(func(ctx context.Context, a audit.DeliveryAlert) error {
			outcome = a.Outcome
			return s.config.Delivery.Alerter.Alert(ctx, a)
		})
		var err error
		recorder, err = audit.NewRecorder(delivery)
		if err != nil {
			return audit.DeliveryResult{}, audit.AppendUnknown, err
		}
	}
	result, err := recorder.Submit(ctx, record)
	if err != nil || result.Disposition != audit.DeliveryProceededAfterAlert {
		outcome = audit.AppendOutcomeOf(err)
	}
	// A failed buffer's classification describes that append, not an earlier
	// ambiguous primary write. The recorder's native observation preserves
	// primary outcome without another sink, retry or recovery owner.
	if err != nil && s.config.Delivery.Mode == audit.DeliveryDurableBuffer && primary.observed && primary.outcome == audit.AppendUnknown && outcome != audit.AppendCommitted {
		outcome = audit.AppendUnknown
	}
	return result, outcome, err
}

type decisionPrimaryOutcomeKey struct{}
type decisionPrimaryOutcome struct {
	outcome  audit.AppendOutcome
	observed bool
}
type decisionAuditObserver struct{ next audit.Observer }

func (o decisionAuditObserver) Observe(ctx context.Context, v audit.Observation) {
	if v.Kind == audit.ObservationFailed || v.Kind == audit.ObservationRejected {
		if p, ok := ctx.Value(decisionPrimaryOutcomeKey{}).(*decisionPrimaryOutcome); ok {
			p.outcome, p.observed = v.Outcome, true
		}
	}
	if o.next != nil {
		o.next.Observe(ctx, v)
	}
}

type decisionProfilePreserver struct{}

func (decisionProfilePreserver) Redact(ctx context.Context, r audit.Record) (audit.Record, error) {
	if err := ctx.Err(); err != nil {
		return audit.Record{}, err
	}
	if !r.RedactionApplied() {
		return audit.Record{}, ErrDecisionAuditUnavailable
	}
	return r, nil
}

func (e Evaluator) finishDecisionAudit(ctx context.Context, r EvaluateRequest, result EvaluateResult, decisionTime, start time.Time) (EvaluateResult, error) {
	d, err := e.state.audit.submit(ctx, r, decisionTime, e.state.policy.state.version, result.Decision.Action)
	result.Audit = d
	if err == nil {
		now := e.state.clock()
		err = ctx.Err()
		if err == nil {
			err = evaluationTime(now, decisionTime, start, e.state.timeout)
		}
		if err == nil {
			err = evaluationTime(now, decisionTime, decisionTime, e.state.audit.config.Timeout)
		}
		if err == nil {
			p := result.provenance
			c := p.context
			c.Now = now
			signals := append([]Signal(nil), p.signals...)
			if result.counter != nil && result.counter.Signal.State == SignalThrottle {
				a, _ := e.state.policy.Admit(c.Operation)
				for i := range signals {
					if signals[i].Name == "velocity" {
						signals[i].RetryAfter = counterRetryAfter(result.counter.result.state.snapshot, a.Profile.Limit, now, e.state.policy.state.limits.RetryAfterMax)
					}
				}
			}
			var assessed Assessment
			assessed, err = e.state.policy.Assess(ctx, c, signals)
			if err == nil {
				result.Decision = assessed.Decision
				result.assessment = assessed
			}
		}
	}
	if err != nil {
		// Never erase a counted outcome or restrictive policy classification.
		// No private issuing provenance survives failed observation/rechecking.
		result.provenance = nil
		if result.Decision.Action == Allow {
			result.Decision = Decision{}
			result.assessment = Assessment{}
		}
		return result, &EvaluateError{cause: errors.Join(err, ctx.Err())}
	}
	result.provenance.audit = d
	return result, nil
}
