package hibp

import (
	"context"
	"errors"
	"time"

	audit "github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// ErrAuditUnavailable means required event submission did not confirm primary
// or durable-buffer delivery. No usable password evidence accompanies it.
var ErrAuditUnavailable = errors.New("hibp: security audit unavailable")

// SecurityAttribution is trusted workflow context, not transport input. The
// attempt must be an actual pre-authentication transaction, not SubjectScope,
// a user identifier or its digest. PolicyVersion is the numeric audit-policy
// version, distinct from the checker's provider configuration version string.
// Caller owns the actor/delegation input and must not mutate it during Check.
type SecurityAttribution struct {
	CommandID, CorrelationID, CausationID identity.CommandID
	Actor                                 audit.ActorInput
	AttemptID                             identity.PreAuthTransactionID
	PolicyID                              string
	PolicyVersion                         uint64
}

// EventDelivery retains immutable records so an unknown delivery can be
// reconciled or retried through the existing audit protocol without rebuilding
// IDs or canonical bytes. It owns no store, retry queue or authority. The host
// owns reconciliation/durable buffering. Its zero value has no submitted events.
type EventDelivery struct {
	records     []audit.Record
	disposition audit.DeliveryDisposition
	outcome     audit.AppendOutcome
}

// Records returns an owned slice of immutable records, in submission order.
func (d EventDelivery) Records() []audit.Record { return append([]audit.Record(nil), d.records...) }

// Disposition distinguishes primary delivery, buffering and alerted loss.
func (d EventDelivery) Disposition() audit.DeliveryDisposition { return d.disposition }

// AppendOutcome retains rejected/committed/unknown acknowledgement semantics.
// Successful primary/buffer acknowledgements report committed; zero is unknown.
func (d EventDelivery) AppendOutcome() audit.AppendOutcome { return d.outcome }

// ObservationConfig selects the existing audit recorder's delivery policy and
// borrows its sink, buffer, alerts and optional telemetry. Delivery.Redactor must
// be nil: this module preserves the shared builder's already-redacted profile,
// rather than allowing downstream redaction to remove required attribution.
// AuditTimeout (1ms..5s) bounds a separate terminal-delivery context, including
// after caller cancellation. The recorder additionally owns its explicit bounded
// recovery policy. Dependencies must honor bounded contexts and be concurrent-safe.
// Logging/metrics are not an audit sink. No goroutines or resource ownership move.
type ObservationConfig struct {
	Delivery     audit.RecorderConfig
	AuditTimeout time.Duration
	Telemetry    *Telemetry
}

// ObservedChecker borrows a Client and its immutable clock/profile. Its recorder
// owns only explicit delivery composition, borrowing the configured dependencies.
// It emits per logical caller, including cache hits and coalesced waiters, not
// per shared network fetch. Client shutdown ownership remains with its caller;
// Close does not own or wait for these separately bounded synchronous callbacks.
// The zero value is invalid. Methods may run concurrently under dependency contracts.
type ObservedChecker struct {
	client   *Client
	config   ObservationConfig
	builder  *identity.IdentitySecurityEventV1
	recorder *audit.Recorder
	// Admission tokens remain owned until audit recovery and observers finish.
	// The channel is never closed; no goroutine waits to acquire a token.
	admission chan struct{}
}

// NewObservedChecker selects required per-caller security events. Existing Client
// APIs remain provider-only. Every observed request must supply valid attribution
// before candidate borrowing/network work. The recorder's fail-open alert can
// surface loss, but cannot make undelivered required events into usable evidence.
func NewObservedChecker(client *Client, config ObservationConfig) (*ObservedChecker, error) {
	if client == nil || client.http == nil || config.Delivery.Redactor != nil || config.AuditTimeout < time.Millisecond || config.AuditTimeout > 5*time.Second || config.Telemetry != nil && !config.Telemetry.valid() {
		return nil, ErrInvalidConfiguration
	}
	builder, e := identity.NewIdentitySecurityEventV1(client.clock)
	if e != nil {
		return nil, ErrInvalidConfiguration
	}
	delivery := config.Delivery
	delivery.Redactor = profilePreserver{}
	recorder, e := audit.NewRecorder(delivery)
	if e != nil {
		return nil, ErrInvalidConfiguration
	}
	return &ObservedChecker{client: client, config: config, builder: builder, recorder: recorder, admission: make(chan struct{}, client.config.MaxWaiters)}, nil
}

// NewObservedSignalProvider preserves the existing neutral normalization around
// the selected observed checker. Assess emits once via Check; it adds no events
// or acceptance decision. Client/recorder/telemetry lifecycle stays with the host.
func NewObservedSignalProvider(checker *ObservedChecker, policy risk.Policy) (SignalProvider, error) {
	if checker == nil || checker.client == nil || checker.builder == nil {
		return nil, ErrInvalidConfiguration
	}
	provider, e := NewSignalProvider(checker.client, policy)
	if e != nil {
		return nil, e
	}
	p := provider.(*signalProvider)
	p.checker = checker
	return p, nil
}

// Check emits query then match/rejection as one recorder batch. Query means one
// logical screening attempt, even on cache hits or pre-network cancellation.
// Detection succeeds when a positive provider fact is observed, not when a
// password is accepted. Rejection succeeds when unusable range evidence is
// discarded; the query record separately retains the provider failure reason.
// MaxWaiters bounds complete observed calls, including terminal delivery and
// telemetry. Saturated calls return ErrOverloaded before starting screening or
// constructing events, even when already cancelled; admission never queues.
// Invalid attribution emits nothing and performs no network work. Unknown audit
// delivery invalidates usable evidence, preserves any original failure, and
// exposes the unchanged built records for the existing reconciliation protocol.
func (o *ObservedChecker) Check(ctx context.Context, request CheckRequest) (CheckResult, error) {
	if o == nil || o.client == nil || o.builder == nil || o.admission == nil {
		return failure(resultFor(request), ErrInvalidConfiguration)
	}
	if ctx == nil || request.Attribution == nil {
		return failure(resultFor(request), ErrInvalidRequest)
	}
	select {
	case o.admission <- struct{}{}:
		defer func() { <-o.admission }()
	default:
		return failure(resultFor(request), ErrOverloaded)
	}
	// Validate trusted attribution through the shared builder before candidate use.
	// A preflight record is not submitted; real records use terminal occurrence time.
	preflight, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.config.AuditTimeout)
	input := o.eventInput(request)
	_, e := o.builder.Build(preflight, input)
	cancel()
	if e != nil {
		return failure(resultFor(request), ErrInvalidRequest)
	}
	measurementCtx, complete := o.config.Telemetry.begin(ctx)
	result, checkErr := o.client.Check(measurementCtx, request)
	terminal, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.config.AuditTimeout)
	defer cancel()
	input = o.eventInput(request)
	input.Outcome, input.Reason, input.Provider.Result = observedClassification(checkErr)
	query, buildErr := o.builder.Build(terminal, input)
	if buildErr == nil {
		result.Events.records = []audit.Record{query}
		if checkErr != nil || result.Outcome == OutcomeMatch {
			input.CausationID = identity.CommandID(query.ID())
			input.Action = identity.SecurityHIBPDetectMatch
			if checkErr != nil {
				input.Action = identity.SecurityHIBPRejectRange
			}
			input.Outcome = audit.OutcomeSucceeded
			input.Reason = identity.SecurityCompleted
			secondary, err := o.builder.Build(terminal, input)
			buildErr = err
			if err == nil {
				result.Events.records = append(result.Events.records, secondary)
			}
		}
	}
	if buildErr == nil {
		delivered, outcome, err := o.submitBatch(terminal, result.Events.records)
		result.Events.disposition = delivered.Disposition
		result.Events.outcome = outcome
		if err == nil && (delivered.Disposition == audit.DeliveryPersisted || delivered.Disposition == audit.DeliveryBuffered) {
			result.Events.outcome = audit.AppendCommitted
		} else {
			buildErr = ErrAuditUnavailable
		}
	}
	if buildErr != nil {
		checkErr = errors.Join(checkErr, ErrAuditUnavailable)
	}
	if e := ctx.Err(); e != nil {
		checkErr = errors.Join(checkErr, e)
	}
	if checkErr != nil {
		// Finalize the failure once, after delivery metadata is known. The
		// provider's original error predates submission and has no event IDs.
		result, checkErr = failure(result, checkErr)
	}
	complete(result.Outcome, result.Events.disposition)
	if e := ctx.Err(); e != nil && !errors.Is(checkErr, e) {
		result, checkErr = failure(result, errors.Join(checkErr, e))
	}
	return result, checkErr
}

func (o *ObservedChecker) submitBatch(ctx context.Context, records []audit.Record) (audit.DeliveryBatchResult, audit.AppendOutcome, error) {
	recorder := o.recorder
	outcome := audit.AppendUnknown
	if o.config.Delivery.Mode == audit.DeliveryFailOpenWithAlert {
		// Alerted-loss success intentionally omits the primary append error.
		// Preserve its authoritative typed alert outcome in invocation-local
		// state, while forwarding the actual host alert exactly once. Sharing
		// a last-outcome field would mix concurrent callers' receipts.
		delivery := o.config.Delivery
		delivery.Redactor = profilePreserver{}
		delivery.Alerter = audit.AlertFunc(func(ctx context.Context, alert audit.DeliveryAlert) error {
			outcome = alert.Outcome
			return o.config.Delivery.Alerter.Alert(ctx, alert)
		})
		var e error
		recorder, e = audit.NewRecorder(delivery)
		if e != nil {
			return audit.DeliveryBatchResult{}, audit.AppendUnknown, e
		}
	}
	delivered, e := recorder.SubmitBatch(ctx, records)
	if e != nil || delivered.Disposition != audit.DeliveryProceededAfterAlert {
		outcome = audit.AppendOutcomeOf(e)
	}
	return delivered, outcome, e
}

func (o *ObservedChecker) eventInput(r CheckRequest) identity.SecurityEventInput {
	a := r.Attribution
	return identity.SecurityEventInput{Action: identity.SecurityHIBPQueryRange, OccurredAt: o.client.clock.Now().UTC(), Outcome: audit.OutcomeSucceeded, Reason: identity.SecurityCompleted, TenantID: r.TenantID, CommandID: a.CommandID, CorrelationID: a.CorrelationID, CausationID: a.CausationID, Actor: a.Actor, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(a.AttemptID), PolicyID: a.PolicyID, PolicyVersion: a.PolicyVersion, Provider: identity.SecurityProvider{Kind: identity.SecurityProviderHIBP, Profile: identity.SecurityHIBPRange, Version: 1, Result: identity.SecurityProviderAccepted}}
}
func observedClassification(e error) (audit.Outcome, identity.SecurityReason, identity.SecurityProviderResult) {
	switch {
	case e == nil:
		return audit.OutcomeSucceeded, identity.SecurityCompleted, identity.SecurityProviderAccepted
	case errors.Is(e, context.Canceled):
		return audit.OutcomeFailed, identity.SecurityCancelled, identity.SecurityProviderResultUnavailable
	case errors.Is(e, context.DeadlineExceeded):
		return audit.OutcomeFailed, identity.SecurityTimeout, identity.SecurityProviderResultTimeout
	case errors.Is(e, ErrMalformedRange):
		return audit.OutcomeFailed, identity.SecurityProviderUnavailable, identity.SecurityProviderMalformed
	case errors.Is(e, ErrInvalidRequest):
		return audit.OutcomeDenied, identity.SecurityInvalidInput, identity.SecurityProviderBindingMismatch
	case errors.Is(e, ErrOverloaded):
		return audit.OutcomeDenied, identity.SecurityRateLimited, identity.SecurityProviderThrottled
	default:
		return audit.OutcomeFailed, identity.SecurityProviderUnavailable, identity.SecurityProviderResultUnavailable
	}
}

var _ Checker = (*ObservedChecker)(nil)

// The shared builder alone owns privacy classification. Recorder still runs
// its mandatory redaction stage, but must not delete required profile fields.
type profilePreserver struct{}

func (profilePreserver) Redact(ctx context.Context, r audit.Record) (audit.Record, error) {
	if e := ctx.Err(); e != nil {
		return audit.Record{}, e
	}
	if !r.RedactionApplied() {
		return audit.Record{}, ErrAuditUnavailable
	}
	return r, nil
}
