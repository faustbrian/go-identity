package hibp

import (
	"context"
	"time"

	audit "github.com/faustbrian/go-audit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Telemetry owns the fixed HIBP privacy profile, not providers/exporters. Borrow
// a Meter and/or Tracer from the host's Golib telemetry Runtime. No globals,
// propagators, exporters, goroutines or shutdown ownership are changed. The zero
// value is invalid; nil disables telemetry explicitly in ObservationConfig.
type Telemetry struct {
	tracer   trace.Tracer
	checks   metric.Int64Counter
	duration metric.Float64Histogram
}

// NewTelemetry creates fixed-name instruments with only six provider outcomes
// and four audit-delivery classes. No identifiers, hashes, URLs, counts, raw
// errors or provider payloads are instrument inputs. The borrowed implementations
// must be concurrency-safe, nonblocking/bounded and must not read context baggage
// into labels. Exporter failure cannot change screening or audit decisions.
func NewTelemetry(meter metric.Meter, tracer trace.Tracer) (result *Telemetry, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = ErrInvalidConfiguration
		}
	}()
	if meter == nil && tracer == nil {
		return nil, ErrInvalidConfiguration
	}
	t := &Telemetry{tracer: tracer}
	if meter != nil {
		t.checks, err = meter.Int64Counter("identity.hibp.checks", metric.WithDescription("Logical password screening calls"))
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		t.duration, err = meter.Float64Histogram("identity.hibp.duration", metric.WithUnit("s"))
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
	}
	if !t.valid() {
		return nil, ErrInvalidConfiguration
	}
	return t, nil
}
func (t *Telemetry) valid() bool {
	return t != nil && (t.tracer != nil || t.checks != nil && t.duration != nil)
}

func (t *Telemetry) begin(ctx context.Context) (next context.Context, complete func(Outcome, audit.DeliveryDisposition)) {
	next = ctx
	start := time.Now()
	var span trace.Span
	if t != nil && t.tracer != nil {
		func() {
			defer func() { _ = recover() }()
			_, s := t.tracer.Start(ctx, "identity.hibp.check", trace.WithNewRoot())
			if s != nil {
				span = s
			}
		}()
	}
	return next, func(outcome Outcome, delivery audit.DeliveryDisposition) {
		if t == nil {
			return
		}
		attrs := []attribute.KeyValue{attribute.String("hibp.outcome", telemetryOutcome(outcome)), attribute.String("audit.delivery", telemetryDelivery(delivery))}
		// Each optional observer is isolated so one panic cannot suppress another
		// observer or change provider evidence/required audit delivery.
		func() {
			defer func() { _ = recover() }()
			if t.checks != nil {
				t.checks.Add(ctx, 1, metric.WithAttributes(attrs...))
			}
		}()
		func() {
			defer func() { _ = recover() }()
			if t.duration != nil {
				t.duration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
			}
		}()
		if span != nil {
			func() {
				defer func() { _ = recover() }()
				span.SetAttributes(attrs...)
				if outcome != OutcomeNoMatch && outcome != OutcomeMatch {
					span.SetStatus(codes.Error, "unavailable")
				}
			}()
			func() { defer func() { _ = recover() }(); span.End() }()
		}
	}
}
func telemetryOutcome(o Outcome) string {
	switch o {
	case OutcomeNoMatch:
		return "no_match"
	case OutcomeMatch:
		return "match"
	case OutcomeInvalidConfiguration:
		return "invalid_configuration"
	case OutcomeMalformed:
		return "malformed"
	case OutcomeCancelled:
		return "cancelled"
	default:
		return "unavailable"
	}
}
func telemetryDelivery(d audit.DeliveryDisposition) string {
	switch d {
	case audit.DeliveryPersisted:
		return "persisted"
	case audit.DeliveryBuffered:
		return "buffered"
	case audit.DeliveryProceededAfterAlert:
		return "alerted_loss"
	default:
		return "unconfirmed"
	}
}
