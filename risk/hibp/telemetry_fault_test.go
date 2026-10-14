package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	audit "github.com/faustbrian/go-audit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

type completionFaults struct {
	fault                                               string
	counters, histograms, attributes, statuses, endings atomic.Int32
	statusCode                                          codes.Code
	statusDescription                                   string
}

type failingCounter struct {
	metric.Int64Counter
	state *completionFaults
}

func (c failingCounter) Add(context.Context, int64, ...metric.AddOption) {
	c.state.counters.Add(1)
	if c.state.fault == "counter" {
		panic("synthetic observer failure")
	}
}

type failingHistogram struct {
	metric.Float64Histogram
	state *completionFaults
}

func (h failingHistogram) Record(context.Context, float64, ...metric.RecordOption) {
	h.state.histograms.Add(1)
	if h.state.fault == "histogram" {
		panic("synthetic observer failure")
	}
}

type completionSpan struct {
	trace.Span
	state *completionFaults
}

func (s completionSpan) SetAttributes(...attribute.KeyValue) {
	s.state.attributes.Add(1)
	if s.state.fault == "attributes" {
		panic("synthetic observer failure")
	}
}

func (s completionSpan) SetStatus(code codes.Code, description string) {
	s.state.statuses.Add(1)
	s.state.statusCode, s.state.statusDescription = code, description
	if s.state.fault == "status" {
		panic("synthetic observer failure")
	}
}

func (s completionSpan) End(...trace.SpanEndOption) {
	s.state.endings.Add(1)
	if s.state.fault == "end" {
		panic("synthetic observer failure")
	}
}

type completionTracer struct {
	trace.Tracer
	state *completionFaults
}

func (tr completionTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	_, span := tr.Tracer.Start(ctx, name, opts...)
	return ctx, completionSpan{Span: span, state: tr.state}
}

func TestTelemetryCompletionFaultsCannotChangeEvidenceOrSuppressOtherObservers(t *testing.T) {
	for _, fault := range []string{"none", "counter", "histogram", "attributes", "status", "end"} {
		t.Run(fault, func(t *testing.T) {
			state := &completionFaults{fault: fault}
			meter := metricnoop.NewMeterProvider().Meter("test")
			counter, err := meter.Int64Counter("test")
			if err != nil {
				t.Fatal(err)
			}
			histogram, err := meter.Float64Histogram("test")
			if err != nil {
				t.Fatal(err)
			}
			telemetry := &Telemetry{tracer: completionTracer{Tracer: tracenoop.NewTracerProvider().Tracer("test"), state: state}, checks: failingCounter{counter, state}, duration: failingHistogram{histogram, state}}
			client, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "invalid\n") })
			sink := &observationSink{}
			observed, err := NewObservedChecker(client, ObservationConfig{Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, AuditTimeout: testConfig().Timeout / 10, Telemetry: telemetry})
			if err != nil {
				t.Fatal(err)
			}
			result, err := observed.Check(context.Background(), attributedRequest(t, "synthetic-observer-fault"))
			if !errors.Is(err, ErrMalformedRange) || result.Outcome != OutcomeMalformed || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() || result.Events.Disposition() != audit.DeliveryPersisted {
				t.Fatal("observer fault altered provider or audit evidence", err)
			}
			assertErrorDelivery(t, result, err)
			assertSameRecordBytes(t, result.Events.Records(), sink.snapshot())
			if state.counters.Load() != 1 || state.histograms.Load() != 1 || state.attributes.Load() != 1 || state.endings.Load() != 1 {
				t.Fatal("observer panic suppressed an independent observer or cleanup")
			}
			if fault != "attributes" && (state.statuses.Load() != 1 || state.statusCode != codes.Error || state.statusDescription != "unavailable") {
				t.Fatal("failure did not reach span status")
			}
		})
	}
}

type constructionMeter struct {
	metric.Meter
	fault string
}

func (m constructionMeter) Int64Counter(name string, opts ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	switch m.fault {
	case "counter-error":
		return nil, errors.New("synthetic constructor failure")
	case "counter-panic":
		panic("synthetic constructor panic")
	case "counter-nil":
		return nil, nil
	}
	return m.Meter.Int64Counter(name, opts...)
}

func (m constructionMeter) Float64Histogram(name string, opts ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	switch m.fault {
	case "histogram-error":
		return nil, errors.New("synthetic constructor failure")
	case "histogram-panic":
		panic("synthetic constructor panic")
	case "histogram-nil":
		return nil, nil
	}
	return m.Meter.Float64Histogram(name, opts...)
}

func TestTelemetryConstructorRejectsMissingOrBrokenInstruments(t *testing.T) {
	if result, err := NewTelemetry(nil, nil); result != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("missing telemetry dependencies became valid")
	}
	for _, fault := range []string{"counter-error", "counter-panic", "counter-nil", "histogram-error", "histogram-panic", "histogram-nil"} {
		result, err := NewTelemetry(constructionMeter{Meter: metricnoop.NewMeterProvider().Meter("test"), fault: fault}, nil)
		if result != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("broken telemetry instruments became valid", err)
		}
	}
}

func TestTelemetryAllOutcomeAndDeliveryLabelsAreClosed(t *testing.T) {
	outcomes := []struct {
		value Outcome
		label string
	}{
		{OutcomeNoMatch, "no_match"}, {OutcomeMatch, "match"}, {OutcomeInvalidConfiguration, "invalid_configuration"},
		{OutcomeMalformed, "malformed"}, {OutcomeCancelled, "cancelled"}, {OutcomeUnavailable, "unavailable"}, {Outcome(255), "unavailable"},
	}
	deliveries := []struct {
		value audit.DeliveryDisposition
		label string
	}{
		{audit.DeliveryPersisted, "persisted"}, {audit.DeliveryBuffered, "buffered"}, {audit.DeliveryProceededAfterAlert, "alerted_loss"}, {0, "unconfirmed"},
	}
	for _, outcome := range outcomes {
		for _, delivery := range deliveries {
			meter := &captureMeter{Meter: metricnoop.NewMeterProvider().Meter("test")}
			telemetry, err := NewTelemetry(meter, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			next, complete := telemetry.begin(ctx)
			complete(outcome.value, delivery.value)
			if next != ctx || len(meter.samples) != 2 {
				t.Fatal("telemetry changed context or missed completion")
			}
			for _, sample := range meter.samples {
				if len(sample) != 2 || sample[0] != attribute.String("audit.delivery", delivery.label) || sample[1] != attribute.String("hibp.outcome", outcome.label) {
					t.Fatal("outcome/delivery labels escaped closed privacy vocabulary")
				}
			}
		}
	}
}
