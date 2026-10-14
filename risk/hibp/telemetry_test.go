package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type faultTracer struct {
	trace.Tracer
	panicStart bool
}

type captureMeter struct {
	metric.Meter
	mu      sync.Mutex
	names   []string
	samples [][]attribute.KeyValue
	onAdd   func()
}
type captureCounter struct {
	metric.Int64Counter
	owner *captureMeter
}
type captureHistogram struct {
	metric.Float64Histogram
	owner *captureMeter
}

func (m *captureMeter) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	m.names = append(m.names, name)
	base, e := m.Meter.Int64Counter(name, options...)
	return captureCounter{base, m}, e
}
func (m *captureMeter) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	m.names = append(m.names, name)
	base, e := m.Meter.Float64Histogram(name, options...)
	return captureHistogram{base, m}, e
}
func (m captureCounter) Add(_ context.Context, n int64, options ...metric.AddOption) {
	if m.owner.onAdd != nil {
		m.owner.onAdd()
	}
	if n != 1 {
		panic("incorrect logical count")
	}
	attrs := metric.NewAddConfig(options).Attributes()
	m.owner.mu.Lock()
	defer m.owner.mu.Unlock()
	m.owner.samples = append(m.owner.samples, attrs.ToSlice())
}

func TestObservedCheckerRetainsCancellationDuringTelemetryCompletion(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meter := &captureMeter{Meter: metricnoop.NewMeterProvider().Meter("test"), onAdd: cancel}
	telemetry, e := NewTelemetry(meter, nil)
	if e != nil {
		t.Fatal(e)
	}
	o := observedFixture(t, c, &observationSink{})
	o.config.Telemetry = telemetry
	result, e := o.Check(ctx, attributedRequest(t, "synthetic-observer-cancel"))
	if !errors.Is(e, context.Canceled) || result.Outcome != OutcomeCancelled || !result.ProviderValidUntil.IsZero() {
		t.Fatal("observer completion swallowed caller cancellation", e)
	}
	assertErrorDelivery(t, result, e)
}
func (m captureHistogram) Record(_ context.Context, n float64, options ...metric.RecordOption) {
	if n < 0 {
		panic("negative duration")
	}
	attrs := metric.NewRecordConfig(options).Attributes()
	m.owner.mu.Lock()
	defer m.owner.mu.Unlock()
	m.owner.samples = append(m.owner.samples, attrs.ToSlice())
}
func TestTelemetryEmitsOnlyClosedLabelsPerLogicalCaller(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	sink := &observationSink{}
	o := observedFixture(t, c, sink)
	meter := &captureMeter{Meter: metricnoop.NewMeterProvider().Meter("test")}
	telemetry, e := NewTelemetry(meter, nil)
	if e != nil {
		t.Fatal(e)
	}
	o.config.Telemetry = telemetry
	for i := 0; i < 2; i++ {
		if _, e := o.Check(context.Background(), attributedRequest(t, "synthetic-metric")); e != nil {
			t.Fatal(e)
		}
	}
	if len(meter.names) != 2 || meter.names[0] != "identity.hibp.checks" || meter.names[1] != "identity.hibp.duration" || len(meter.samples) != 4 {
		t.Fatal("logical telemetry missing")
	}
	for _, sample := range meter.samples {
		if len(sample) != 2 {
			t.Fatal("unbounded telemetry labels")
		}
		values := map[string]string{}
		for _, label := range sample {
			values[string(label.Key)] = label.Value.AsString()
		}
		if values["hibp.outcome"] != "no_match" || values["audit.delivery"] != "persisted" {
			t.Fatal("caller data became telemetry")
		}
	}
}

func (t faultTracer) Start(ctx context.Context, name string, options ...trace.SpanStartOption) (context.Context, trace.Span) {
	if t.panicStart {
		panic("SECRET exporter diagnostics")
	}
	_, span := t.Tracer.Start(ctx, name, options...)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	return cancelled, span
}

func TestTelemetryCannotChangeCallerCancellationOrEvidence(t *testing.T) {
	for _, panicStart := range []bool{false, true} {
		t.Run(fmt.Sprint(panicStart), func(t *testing.T) {
			var reads atomic.Int32
			c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				reads.Add(1)
				fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
			})
			sink := &observationSink{}
			observed := observedFixture(t, c, sink)
			telemetry, e := NewTelemetry(nil, faultTracer{Tracer: noop.NewTracerProvider().Tracer("test"), panicStart: panicStart})
			if e != nil {
				t.Fatal(e)
			}
			observed.config.Telemetry = telemetry
			result, e := observed.Check(context.Background(), attributedRequest(t, "synthetic-telemetry"))
			if e != nil || result.Outcome != OutcomeNoMatch || reads.Load() != 1 || len(sink.snapshot()) != 1 {
				t.Fatal("telemetry changed provider/audit outcome", e)
			}
		})
	}
}
