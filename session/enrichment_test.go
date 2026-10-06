package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type displayEnricher func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error)

func (f displayEnricher) Enrich(ctx context.Context, source session.Session, schema session.EnrichmentSchema) (session.Enrichment, error) {
	return f(ctx, source, schema)
}

func enrichmentConfig() session.EnrichmentConfig {
	return session.EnrichmentConfig{Schema: session.EnrichmentSchema{Version: 1, FieldNames: []string{"label"}, MaxBytes: 8}, MaximumDuration: time.Second, FailurePolicy: session.EnrichmentFail}
}

func TestEnrichmentCancellationNeverFallsBack(t *testing.T) {
	record, _ := session.NewSession(sessionSpec(t))
	for _, reported := range []error{context.Canceled, context.DeadlineExceeded, identity.CancelledError{}, identity.DeadlineExceededError{}} {
		config := enrichmentConfig()
		config.FailurePolicy = session.EnrichmentOmit
		service, _ := session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
			return session.Enrichment{Values: []string{"partial"}}, reported
		}), config)
		got, err := service.Enrich(context.Background(), record)
		var cancelled identity.CancelledError
		var deadline identity.DeadlineExceededError
		if got.Values != nil || !(errors.As(err, &cancelled) || errors.As(err, &deadline)) {
			t.Fatal("reported cancellation suppressed", err)
		}
	}
	for _, policy := range []session.EnrichmentFailurePolicy{session.EnrichmentFail, session.EnrichmentOmit} {
		config := enrichmentConfig()
		config.FailurePolicy = policy
		ctx, cancel := context.WithCancel(context.Background())
		provider := displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
			cancel()
			return session.Enrichment{Values: []string{"partial"}}, nil
		})
		service, _ := session.NewEnrichmentService(provider, config)
		got, err := service.Enrich(ctx, record)
		var cancelled identity.CancelledError
		if !errors.As(err, &cancelled) || got.Values != nil {
			t.Fatal("cancelled partial result", err)
		}
	}
}

func TestEnrichmentBoundsAndExplicitFallback(t *testing.T) {
	record, _ := session.NewSession(sessionSpec(t))
	for _, values := range [][]string{nil, {}, {"a", "b"}, {"123456789"}, {string([]byte{0xff})}} {
		for _, policy := range []session.EnrichmentFailurePolicy{session.EnrichmentFail, session.EnrichmentOmit} {
			config := enrichmentConfig()
			config.FailurePolicy = policy
			service, _ := session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
				return session.Enrichment{Values: values}, nil
			}), config)
			got, err := service.Enrich(context.Background(), record)
			if err != session.ErrUnavailable || got.Values != nil {
				t.Fatal("malformed callback accepted", err)
			}
		}
	}
	for _, value := range []string{"", "12345678", "éééé"} {
		service, _ := session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
			return session.Enrichment{Values: []string{value}}, nil
		}), enrichmentConfig())
		got, err := service.Enrich(context.Background(), record)
		if err != nil || len(got.Values) != 1 || got.Values[0] != value {
			t.Fatal("valid value rejected", err)
		}
	}
	for _, panicCallback := range []bool{false, true} {
		for _, policy := range []session.EnrichmentFailurePolicy{session.EnrichmentFail, session.EnrichmentOmit} {
			config := enrichmentConfig()
			config.FailurePolicy = policy
			service, _ := session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
				if panicCallback {
					panic("private callback detail")
				}
				return session.Enrichment{}, errors.New("private callback detail")
			}), config)
			got, err := service.Enrich(context.Background(), record)
			if got.Values != nil || (policy == session.EnrichmentFail && err != session.ErrUnavailable) || (policy == session.EnrichmentOmit && err != nil) {
				t.Fatal("fallback mismatch", err)
			}
		}
	}
}

func TestEnrichmentConfigAndZeroInputs(t *testing.T) {
	provider := displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
		return session.Enrichment{Values: []string{"ok"}}, nil
	})
	for _, change := range []func(*session.EnrichmentConfig){
		func(c *session.EnrichmentConfig) { c.Schema.Version = 0 }, func(c *session.EnrichmentConfig) { c.Schema.MaxBytes = 0 }, func(c *session.EnrichmentConfig) { c.Schema.MaxBytes = 16385 },
		func(c *session.EnrichmentConfig) { c.Schema.FieldNames = nil }, func(c *session.EnrichmentConfig) { c.Schema.FieldNames = []string{"x", "x"} }, func(c *session.EnrichmentConfig) { c.Schema.FieldNames = []string{"bad\n"} }, func(c *session.EnrichmentConfig) { c.Schema.FieldNames = []string{strings.Repeat("x", 65)} },
		func(c *session.EnrichmentConfig) { c.Schema.FieldNames = make([]string, 33) }, func(c *session.EnrichmentConfig) { c.MaximumDuration = 0 }, func(c *session.EnrichmentConfig) { c.MaximumDuration = 5*time.Second + 1 }, func(c *session.EnrichmentConfig) { c.FailurePolicy = 0 }, func(c *session.EnrichmentConfig) { c.FailurePolicy = 255 },
	} {
		config := enrichmentConfig()
		change(&config)
		if got, err := session.NewEnrichmentService(provider, config); got != nil || err != session.ErrInvalidInput {
			t.Fatal("invalid config accepted", err)
		}
	}
	var typedNil displayEnricher
	for _, p := range []session.SessionEnricher{nil, typedNil} {
		if got, err := session.NewEnrichmentService(p, enrichmentConfig()); got != nil || err != session.ErrInvalidInput {
			t.Fatal("nil callback accepted", err)
		}
	}
	service, _ := session.NewEnrichmentService(provider, enrichmentConfig())
	record, _ := session.NewSession(sessionSpec(t))
	for _, invoke := range []func() (session.Enrichment, error){func() (session.Enrichment, error) { return service.Enrich(nil, record) }, func() (session.Enrichment, error) { return service.Enrich(context.Background(), session.Session{}) }, func() (session.Enrichment, error) {
		return (*session.EnrichmentService)(nil).Enrich(context.Background(), record)
	}, func() (session.Enrichment, error) {
		return (&session.EnrichmentService{}).Enrich(context.Background(), record)
	}} {
		got, err := invoke()
		if err != session.ErrInvalidInput || got.Values != nil {
			t.Fatal("zero input", err)
		}
	}
	for _, v := range []any{session.Enrichment{Values: []string{"private"}}, enrichmentConfig(), enrichmentConfig().Schema, *service} {
		if strings.Contains(fmt.Sprintf("%#v", v), "private") {
			t.Fatal("format leak")
		}
		if b, err := json.Marshal(v); err == nil || len(b) != 0 {
			t.Fatal("implicit export")
		}
	}
}

func TestEnrichmentReevaluatesChangedSourceAndConcurrentCalls(t *testing.T) {
	config := enrichmentConfig()
	config.Schema.MaxBytes = 128
	service, _ := session.NewEnrichmentService(displayEnricher(func(_ context.Context, source session.Session, schema session.EnrichmentSchema) (session.Enrichment, error) {
		bindings, _ := source.Bindings()
		schema.FieldNames[0] = "owned"
		return session.Enrichment{Values: []string{bindings.LastActivityAt.Format(time.RFC3339Nano)}}, nil
	}), config)
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			spec := sessionSpec(t)
			spec.LastActivityAt = spec.LastActivityAt.Add(time.Duration(i) * time.Second)
			record, err := session.NewSession(spec)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := service.Enrich(context.Background(), record)
			if err != nil || len(got.Values) != 1 || got.Values[0] != spec.LastActivityAt.Format(time.RFC3339Nano) {
				t.Error("cached/aliased source", err)
			}
		}(i)
	}
	group.Wait()
}

func TestEnrichmentDeadlineAndPreCancellation(t *testing.T) {
	record, _ := session.NewSession(sessionSpec(t))
	config := enrichmentConfig()
	config.FailurePolicy = session.EnrichmentOmit
	config.MaximumDuration = time.Millisecond
	service, _ := session.NewEnrichmentService(displayEnricher(func(ctx context.Context, _ session.Session, _ session.EnrichmentSchema) (session.Enrichment, error) {
		<-ctx.Done()
		return session.Enrichment{Values: []string{"partial"}}, nil
	}), config)
	got, err := service.Enrich(context.Background(), record)
	var deadline identity.DeadlineExceededError
	if !errors.As(err, &deadline) || got.Values != nil {
		t.Fatal("deadline converted into fallback", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service, _ = session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
		t.Error("callback entered after cancellation")
		return session.Enrichment{}, nil
	}), config)
	got, err = service.Enrich(ctx, record)
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) || got.Values != nil {
		t.Fatal("pre-cancelled result", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	service, _ = session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
		cancel()
		panic("private panic")
	}), config)
	got, err = service.Enrich(ctx, record)
	if !errors.As(err, &cancelled) || got.Values != nil {
		t.Fatal("cancelled panic converted into fallback", err)
	}
}

func TestEnrichmentTotalByteBudgetAndMaximumSchema(t *testing.T) {
	record, _ := session.NewSession(sessionSpec(t))
	config := enrichmentConfig()
	config.Schema.FieldNames = []string{"first", "second"}
	for _, values := range [][]string{{"1234", "5678"}, {"12345", "6789"}} {
		service, _ := session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
			return session.Enrichment{Values: values}, nil
		}), config)
		got, err := service.Enrich(context.Background(), record)
		if len(values[0])+len(values[1]) == 8 {
			if err != nil || len(got.Values) != 2 {
				t.Fatal("inclusive total cap", err)
			}
		} else if err != session.ErrUnavailable || got.Values != nil {
			t.Fatal("per-field cap confused with total cap", err)
		}
	}
	config.Schema.MaxBytes = 16384
	config.Schema.FieldNames = make([]string, 32)
	values := make([]string, 32)
	for i := range values {
		config.Schema.FieldNames[i] = fmt.Sprintf("%064d", i)
		values[i] = strings.Repeat("x", 512)
	}
	config.MaximumDuration = 5 * time.Second
	service, err := session.NewEnrichmentService(displayEnricher(func(context.Context, session.Session, session.EnrichmentSchema) (session.Enrichment, error) {
		return session.Enrichment{Values: values}, nil
	}), config)
	if err != nil {
		t.Fatal("maximum config", err)
	}
	got, err := service.Enrich(context.Background(), record)
	if err != nil || len(got.Values) != 32 || len(got.Values[31]) != 512 {
		t.Fatal("maximum bounded result", err)
	}
}

func TestEnrichmentReturnsOwnedNonAuthoritativeProjection(t *testing.T) {
	source, err := session.NewSession(sessionSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := source.Bindings()
	values := []string{"display"}
	schema := session.EnrichmentSchema{Version: 1, FieldNames: []string{"label"}, MaxBytes: 16}
	provider := displayEnricher(func(ctx context.Context, got session.Session, declared session.EnrichmentSchema) (session.Enrichment, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded callback")
		}
		bindings, _ := got.Bindings()
		if bindings != before || declared.FieldNames[0] != "label" {
			t.Fatal("source or schema changed")
		}
		declared.FieldNames[0] = "tampered"
		return session.Enrichment{Values: values}, nil
	})
	service, err := session.NewEnrichmentService(provider, session.EnrichmentConfig{Schema: schema, MaximumDuration: time.Second, FailurePolicy: session.EnrichmentFail})
	if err != nil {
		t.Fatal(err)
	}
	schema.FieldNames[0] = "caller-change"
	result, err := service.Enrich(context.Background(), source)
	if err != nil || len(result.Values) != 1 || result.Values[0] != "display" {
		t.Fatal(result, err)
	}
	values[0] = "provider-change"
	if result.Values[0] != "display" {
		t.Fatal("output alias")
	}
	result.Values[0] = "consumer-change"
	if values[0] != "provider-change" {
		t.Fatal("reverse output alias")
	}
	after, _ := source.Bindings()
	if after != before {
		t.Fatal("enrichment changed session authority")
	}
	if _, err := service.Enrich(context.Background(), source); err != nil {
		t.Fatal("schema alias retained", err)
	}
}
