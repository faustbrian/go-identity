package identityhttp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func catalogConstructionConfig(tb testing.TB) identityhttp.CanonicalOperationConfig {
	tb.Helper()
	live, _, err := identityhttp.NewProbeHandlers(identityhttp.ProbeConfig{
		State:   func() identityhttp.ServerState { return identityhttp.ServerRunning },
		Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
			return identityhttp.ReadinessSnapshot{Ready: true}, nil
		}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return identityhttp.CanonicalOperationConfig{
		Owner: "identity/http", OperationID: "identity.health", Handler: live,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384,
	}
}

func TestCanonicalOperationConstructionAllocationBudget(t *testing.T) {
	config := catalogConstructionConfig(t)
	allocations := testing.AllocsPerRun(10, func() {
		if _, err := identityhttp.NewCanonicalOperation(config); err != nil {
			t.Fatal(err)
		}
	})
	// One detached descriptor needs only its own metadata. This generous budget
	// permits constructor changes but rejects decoding all catalog rows per call
	// (over 4,500 allocations on the pre-cache implementation).
	if allocations > 256 {
		t.Fatalf("repeated single-operation construction allocated %.0f times; budget 256", allocations)
	}
}

func TestCanonicalOperationConstructionMetadataIsolation(t *testing.T) {
	config := catalogConstructionConfig(t)
	want, err := identityhttp.NewCanonicalOperation(config)
	if err != nil {
		t.Fatal(err)
	}
	op, err := identityhttp.NewCanonicalOperation(config)
	if err != nil {
		t.Fatal(err)
	}
	feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: config.Owner, Operations: []identityhttp.OperationDescriptor{op}})
	if err != nil {
		t.Fatal(err)
	}
	mutateCatalogDescriptor(&op)
	exported := feature.Operations()
	assertCatalogDescriptor(t, exported[0], want)
	mutateCatalogDescriptor(&exported[0])
	selected, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(selected) != 1 {
		t.Fatalf("selection after exported mutation: %v", err)
	}
	assertCatalogDescriptor(t, selected[0], want)
	mutateCatalogDescriptor(&selected[0])
	fresh, err := identityhttp.NewCanonicalOperation(config)
	if err != nil {
		t.Fatal(err)
	}
	assertCatalogDescriptor(t, fresh, want)
	w := httptest.NewRecorder()
	fresh.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || w.Body.String() != "{\"status\":\"alive\"}\n" {
		t.Fatal("exported metadata mutation changed the owned probe")
	}
}

func TestCanonicalOperationConstructionConcurrent(t *testing.T) {
	config := catalogConstructionConfig(t)
	for worker := 0; worker < 8; worker++ {
		t.Run(fmt.Sprint(worker), func(t *testing.T) {
			t.Parallel()
			for range 16 {
				op, err := identityhttp.NewCanonicalOperation(config)
				if err != nil {
					t.Fatal(err)
				}
				if op.Record.OperationID != config.OperationID || len(op.Record.Owners) != 1 || op.Record.Owners[0] != config.Owner || op.Route.Path != "/healthz" || len(op.Schemas) != 3 {
					t.Fatal("concurrent construction observed changed canonical metadata")
				}
				mutateCatalogDescriptor(&op)
			}
		})
	}
}

func mutateCatalogDescriptor(op *identityhttp.OperationDescriptor) {
	op.Record.Owners[0] = "untrusted"
	op.Record.RequestSchema.Digest[0] ^= 0xff
	op.Record.CSRFOrigin.Mode = identityhttp.CSRFExactOrigin
	op.Route.Path = "/untrusted"
	op.Schemas[0].Name = "Untrusted"
	op.Schemas[0].Schema.Digest[0] ^= 0xff
}

func assertCatalogDescriptor(t *testing.T, got, want identityhttp.OperationDescriptor) {
	t.Helper()
	if !reflect.DeepEqual(got.Record, want.Record) || got.Route != want.Route || !reflect.DeepEqual(got.Schemas, want.Schemas) || got.Handler != want.Handler {
		t.Fatal("caller mutation escaped a detached canonical descriptor")
	}
}

func BenchmarkCanonicalOperationConstruction(b *testing.B) {
	config := catalogConstructionConfig(b)
	if _, err := identityhttp.NewCanonicalOperation(config); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		op, err := identityhttp.NewCanonicalOperation(config)
		if err != nil || op.Route.Method != http.MethodGet || op.Route.Path != "/healthz" {
			b.Fatalf("canonical health construction: %v", err)
		}
	}
}
