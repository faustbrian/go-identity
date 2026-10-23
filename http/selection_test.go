package identityhttp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestCanonicalEmailStoredSynchronizerPolicy(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	stored := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	for _, operation := range []string{"identity.email.verification-send", "identity.email.change-request", "identity.email.address-remove"} {
		if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: operation, Handler: handler, CSRF: stored, MaximumSerializedBytes: 16384}); err != nil {
			t.Fatal("exact stored synchronizer rejected", operation, err)
		}
		for _, mutate := range []func(*identityhttp.CSRFPolicy){
			func(p *identityhttp.CSRFPolicy) { p.TokenHeader = "X-Other" },
			func(p *identityhttp.CSRFPolicy) { p.TokenMaximumAge = time.Minute },
			func(p *identityhttp.CSRFPolicy) { p.RefererFallback = identityhttp.RefererFallbackSameOriginHTTPS },
		} {
			policy := stored
			mutate(&policy)
			if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: operation, Handler: handler, CSRF: policy, MaximumSerializedBytes: 16384}); err == nil {
				t.Fatal("weaker/independently aged policy accepted", operation)
			}
		}
	}
	if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/email", OperationID: "identity.email.verification-confirm", Handler: handler, CSRF: stored, MaximumSerializedBytes: 16384}); err == nil {
		t.Fatal("stored request exception leaked to confirmation")
	}
}

func TestCanonicalPasskeyManagementUsesOriginalSessionSynchronizer(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	stored := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	for _, operation := range []string{"identity.passkey.register-options", "identity.passkey.register-verify", "identity.passkey.update", "identity.passkey.delete"} {
		if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "passkey", OperationID: operation, Handler: handler, CSRF: stored, MaximumSerializedBytes: 16384}); err != nil {
			t.Fatal("original passkey enrollment synchronizer rejected", operation, err)
		}
		for _, mutate := range []func(*identityhttp.CSRFPolicy){
			func(p *identityhttp.CSRFPolicy) { p.TokenHeader = "X-Other" },
			func(p *identityhttp.CSRFPolicy) { p.TokenMaximumAge = time.Minute },
			func(p *identityhttp.CSRFPolicy) { p.RefererFallback = identityhttp.RefererFallbackSameOriginHTTPS },
		} {
			policy := stored
			mutate(&policy)
			if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "passkey", OperationID: operation, Handler: handler, CSRF: policy, MaximumSerializedBytes: 16384}); err == nil {
				t.Fatal("changed or independently aged synchronizer admitted", operation)
			}
		}
	}
	for _, operation := range []string{"identity.passkey.signin-options", "identity.passkey.signin-verify"} {
		if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "passkey", OperationID: operation, Handler: handler, CSRF: stored, MaximumSerializedBytes: 16384}); err == nil {
			t.Fatal("authenticated enrollment exception leaked into signin", operation)
		}
	}
}

// HTTPSEL-01/06/07: selecting no feature exposes nothing; selecting probes
// returns real owned handlers, not fabricated domain-route placeholders.
func TestSelectedProbeOperations(t *testing.T) {
	empty, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{})
	if err != nil || len(empty) != 0 {
		t.Fatalf("base selected features: %v", err)
	}
	feature, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{
		State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
			return identityhttp.ReadinessSnapshot{Ready: true}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 2 {
		t.Fatalf("probe selection: %v", err)
	}
	for i, want := range []struct{ id, path, owner, body string }{
		{"identity.health", "/healthz", "identity/http", "{\"status\":\"alive\"}\n"},
		{"identity.readiness", "/readyz", "identity/reference", "{\"ready\":true}\n"},
	} {
		op := ops[i]
		if op.Record.OperationID != want.id || op.Route.Path != want.path || op.Route.Method != "GET" || string(op.Record.Owners[0]) != want.owner || string(op.Record.RatePolicy) != "rate.safe" {
			t.Fatalf("wrong probe metadata: %+v", op.Record)
		}
		w := httptest.NewRecorder()
		op.Handler.ServeHTTP(w, httptest.NewRequest("GET", want.path, nil))
		if w.Code != 200 || w.Body.String() != want.body {
			t.Fatal("descriptor does not own real probe behavior")
		}
	}
}

func extensionDescriptor(t *testing.T, owner, name string) identityhttp.OperationDescriptor {
	t.Helper()
	id := "extension." + strings.ReplaceAll(owner, "/", ".") + "." + name
	policy := identityhttp.RouteAuthorization{Access: "public", Policy: "none"}
	r := identityhttp.OperationRecord{OperationID: id, Exposure: identityhttp.ExposureBoth, Owners: []identityhttp.ModuleID{identityhttp.ModuleID(owner)}, Access: "public", Authorization: policy,
		CSRFOrigin: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, RiskClass: "safe", RatePolicy: "rate.safe", Idempotency: "read", EventSemantics: "Read the selected extension result.", HandlerOwner: identityhttp.ModuleID(owner), Method: "GET", Path: "/extensions/" + owner + "/" + name, OpenAPIOperationID: id}
	var schemas []identityhttp.OpenAPISchema
	for i, suffix := range []string{"request", "result", "error"} {
		s := identityhttp.TypedSchema{ID: id + "." + suffix, Digest: [32]byte{byte(i + 1)}, MaximumDepth: 1}
		schemas = append(schemas, identityhttp.OpenAPISchema{Name: strings.ReplaceAll(id, ".", "_") + "_" + suffix, Schema: s, MaximumSerializedBytes: 1024})
	}
	r.RequestSchema, r.ResultSchema, r.ErrorSchema = schemas[0].Schema, schemas[1].Schema, schemas[2].Schema
	return identityhttp.OperationDescriptor{Record: r, Route: identityhttp.Route{Method: r.Method, Path: r.Path, Authorization: policy, CSRF: r.CSRFOrigin, RatePolicy: r.RatePolicy}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("extension")) }), Schemas: schemas}
}

func feature(t *testing.T, owner string, requires []identityhttp.ModuleID, ops ...identityhttp.OperationDescriptor) identityhttp.Feature {
	t.Helper()
	f, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: identityhttp.ModuleID(owner), Requires: requires, Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// HTTPSEL-01/02/07: only selected integrations matter; prerequisite order does not.
func TestSelectedFeatureDependencies(t *testing.T) {
	a := feature(t, "alpha", []identityhttp.ModuleID{"beta"}, extensionDescriptor(t, "alpha", "read"))
	b := feature(t, "beta", nil, extensionDescriptor(t, "beta", "read"))
	if ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{a}}); !errors.Is(err, identityhttp.ErrInvalidInput) || ops != nil {
		t.Fatal("missing dependency exposed partial operations")
	}
	for _, features := range [][]identityhttp.Feature{{b}, {a, b}, {b, a}} {
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: features})
		if err != nil || len(ops) != len(features) {
			t.Fatal(err)
		}
		for _, op := range ops {
			w := httptest.NewRecorder()
			op.Handler.ServeHTTP(w, httptest.NewRequest("GET", op.Route.Path, nil))
			if w.Code != 200 || w.Body.String() != "extension" {
				t.Fatal("missing extension handler behavior")
			}
		}
	}
	bCycle := feature(t, "beta", []identityhttp.ModuleID{"alpha"}, extensionDescriptor(t, "beta", "read"))
	if ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{a, bCycle}}); !errors.Is(err, identityhttp.ErrInvalidInput) || ops != nil {
		t.Fatal("dependency cycle accepted")
	}
}

// HTTPSEL-03: identical duplicates never become last-writer wins.
func TestSelectedFeatureCollisions(t *testing.T) {
	a := extensionDescriptor(t, "alpha", "one")
	for _, change := range []func(*identityhttp.OperationDescriptor){
		func(b *identityhttp.OperationDescriptor) { *b = a },
		func(b *identityhttp.OperationDescriptor) { b.Route.Path = a.Route.Path; b.Record.Path = a.Record.Path },
		func(b *identityhttp.OperationDescriptor) { b.Schemas = append(b.Schemas, a.Schemas[0]) },
		func(b *identityhttp.OperationDescriptor) { b.Schemas[0].Name = a.Schemas[0].Name },
	} {
		b := extensionDescriptor(t, "alpha", "two")
		change(&b)
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "alpha", Operations: []identityhttp.OperationDescriptor{a, b}}); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("local collision accepted")
		}
	}
	fa := feature(t, "alpha", nil, a)
	if ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{fa, fa}}); !errors.Is(err, identityhttp.ErrInvalidInput) || ops != nil {
		t.Fatal("duplicate feature accepted")
	}
	for _, change := range []func(*identityhttp.OperationDescriptor){
		func(b *identityhttp.OperationDescriptor) { b.Route.Path = a.Route.Path; b.Record.Path = a.Record.Path },
		func(b *identityhttp.OperationDescriptor) { b.Schemas[0].Name = a.Schemas[0].Name },
		func(b *identityhttp.OperationDescriptor) {
			b.Schemas[0].Schema = a.Schemas[0].Schema
			b.Record.RequestSchema = a.Record.RequestSchema
		},
	} {
		b := extensionDescriptor(t, "beta", "one")
		change(&b)
		fb := feature(t, "beta", nil, b)
		if ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{fa, fb}}); !errors.Is(err, identityhttp.ErrInvalidInput) || ops != nil {
			t.Fatal("cross-feature collision accepted")
		}
	}
	b := extensionDescriptor(t, "alpha", "two")
	b.Route.Path = a.Route.Path
	b.Record.Path = a.Record.Path
	b.Route.Method = "POST"
	b.Record.Method = "POST"
	feature(t, "alpha", nil, a, b) // Different explicit methods are distinguishable.
}

// HTTPSEL-04/08: copy inputs and outputs, not mutable registries or handlers.
func TestSelectedFeatureSnapshots(t *testing.T) {
	a := extensionDescriptor(t, "alpha", "read")
	deps := []identityhttp.ModuleID{"beta"}
	inputs := []identityhttp.OperationDescriptor{a}
	f := feature(t, "alpha", deps, inputs...)
	b := feature(t, "beta", nil, extensionDescriptor(t, "beta", "read"))
	services := identityhttp.FeatureServices{Features: []identityhttp.Feature{f, b}}
	original, err := identityhttp.NewOperationDescriptors(services)
	if err != nil {
		t.Fatal(err)
	}
	deps[0] = "absent"
	inputs[0].Record.Owners[0] = "absent"
	inputs[0].Schemas[0].Name = "changed"
	inputs[0].Record.Path = "/changed"
	got := f.Operations()
	got[0].Record.Owners[0] = "changed"
	got[0].Schemas[0].Schema.ID = "changed"
	got[0].Route.Path = "/changed"
	copy, err := identityhttp.NewOperationDescriptors(services)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(metadata(original), metadata(copy)) {
		t.Fatal("caller input/getter mutation escaped")
	}
	copy[0].Record.Owners[0] = "changed"
	copy[0].Schemas[0].Name = "changed"
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ops, err := identityhttp.NewOperationDescriptors(services)
				if err != nil || !reflect.DeepEqual(metadata(original), metadata(ops)) {
					t.Error("snapshot isolation failed")
					return
				}
				ops[0].Record.Owners[0] = "changed"
			}
		}()
	}
	wg.Wait()
}

func metadata(ops []identityhttp.OperationDescriptor) []identityhttp.OperationDescriptor {
	result := append([]identityhttp.OperationDescriptor(nil), ops...)
	for i := range result {
		result[i].Handler = nil
	}
	return result
}

// HTTPSEL-05/06: bounded/closed construction and no canonical policy override.
func TestSelectedFeatureInvalidInput(t *testing.T) {
	for _, change := range []func(*identityhttp.OperationDescriptor){
		func(o *identityhttp.OperationDescriptor) { o.Handler = nil },
		func(o *identityhttp.OperationDescriptor) { o.Handler = http.HandlerFunc(nil) },
		func(o *identityhttp.OperationDescriptor) { o.Record.Exposure = 0 },
		func(o *identityhttp.OperationDescriptor) { o.Record.Exposure = identityhttp.ExposureDirect },
		func(o *identityhttp.OperationDescriptor) { o.Record.Owners = nil },
		func(o *identityhttp.OperationDescriptor) {
			o.Record.Owners = append(o.Record.Owners, o.Record.Owners[0])
		},
		func(o *identityhttp.OperationDescriptor) { o.Record.Access = "" },
		func(o *identityhttp.OperationDescriptor) { o.Record.EventSemantics = strings.Repeat("x", 4097) },
		func(o *identityhttp.OperationDescriptor) { o.Record.RequestSchema.Digest = [32]byte{} },
		func(o *identityhttp.OperationDescriptor) { o.Record.RequestSchema.MaximumDepth = 129 },
		func(o *identityhttp.OperationDescriptor) { o.Schemas[0].MaximumSerializedBytes = 16<<20 + 1 },
		func(o *identityhttp.OperationDescriptor) { o.Schemas = nil },
		func(o *identityhttp.OperationDescriptor) { o.Record.OpenAPIOperationID = "identity.health" },
		func(o *identityhttp.OperationDescriptor) {
			o.Record.OperationID = "identity.platform.bootstrap-administrator"
		},
		func(o *identityhttp.OperationDescriptor) {
			o.Record.RatePolicy = "rate.unknown"
			o.Route.RatePolicy = "rate.unknown"
		},
		func(o *identityhttp.OperationDescriptor) {
			o.Route.Path = "/encoded%2falias"
			o.Record.Path = o.Route.Path
		},
		func(o *identityhttp.OperationDescriptor) {
			o.Route.CSRF.TokenHeader = "X-CSRF"
			o.Record.CSRFOrigin = o.Route.CSRF
		},
	} {
		op := extensionDescriptor(t, "alpha", "read")
		change(&op)
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "alpha", Operations: []identityhttp.OperationDescriptor{op}}); err != identityhttp.ErrInvalidInput {
			t.Fatalf("invalid contribution accepted: %v", err)
		}
	}
	for _, c := range []identityhttp.FeatureConfig{{}, {ID: "UPPER", Operations: []identityhttp.OperationDescriptor{extensionDescriptor(t, "alpha", "read")}}, {ID: "alpha", Requires: []identityhttp.ModuleID{"alpha"}, Operations: []identityhttp.OperationDescriptor{extensionDescriptor(t, "alpha", "read")}}, {ID: "alpha", Requires: []identityhttp.ModuleID{"beta", "beta"}, Operations: []identityhttp.OperationDescriptor{extensionDescriptor(t, "alpha", "read")}}} {
		if _, err := identityhttp.NewFeature(c); err != identityhttp.ErrInvalidInput {
			t.Fatal("invalid feature accepted")
		}
	}
	for _, fs := range [][]identityhttp.Feature{{{}}, make([]identityhttp.Feature, 65)} {
		if ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: fs}); err != identityhttp.ErrInvalidInput || ops != nil {
			t.Fatal("invalid selection exposed output")
		}
	}
	f, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second, Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	op := f.Operations()[0]
	op.Record.RatePolicy = "rate.auth"
	op.Route.RatePolicy = "rate.auth"
	if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/http", Operations: []identityhttp.OperationDescriptor{op}}); err != identityhttp.ErrInvalidInput {
		t.Fatal("canonical rate mapping overridden")
	}
}

func TestSelectedFeatureAggregateBounds(t *testing.T) {
	var ops []identityhttp.OperationDescriptor
	for i := range 1024 {
		ops = append(ops, extensionDescriptor(t, "alpha", fmt.Sprintf("op%d", i)))
	}
	a := feature(t, "alpha", nil, ops...)
	if got, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{a}}); err != nil || len(got) != 1024 {
		t.Fatal("exact operation limit denied", err)
	}
	if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "alpha", Operations: append(ops, extensionDescriptor(t, "alpha", "overflow"))}); err != identityhttp.ErrInvalidInput {
		t.Fatal("feature operation overflow accepted")
	}
	b := feature(t, "beta", nil, extensionDescriptor(t, "beta", "read"))
	if got, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{a, b}}); err != identityhttp.ErrInvalidInput || got != nil {
		t.Fatal("aggregate operation overflow accepted")
	}
}

func TestSelectedCanonicalSchemaDigestCannotBeOverridden(t *testing.T) {
	f, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{
		State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
			return identityhttp.ReadinessSnapshot{Ready: true}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1, 2} {
		op := f.Operations()[0]
		schemas := []*identityhttp.TypedSchema{&op.Record.RequestSchema, &op.Record.ResultSchema, &op.Record.ErrorSchema}
		schemas[index].Digest[0] ^= 0xff
		for i := range op.Schemas {
			if op.Schemas[i].Schema.ID == schemas[index].ID {
				op.Schemas[i].Schema = *schemas[index]
			}
		}
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/http", Operations: []identityhttp.OperationDescriptor{op}}); err != identityhttp.ErrInvalidInput {
			t.Fatalf("canonical schema %d digest overridden: %v", index, err)
		}
	}
}
