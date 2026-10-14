package identityhttp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestDocumentedSelectionExportsRealProbeWire(t *testing.T) {
	checks := 0
	f, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second, Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		checks++
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	if checks != 0 {
		t.Fatal("export invoked readiness")
	}
	var raw map[string]any
	if err := json.Unmarshal(doc.JSON(), &raw); err != nil || raw["openapi"] != "3.1.1" {
		t.Fatal("not a concrete 3.1.1 document")
	}
	paths := raw["paths"].(map[string]any)
	if len(paths) != 2 || paths["/healthz"] == nil || paths["/readyz"] == nil {
		t.Fatal("wrong selected paths")
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal("not actual probe")
		}
	}
	first := doc.JSON()
	first[0] = '!'
	if !json.Valid(doc.JSON()) {
		t.Fatal("mutable document alias")
	}
	_, repeat, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || !bytes.Equal(doc.JSON(), repeat.JSON()) {
		t.Fatal("nondeterministic export")
	}
	_, empty, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(empty.JSON(), []byte("healthz")) || bytes.Contains(empty.JSON(), []byte("readyz")) {
		t.Fatal("disabled metadata leaked")
	}
}

func TestDocumentedSelectionRejectsUnboundWire(t *testing.T) {
	op := extensionDescriptor(t, "wire", "read")
	f := feature(t, "wire", nil, op)
	if h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}}); err == nil || h != nil || len(doc.JSON()) != 0 {
		t.Fatal("direct summary fabricated as wire schema")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, _, err := identityhttp.NewDocumentedHandler(ctx, identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{}); err == nil || h != nil {
		t.Fatal("canceled constructor admitted")
	}
}

func TestWireContributionBoundsReferencesAndSnapshot(t *testing.T) {
	op := extensionDescriptor(t, "wire", "read")
	definition := []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","additionalProperties":false}}}}}}`)
	op.Wire = &identityhttp.WireOperation{Definition: definition}
	f := feature(t, "wire", nil, op)
	definition[0] = '!'
	_, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	copy := f.Operations()
	copy[0].Wire.Definition[0] = '!'
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			raw := doc.JSON()
			raw[0] = '!'
			ops := doc.Operations()
			ops[0].Wire.Definition[0] = '!'
			if !json.Valid(doc.JSON()) {
				t.Error("concurrent mutable snapshot")
			}
		})
	}
	wg.Wait()
	valid := f.Operations()[0]
	for index, raw := range []string{
		`{"operationId":"wrong","responses":{}}`,
		`{"operationId":"one","operationId":"two"}`,
		`{"operationId":"` + valid.Record.OpenAPIOperationID + `","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"https://internal.invalid/private"}}}}}}`,
		`{"operationId":"` + valid.Record.OpenAPIOperationID + `","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Missing"}}}}}}`,
		`{"operationId":"` + valid.Record.OpenAPIOperationID + `","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"invented"}}}}}}`,
	} {
		candidate := valid
		candidate.Wire = &identityhttp.WireOperation{Definition: []byte(raw)}
		f := feature(t, "wire", nil, candidate)
		if h, d, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}}); err == nil || h != nil || len(d.JSON()) != 0 {
			t.Fatalf("invalid wire case%d accepted", index)
		}
	}
	for _, wire := range []*identityhttp.WireOperation{
		{}, {Definition: []byte(strings.Repeat("a", 65537))},
		{Definition: []byte(`{}`), Schemas: make([]identityhttp.WireComponent, 65)},
	} {
		candidate := valid
		candidate.Wire = wire
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "wire", Operations: []identityhttp.OperationDescriptor{candidate}}); err == nil {
			t.Fatal("unbounded wire cloned/admitted")
		}
	}
	dup := valid
	dup.Wire = &identityhttp.WireOperation{Definition: valid.Wire.Definition, Schemas: []identityhttp.WireComponent{{Name: "Shared", Definition: []byte(`{"type":"string"}`)}, {Name: "Shared", Definition: []byte(`{"type":"string"}`)}}}
	f = feature(t, "wire", nil, dup)
	if h, _, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}}); err == nil || h != nil {
		t.Fatal("identical schema collision coalesced")
	}
}

func FuzzWireDocument(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"operationId":"extension.wire.read","responses":{}}`))
	f.Add([]byte(`{"a":{"a":{"a":1}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		op := extensionDescriptor(t, "wire", "read")
		op.Wire = &identityhttp.WireOperation{Definition: raw}
		feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "wire", Operations: []identityhttp.OperationDescriptor{op}})
		if err != nil {
			return
		}
		h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err == nil {
			if h == nil || !json.Valid(doc.JSON()) {
				t.Fatal("partial successful composition")
			}
		} else if h != nil || len(doc.JSON()) != 0 {
			t.Fatal("partial failed composition")
		}
	})
}

func TestWireSchemaPreservesExactIntegerConstants(t *testing.T) {
	op := extensionDescriptor(t, "wire", "read")
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"const":9007199254740993}}}}}}`)}
	f := feature(t, "wire", nil, op)
	_, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || !bytes.Contains(doc.JSON(), []byte("9007199254740993")) {
		t.Fatal("schema integer rounded through floating point")
	}
}

func TestDocumentSnapshotAccessorsOwnTheirComponents(t *testing.T) {
	var zero identityhttp.OpenAPIDocument
	if zero.Version() != "" || zero.Digest() != [32]byte{} || len(zero.Schemas()) != 0 || len(zero.Operations()) != 0 {
		t.Fatal("zero document advertises metadata")
	}
	op := extensionDescriptor(t, "wire", "read")
	op.Wire = &identityhttp.WireOperation{
		Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Allowed"}}}}}}`),
		Schemas:    []identityhttp.WireComponent{{Name: "Rejected", Definition: []byte(`false`)}, {Name: "Allowed", Definition: []byte(`true`)}},
	}
	f := feature(t, "wire", nil, op)
	_, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version() != "3.1.1" || doc.Digest() != sha256.Sum256(doc.JSON()) {
		t.Fatal("document identity does not identify exported bytes")
	}
	components := doc.Schemas()
	if len(components) != 2 || components[0].Name != "Allowed" || string(components[0].Definition) != "true" || components[1].Name != "Rejected" || string(components[1].Definition) != "false" {
		t.Fatal("schema snapshot loses boolean schemas or stable ordering")
	}
	components[0].Definition[0] = '!'
	components[1].Name = "Mutated"
	ops := doc.Operations()
	ops[0].Wire.Schemas[0].Definition[0] = '!'
	if fresh := doc.Schemas(); string(fresh[0].Definition) != "true" || fresh[1].Name != "Rejected" || doc.Digest() != sha256.Sum256(doc.JSON()) {
		t.Fatal("export aliases immutable component storage")
	}
}

func TestWireSchemaPayloadNamesAreNotOpenAPIStructure(t *testing.T) {
	for _, name := range []string{"schemas", "schema", "$ref", "$id", "$dynamicRef", "externalValue"} {
		t.Run(name, func(t *testing.T) {
			op := extensionDescriptor(t, "wire", "read")
			op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"` + name + `":{"type":"string"}}}}}}}}`)}
			f := feature(t, "wire", nil, op)
			if h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}}); err != nil || h == nil || len(doc.JSON()) == 0 {
				t.Fatalf("valid payload property interpreted as document structure: %v", err)
			}
		})
	}
}

func TestWireProfileDistinguishesReferencesFromLiteralData(t *testing.T) {
	for _, tc := range []struct {
		name, schema, extra string
		valid               bool
	}{
		{"nested-reference", `{"properties":{"field":{"$ref":"https://private.invalid/schema"}}}`, "", false},
		{"missing-nested-reference", `{"properties":{"field":{"$ref":"#/components/schemas/Missing"}}}`, "", false},
		{"nested-invalid-schema", `{"properties":{"field":{"type":"invented"}}}`, "", false},
		{"schema-resource", `{"$id":"https://private.invalid/schema"}`, "", false},
		{"dynamic-reference", `{"$dynamicRef":"#anchor"}`, "", false},
		{"literal-default", `{"default":{"$ref":"https://example.invalid/data","$id":"ordinary data"}}`, "", true},
		{"literal-example", `{}`, `,"example":{"$ref":{"type":"ordinary data"}}`, true},
		{"external-example", `{}`, `,"examples":{"one":{"externalValue":"https://private.invalid/data"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := extensionDescriptor(t, "wire", "read")
			op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":` + tc.schema + tc.extra + `}}}}}`)}
			f := feature(t, "wire", nil, op)
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if tc.valid {
				if err != nil || h == nil || len(doc.JSON()) == 0 {
					t.Fatalf("literal data treated as protocol: %v", err)
				}
			} else if err == nil || h != nil || len(doc.JSON()) != 0 {
				t.Fatal("invalid structural reference or schema admitted")
			}
		})
	}
}

func TestWireProfileContextualCollections(t *testing.T) {
	for _, tc := range []struct {
		name, responses, callbacks string
		valid                      bool
	}{
		{"response-extension", `{"200":{"description":"ok"},"x-data":{"$ref":"literal","externalValue":"ordinary data"}}`, "", true},
		{"external-callback", `{"200":{"description":"ok"}}`, `,"callbacks":{"notify":{"$ref":"https://example.invalid/callback"}}`, false},
		{"missing-callback", `{"200":{"description":"ok"}}`, `,"callbacks":{"notify":{"$ref":"#/components/callbacks/Missing"}}`, false},
		{"named-x-schema", `{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/x-Result"}}}}}`, "", true},
		{"external-operation-link", `{"200":{"description":"ok","links":{"next":{"operationRef":"https://example.invalid/openapi.json#/paths/~1next/get"}}}}`, "", false},
		{"local-operation-link", `{"200":{"description":"ok","links":{"next":{"operationRef":"SELFOP"}}}}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := extensionDescriptor(t, "wire", "read")
			path := strings.ReplaceAll(strings.ReplaceAll(op.Route.Path, "~", "~0"), "/", "~1")
			responses := strings.ReplaceAll(tc.responses, "SELFOP", "#/paths/"+path+"/get")
			op.Wire = &identityhttp.WireOperation{
				Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":` + responses + tc.callbacks + `}`),
				Schemas:    []identityhttp.WireComponent{{Name: "x-Result", Definition: []byte(`{"type":"object","properties":{"x-field":{"type":"string"}}}`)}},
			}
			f := feature(t, "wire", nil, op)
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if tc.valid {
				if err != nil || h == nil || len(doc.JSON()) == 0 {
					t.Fatalf("valid extension or named map rejected: %v", err)
				}
			} else if err == nil || h != nil || len(doc.JSON()) != 0 {
				t.Fatal("callback reference bypassed closed profile")
			}
		})
	}
}

func TestWireReferenceTargetsRetainTheirStructuralRole(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		valid        bool
	}{
		{"concrete-response", `{"description":"ok"}`, true},
		{"missing-response-description", `{}`, false},
		{"wrong-response-description", `{"description":23}`, false},
		{"external-alias", `{"$ref":"https://example.invalid/response"}`, false},
		{"reference-object-cycle", `{"$ref":"SELF"}`, false},
		{"nested-invalid-schema", `{"description":"ok","content":{"application/json":{"schema":{"type":"invented"}}}}`, false},
		{"nested-profile-violation", `{"description":"ok","content":{"application/json":{"schema":{"$id":"https://example.invalid/schema"}}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := extensionDescriptor(t, "wire", "read")
			path := strings.ReplaceAll(strings.ReplaceAll(op.Route.Path, "~", "~0"), "/", "~1")
			target := strings.ReplaceAll(tc.target, "SELF", "#/paths/"+path+"/get/x-response")
			op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"$ref":"#/paths/` + path + `/get/x-response"}},"x-response":` + target + `}`)}
			f := feature(t, "wire", nil, op)
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if tc.valid {
				if err != nil || h == nil || len(doc.JSON()) == 0 {
					t.Fatalf("valid internal alias rejected: %v", err)
				}
			} else if err == nil || h != nil || len(doc.JSON()) != 0 {
				t.Fatal("alias concealed a reachable invalid reference or schema")
			}
		})
	}
}

func TestWireProfileAllowsRecursiveSchemaReferences(t *testing.T) {
	op := extensionDescriptor(t, "wire", "read")
	op.Wire = &identityhttp.WireOperation{
		Definition: []byte(`{"operationId":"` + op.Record.OpenAPIOperationID + `","security":[],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Recursive"}}}}}}`),
		Schemas:    []identityhttp.WireComponent{{Name: "Recursive", Definition: []byte(`{"type":"object","properties":{"next":{"$ref":"#/components/schemas/Recursive"}}}`)}},
	}
	f := feature(t, "wire", nil, op)
	if h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}}); err != nil || h == nil || len(doc.JSON()) == 0 {
		t.Fatalf("legal recursive schema rejected: %v", err)
	}
}
