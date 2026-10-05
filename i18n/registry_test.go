package i18n

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type registryError struct {
	identity ErrorIdentity
	params   []SafeParameter
}

func (*registryError) Error() string                     { panic("error text must never be inspected") }
func (e *registryError) ErrorIdentity() ErrorIdentity    { return e.identity }
func (e *registryError) SafeParameters() []SafeParameter { return e.params }

type registryWrap struct{ error }

func (e registryWrap) Unwrap() error { return e.error }

func TestRegistryConstructionSealingAndTypedResolution(t *testing.T) {
	r := NewErrorRegistry()
	schema := ParameterSchema{Parameters: []ParameterSpec{{Name: "attempts", Kind: identity.AttributeInt64, Context: ParameterPlainText}}}
	if err := r.Register("identity.test.denied", "signin.denied", schema); err != nil {
		t.Fatal(err)
	}
	schema.Parameters[0].Name = "mutated"
	input := &registryError{identity: "identity.test.denied", params: []SafeParameter{{Name: "attempts", Value: identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: 3}, Context: ParameterPlainText}}}
	if _, _, ok := r.Resolve(input); ok {
		t.Fatal("unsealed registry used")
	}
	if err := SealErrorRegistry(r); err != nil {
		t.Fatal(err)
	}
	id, params, ok := r.Resolve(registryWrap{input})
	if !ok || id != "signin.denied" || len(params) != 1 || params[0].Value.Int64 != 3 {
		t.Fatal("typed resolution lost identity/schema", id, ok)
	}
	params[0].Name = "changed"
	if input.params[0].Name != "attempts" {
		t.Fatal("result aliases originating error")
	}
	if err := r.Register("identity.test.other", "other", ParameterSchema{}); err == nil {
		t.Fatal("sealed registry changed")
	}
	if err := SealErrorRegistry(r); err != nil {
		t.Fatal("idempotent seal failed", err)
	}
	if _, _, ok := r.Resolve(errors.New("identity.test.denied")); ok {
		t.Fatal("error text guessed registered identity")
	}
}

func TestRegistryRejectsConflictingAndUnsafeDeclarations(t *testing.T) {
	r := NewErrorRegistry()
	if err := r.Register("identity.test.denied", "signin.denied", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("identity.test.denied", "signin.denied", ParameterSchema{}); err == nil {
		t.Fatal("duplicate owning registration accepted")
	}
	for _, tc := range []struct {
		identity ErrorIdentity
		message  MessageID
		schema   ParameterSchema
	}{
		{"", "message", ParameterSchema{}}, {"UPPER", "message", ParameterSchema{}}, {"id", "", ParameterSchema{}},
		{"id", MessageID(strings.Repeat("a", 129)), ParameterSchema{}},
		{"id", "message", ParameterSchema{Parameters: make([]ParameterSpec, 33)}},
		{"id", "message", ParameterSchema{Parameters: []ParameterSpec{{Name: "value", Kind: identity.AttributeStringList, Context: ParameterPlainText}}}},
		{"id", "message", ParameterSchema{Parameters: []ParameterSpec{{Name: "value", Kind: identity.AttributeString}}}},
		{"id", "message", ParameterSchema{Parameters: []ParameterSpec{{Name: "value", Kind: identity.AttributeString, Context: ParameterHTML}, {Name: "value", Kind: identity.AttributeString, Context: ParameterHTML}}}},
	} {
		if err := r.Register(tc.identity, tc.message, tc.schema); err == nil {
			t.Fatal("unsafe declaration admitted")
		}
	}
	var zero ErrorRegistry
	if err := zero.Register("id", "message", ParameterSchema{}); err == nil {
		t.Fatal("zero registry accepted")
	}
	if err := SealErrorRegistry(&zero); err == nil {
		t.Fatal("zero registry sealed")
	}
}

func TestRegistryValidatesExactParameterSchema(t *testing.T) {
	r := NewErrorRegistry()
	schema := ParameterSchema{Parameters: []ParameterSpec{{Name: "value", Kind: identity.AttributeString, Context: ParameterHTML}}}
	if err := r.Register("id", "message", schema); err != nil {
		t.Fatal(err)
	}
	if err := SealErrorRegistry(r); err != nil {
		t.Fatal(err)
	}
	valid := SafeParameter{Name: "value", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "<safe&>"}, Context: ParameterHTML}
	_, got, ok := r.Resolve(&registryError{identity: "id", params: []SafeParameter{valid}})
	if !ok || !reflect.DeepEqual(got, []SafeParameter{valid}) {
		t.Fatal("typed values changed or escaped")
	}
	variants := []SafeParameter{valid, valid, valid, valid, valid, valid}
	variants[0].Name = "other"
	variants[1].Context = ParameterPlainText
	variants[2].Value.Kind = identity.AttributeBool
	variants[3].Value.Bool = true
	variants[4].Value.String = strings.Repeat("x", 4097)
	variants[5].Value.String = string([]byte{255})
	for _, bad := range variants {
		if id, p, ok := r.Resolve(&registryError{identity: "id", params: []SafeParameter{bad}}); ok || id != "" || p != nil {
			t.Fatal("unsafe partial translation escaped")
		}
	}
	for _, params := range [][]SafeParameter{nil, {valid, valid}, make([]SafeParameter, 33)} {
		if _, _, ok := r.Resolve(&registryError{identity: "id", params: params}); ok {
			t.Fatal("missing/extra parameters admitted")
		}
	}
	if _, _, ok := r.Resolve(&registryError{identity: "unknown", params: []SafeParameter{valid}}); ok {
		t.Fatal("unknown identity translated")
	}
	if text := fmt.Sprintf("%+v %#+v", valid, schema); strings.Contains(text, "<safe&>") {
		t.Fatal("safe parameter leaked into diagnostics")
	}
}

func TestRegistryConcurrentSealedReads(t *testing.T) {
	r := NewErrorRegistry()
	if err := r.Register("id", "message", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	if err := SealErrorRegistry(r); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 32 {
				if id, _, ok := r.Resolve(&registryError{identity: "id"}); !ok || id != "message" {
					t.Error("sealed reads changed")
				}
			}
		}()
	}
	wg.Wait()
}

type registryCycle struct{}

func (e *registryCycle) Error() string { panic("never inspect") }
func (e *registryCycle) Unwrap() error { return e }

type registryPanic struct{ stage string }

func (e registryPanic) Error() string { panic("never inspect") }
func (e registryPanic) ErrorIdentity() ErrorIdentity {
	if e.stage == "identity" {
		panic("private diagnostic")
	}
	return "id"
}
func (e registryPanic) SafeParameters() []SafeParameter { panic("private diagnostic") }

type registryPanicWrap struct{}

func (registryPanicWrap) Error() string { panic("never inspect") }
func (registryPanicWrap) Unwrap() error { panic("private diagnostic") }

type registryCustomAs struct{}

type registryWide struct{}

func (registryWide) Error() string   { panic("never inspect") }
func (registryWide) Unwrap() []error { return make([]error, 33) }

func (registryCustomAs) Error() string { panic("never inspect") }
func (registryCustomAs) As(any) bool   { panic("custom As must never be called") }

func TestRegistryBoundsHostileWrappersAndCallbackFailures(t *testing.T) {
	r := NewErrorRegistry()
	if err := r.Register("id", "message", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	copy := *r
	if err := SealErrorRegistry(&copy); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{nil, &registryCycle{}, registryPanic{"identity"}, registryPanic{"parameters"}, registryPanicWrap{}, registryCustomAs{}, (*registryError)(nil), registryWide{}} {
		if id, p, ok := r.Resolve(err); id != "" || p != nil || ok {
			t.Fatal("hostile callback/wrapper translated")
		}
	}
	// A chain at the traversal limit resolves; one beyond it does not.
	var chain error = &registryError{identity: "id"}
	for range 31 {
		chain = registryWrap{chain}
	}
	if id, _, ok := r.Resolve(chain); !ok || id != "message" {
		t.Fatal("bounded wrapper did not resolve")
	}
	if _, _, ok := r.Resolve(registryWrap{chain}); ok {
		t.Fatal("traversal limit bypassed")
	}
	unknown := &registryError{identity: "unknown"}
	if _, _, ok := r.Resolve(errors.Join(unknown, &registryError{identity: "id"})); ok {
		t.Fatal("unknown typed owner bypassed")
	}
	if id, _, ok := r.Resolve(errors.Join(errors.New("opaque"), &registryError{identity: "id"})); !ok || id != "message" {
		t.Fatal("joined typed error not visited")
	}
}

func TestRegistryPreservesAllScalarValuesAndSchemaOrder(t *testing.T) {
	r := NewErrorRegistry()
	schema := ParameterSchema{Parameters: []ParameterSpec{{Name: "text", Kind: identity.AttributeString, Context: ParameterPlainText}, {Name: "flag", Kind: identity.AttributeBool, Context: ParameterJSON}, {Name: "count", Kind: identity.AttributeInt64, Context: ParameterHeader}, {Name: "when", Kind: identity.AttributeTime, Context: ParameterURL}}}
	if err := r.Register("id", "message", schema); err != nil {
		t.Fatal(err)
	}
	if err := SealErrorRegistry(r); err != nil {
		t.Fatal(err)
	}
	values := []SafeParameter{{Name: "when", Value: identity.AttributeScalar{Kind: identity.AttributeTime, Time: time.Unix(1, 0).UTC()}, Context: ParameterURL}, {Name: "count", Value: identity.AttributeScalar{Kind: identity.AttributeInt64}, Context: ParameterHeader}, {Name: "flag", Value: identity.AttributeScalar{Kind: identity.AttributeBool}, Context: ParameterJSON}, {Name: "text", Value: identity.AttributeScalar{Kind: identity.AttributeString}, Context: ParameterPlainText}}
	_, got, ok := r.Resolve(&registryError{identity: "id", params: values})
	if !ok || len(got) != 4 {
		t.Fatal("valid zero scalar values rejected")
	}
	for i, spec := range schema.Parameters {
		if got[i].Name != spec.Name {
			t.Fatal("schema order lost")
		}
	}
	for i := range values {
		bad := append([]SafeParameter(nil), values...)
		if bad[i].Value.Kind == identity.AttributeString {
			bad[i].Value.Time = time.Unix(1, 0)
		} else {
			bad[i].Value.String = "unexpected arm"
		}
		if _, _, ok := r.Resolve(&registryError{identity: "id", params: bad}); ok {
			t.Fatal("mixed scalar arms admitted")
		}
	}
	values[0].Value.Time = time.Time{}
	if _, _, ok := r.Resolve(&registryError{identity: "id", params: values}); ok {
		t.Fatal("zero time admitted")
	}
}

func TestRegistryRegistrationLimit(t *testing.T) {
	r := NewErrorRegistry()
	for i := range 10000 {
		if err := r.Register(ErrorIdentity(fmt.Sprintf("id%d", i)), "message", ParameterSchema{}); err != nil {
			t.Fatal("bounded registry rejected", i, err)
		}
	}
	if err := r.Register("overflow", "message", ParameterSchema{}); err == nil {
		t.Fatal("registry capacity bypassed")
	}
}

func FuzzRegistrySafeParameters(f *testing.F) {
	for _, seed := range []string{"", "plain", "<public&>", string([]byte{255}), strings.Repeat("a", 4097)} {
		f.Add(seed, false)
	}
	f.Fuzz(func(t *testing.T, value string, mixedArm bool) {
		r := NewErrorRegistry()
		if err := r.Register("id", "message", ParameterSchema{Parameters: []ParameterSpec{{Name: "text", Kind: identity.AttributeString, Context: ParameterHTML}}}); err != nil {
			t.Fatal(err)
		}
		if err := SealErrorRegistry(r); err != nil {
			t.Fatal(err)
		}
		input := []SafeParameter{{Name: "text", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: value, Bool: mixedArm}, Context: ParameterHTML}}
		id, got, ok := r.Resolve(&registryError{identity: "id", params: input})
		if !ok {
			if id != "" || got != nil {
				t.Fatal("partial value escaped")
			}
			return
		}
		if mixedArm || len(value) > 4096 || id != "message" || !reflect.DeepEqual(got, input) {
			t.Fatal("scalar/context changed or unsafe arms admitted")
		}
	})
}
