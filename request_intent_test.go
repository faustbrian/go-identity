package identity

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// RK-03: request identity must be fixed before generated code or command state.
func TestRequestIntentFreezesCanonicalTypedInput(t *testing.T) {
	when := time.Date(2026, 10, 7, 9, 0, 0, 123000, time.FixedZone("caller", 3600))
	input := []FeatureField{
		{Name: "target.digest", Value: FeatureValue{Kind: FeatureBytes, Bytes: []byte{1, 2, 3}}},
		{Name: "version", Value: FeatureValue{Kind: FeatureUint64, Uint64: math.MaxUint64}},
		{Name: "locale", Value: FeatureValue{Kind: FeatureText, Text: "日本語"}},
		{Name: "when", Value: FeatureValue{Kind: FeatureTime, Time: when}},
		{Name: "remember", Value: FeatureValue{Kind: FeatureBool}},
		{Name: "duration", Value: FeatureValue{Kind: FeatureInt64, Int64: math.MinInt64}},
	}
	intent, err := NewRequestIntent(input)
	if err != nil {
		t.Fatal("valid typed request rejected:", err)
	}
	fields, ok := intent.Fields()
	if !ok || len(fields) != len(input) {
		t.Fatal("missing frozen intent")
	}
	wantNames := []string{"duration", "locale", "remember", "target.digest", "version", "when"}
	for i, name := range wantNames {
		if fields[i].Name != name {
			t.Fatal("noncanonical ordering")
		}
	}
	if fields[4].Value.Uint64 != math.MaxUint64 || fields[0].Value.Int64 != math.MinInt64 || fields[5].Value.Time != when.UTC() {
		t.Fatal("lossy scalar normalization")
	}
	input[0].Value.Bytes[0] = 99
	input[1].Name = "changed"
	fields[3].Value.Bytes[1] = 99
	fields[1].Value.Text = "changed"
	again, ok := intent.Fields()
	if !ok || !reflect.DeepEqual(again[3].Value.Bytes, []byte{1, 2, 3}) || again[1].Value.Text != "日本語" || again[4].Name != "version" {
		t.Fatal("caller mutation changed retained intent")
	}
	reordered := []FeatureField{again[5], again[2], again[0], again[4], again[1], again[3]}
	other, err := NewRequestIntent(reordered)
	if err != nil {
		t.Fatal(err)
	}
	otherFields, _ := other.Fields()
	if !reflect.DeepEqual(again, otherFields) {
		t.Fatal("field order altered intent")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, intent), "日本語") {
			t.Fatal("intent diagnostic disclosure")
		}
	}
	if _, err := json.Marshal(intent); err == nil {
		t.Fatal("implicit request serialization permitted")
	}
	if bytes, err := intent.MarshalText(); err == nil || bytes != nil {
		t.Fatal("private intent text serialization")
	}
	if strings.Contains(intent.LogValue().String(), "日本語") {
		t.Fatal("private intent log disclosure")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				projection, ok := intent.Fields()
				if !ok || !reflect.DeepEqual(projection, again) {
					t.Error("concurrent intent mutation")
				}
				projection[3].Value.Bytes[0] = 99
			}
		})
	}
	wg.Wait()
}

// Private request scalars must stay hidden when fmt cannot dispatch Format.
func TestRequestIntentNestedDiagnostics(t *testing.T) {
	const private = "synthetic_private_request_marker"
	intent, err := NewRequestIntent([]FeatureField{{Name: "target", Value: FeatureValue{Kind: FeatureText, Text: private}}})
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		struct{ intent RequestIntent }{intent},
		&struct{ intent RequestIntent }{intent},
		struct{ intents []RequestIntent }{[]RequestIntent{intent}},
		struct{ intents [1]RequestIntent }{[1]RequestIntent{intent}},
		struct{ intents map[string]RequestIntent }{map[string]RequestIntent{"intent": intent}},
	}
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			formatted := fmt.Sprintf(verb, value)
			for _, encoding := range []string{private, fmt.Sprintf("%x", private), fmt.Sprintf("%X", private)} {
				if strings.Contains(formatted, encoding) {
					t.Fatalf("private request disclosed through %s", verb)
				}
			}
		}
	}
}

// RK-09: reject ambiguous unions and hostile input before copying/hashing.
func TestRequestIntentRejectsInvalidInput(t *testing.T) {
	valid := FeatureField{Name: "field", Value: FeatureValue{Kind: FeatureText, Text: "safe"}}
	for _, fields := range [][]FeatureField{
		{{Name: "Upper", Value: valid.Value}},
		{{Name: "a..b", Value: valid.Value}},
		{{Name: "", Value: valid.Value}},
		{valid, valid},
		{{Name: "field", Value: FeatureValue{Kind: FeatureText, Text: string([]byte{255})}}},
		{{Name: "field", Value: FeatureValue{Kind: FeatureBytes, Bytes: make([]byte, 8193)}}},
		{{Name: "field", Value: FeatureValue{Kind: FeatureBool, Text: "hidden"}}},
		{{Name: "field", Value: FeatureValue{Kind: FeatureTime, Time: time.Unix(0, 1)}}},
		{{Name: "field", Value: FeatureValue{Kind: FeatureKind(255)}}},
		make([]FeatureField, 129),
	} {
		intent, err := NewRequestIntent(fields)
		if err == nil {
			t.Fatal("invalid request accepted")
		}
		if _, ok := intent.Fields(); ok {
			t.Fatal("failure returned usable intent")
		}
	}
	var zero RequestIntent
	if _, ok := zero.Fields(); ok {
		t.Fatal("zero intent accepted")
	}
	empty, err := NewRequestIntent(nil)
	if err != nil {
		t.Fatal("valid empty input rejected")
	}
	if fields, ok := empty.Fields(); !ok || len(fields) != 0 {
		t.Fatal("empty request confused with zero")
	}
	explicit, err := NewRequestIntent([]FeatureField{{Name: "remember", Value: FeatureValue{Kind: FeatureBool}}})
	if err != nil {
		t.Fatal(err)
	}
	ef, _ := explicit.Fields()
	nf, _ := empty.Fields()
	if reflect.DeepEqual(ef, nf) {
		t.Fatal("absent and false collapsed")
	}
}

func TestRequestIntentBoundsBeforeCopy(t *testing.T) {
	fields := make([]FeatureField, 128)
	for i := range fields {
		fields[i] = FeatureField{Name: fmt.Sprintf("field%d", i), Value: FeatureValue{Kind: FeatureText}}
	}
	if _, err := NewRequestIntent(fields); err != nil {
		t.Fatal("maximum field count rejected")
	}
	for i := range fields {
		fields[i].Value.Text = strings.Repeat("x", 8192)
	}
	if _, err := NewRequestIntent(fields); err == nil {
		t.Fatal("aggregate byte budget bypassed")
	}
	if _, err := NewRequestIntent([]FeatureField{{Name: "field", Value: FeatureValue{Kind: FeatureText, Text: strings.Repeat("x", 8192)}}}); err != nil {
		t.Fatal("exact scalar bound rejected")
	}
}
