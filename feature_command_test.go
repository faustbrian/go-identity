package identity_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func featureCommandSpec() identity.FeatureCommandSpec {
	return identity.FeatureCommandSpec{Binding: featureBinding(), Operation: featureOperation(), Fields: []identity.FeatureField{
		{Name: "authority.user-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: math.MaxUint64}},
		{Name: "policy.remember", Value: identity.FeatureValue{Kind: identity.FeatureBool}},
		{Name: "proof.record-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1, 2, 3}}},
		{Name: "policy.label", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "private-feature-value"}},
		{Name: "policy.duration-us", Value: identity.FeatureValue{Kind: identity.FeatureInt64, Int64: -1}},
		{Name: "proof.authenticated-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Date(2026, 10, 3, 0, 0, 0, 1000, time.FixedZone("example", 3600))}},
	}}
}

func TestFeatureCommandExactPayloadBudget(t *testing.T) {
	s := featureCommandSpec()
	s.Fields = make([]identity.FeatureField, 32)
	used := 0
	for i := range s.Fields {
		name := fmt.Sprintf("input.i%d", i)
		s.Fields[i] = identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: make([]byte, 8192)}}
		used += len(name) + 1 + 8192
	}
	last := &s.Fields[31].Value.Bytes
	*last = (*last)[:8192-(used-(256<<10))]
	if _, e := identity.NewFeatureCommand(s); e != nil {
		t.Fatal("exact byte budget rejected", e)
	}
	*last = append(*last, 0)
	if _, e := identity.NewFeatureCommand(s); e == nil {
		t.Fatal("one byte beyond budget accepted")
	}
}

func FuzzFeatureCommand(f *testing.F) {
	f.Add("input.value", uint8(identity.FeatureBytes), []byte{1, 2}, uint64(0))
	f.Add("input.value", uint8(identity.FeatureText), []byte("value"), uint64(0))
	f.Add("input.value", uint8(identity.FeatureUint64), []byte{}, uint64(math.MaxUint64))
	f.Add("bad..field", uint8(99), []byte{}, uint64(0))
	f.Fuzz(func(t *testing.T, name string, kind uint8, data []byte, number uint64) {
		s := featureCommandSpec()
		v := identity.FeatureValue{Kind: identity.FeatureKind(kind)}
		switch v.Kind {
		case identity.FeatureBytes:
			v.Bytes = data
		case identity.FeatureText:
			if len(data) > 16384 {
				return // bound fixture conversion; deterministic tests cover 8193
			}
			v.Text = string(data)
		case identity.FeatureUint64:
			v.Uint64 = number
		case identity.FeatureInt64:
			v.Int64 = int64(number)
		case identity.FeatureBool:
			v.Bool = number != 0
		case identity.FeatureTime:
			v.Time = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
		}
		s.Fields = []identity.FeatureField{{Name: name, Value: v}}
		c, e := identity.NewFeatureCommand(s)
		if e != nil {
			return
		}
		got, ok := c.Feature()
		value := got.Fields[0].Value
		if !ok || got.Fields[0].Name != name || value.Kind != v.Kind || value.Text != v.Text || !bytes.Equal(value.Bytes, v.Bytes) || value.Uint64 != v.Uint64 || value.Int64 != v.Int64 || value.Bool != v.Bool || !value.Time.Equal(v.Time) {
			t.Fatal("validated named input changed")
		}
	})
}

func TestFeatureCommandFreezesNamedTypedPayload(t *testing.T) {
	spec := featureCommandSpec()
	command, e := identity.NewFeatureCommand(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec.Fields[2].Value.Bytes[0] = 99
	spec.Fields[3].Value.Text = "changed"
	spec.Binding.RecordID = "changed"
	spec.Operation.SchemaVersion++
	got, ok := command.Feature()
	if !ok || got.Binding != featureBinding() || got.Operation != featureOperation() {
		t.Fatal("caller changed retained scope")
	}
	for i, field := range got.Fields {
		if i > 0 && got.Fields[i-1].Name >= field.Name {
			t.Fatal("named fields not canonical")
		}
		switch field.Value.Kind {
		case identity.FeatureUint64:
			if field.Value.Uint64 != math.MaxUint64 {
				t.Fatal("unsigned authority version lost")
			}
		case identity.FeatureBytes:
			if field.Value.Bytes[0] != 1 {
				t.Fatal("input bytes alias retained state")
			}
			field.Value.Bytes[0] = 88
		case identity.FeatureText:
			if field.Value.Text != "private-feature-value" {
				t.Fatal("input text changed retained state")
			}
		case identity.FeatureTime:
			if field.Value.Time.Location() != time.UTC || !field.Value.Time.Equal(featureCommandSpec().Fields[5].Value.Time) {
				t.Fatal("timestamp instant not preserved")
			}
		}
	}
	got.Fields[0].Name = "changed"
	retained, _ := command.Feature()
	if retained.Fields[0].Name != "authority.user-version" || retained.Fields[5].Value.Bytes[0] != 1 {
		t.Fatal("returned projection changed retained state")
	}
	if _, ok := command.CreateUser(); ok {
		t.Fatal("feature entered kernel creation variant")
	}
	if _, ok := (identity.Command{}).Feature(); ok {
		t.Fatal("zero command became feature")
	}
	for _, value := range []any{command, struct{ command identity.Command }{command}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
			if strings.Contains(fmt.Sprintf(verb, value), "private-feature-value") {
				t.Fatal("command formatting exposed payload")
			}
		}
	}
	if _, e := json.Marshal(command); e == nil {
		t.Fatal("command implicitly serialized")
	}
}

func TestFeatureCommandRejectsAmbiguousAndUnboundedPayload(t *testing.T) {
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.SchemaVersion++ },
		func(s *identity.FeatureCommandSpec) { s.Fields = make([]identity.FeatureField, 129) },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "" },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "bad..field" },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = s.Fields[1].Name },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Kind = 0 },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Kind = 99 },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Text = "hidden" },
		func(s *identity.FeatureCommandSpec) { s.Fields[1].Value.Int64 = 1 },
		func(s *identity.FeatureCommandSpec) { s.Fields[2].Value.Uint64 = 1 },
		func(s *identity.FeatureCommandSpec) { s.Fields[3].Value.Bool = true },
		func(s *identity.FeatureCommandSpec) { s.Fields[4].Value.Bytes = []byte{} },
		func(s *identity.FeatureCommandSpec) { s.Fields[5].Value.Time = time.Time{} },
		func(s *identity.FeatureCommandSpec) {
			s.Fields[5].Value.Time = s.Fields[5].Value.Time.Add(time.Nanosecond)
		},
		func(s *identity.FeatureCommandSpec) {
			s.Fields[5].Value.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		func(s *identity.FeatureCommandSpec) { s.Fields[3].Value.Text = "\xff" },
		func(s *identity.FeatureCommandSpec) { s.Fields[3].Value.Text = strings.Repeat("a", 8193) },
		func(s *identity.FeatureCommandSpec) { s.Fields[2].Value.Bytes = make([]byte, 8193) },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = make([]identity.FeatureField, 128)
			for i := range s.Fields {
				s.Fields[i] = identity.FeatureField{Name: fmt.Sprintf("input.i%d", i), Value: identity.FeatureValue{Kind: identity.FeatureText, Text: strings.Repeat("a", 8192)}}
			}
		},
	} {
		s := featureCommandSpec()
		change(&s)
		if _, e := identity.NewFeatureCommand(s); e == nil {
			t.Fatal("malformed feature payload accepted")
		}
	}
	for _, value := range []identity.FeatureValue{
		{Kind: identity.FeatureText}, {Kind: identity.FeatureBytes},
		{Kind: identity.FeatureUint64}, {Kind: identity.FeatureInt64}, {Kind: identity.FeatureBool},
	} {
		s := featureCommandSpec()
		s.Fields = []identity.FeatureField{{Name: "input.zero", Value: value}}
		if _, e := identity.NewFeatureCommand(s); e != nil {
			t.Fatal("explicit zero scalar rejected", e)
		}
	}
	s := featureCommandSpec()
	s.Fields = nil
	if _, e := identity.NewFeatureCommand(s); e != nil {
		t.Fatal("explicit empty named payload rejected", e)
	}
}
