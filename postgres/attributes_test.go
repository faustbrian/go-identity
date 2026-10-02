package postgres

import (
	"bytes"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func storageSchema() identity.AttributeSchema {
	schema := identity.AttributeSchema{ID: "fields", Version: 1}
	for _, field := range []struct {
		name string
		kind identity.AttributeKind
	}{
		{"empty", identity.AttributeString}, {"flag", identity.AttributeBool}, {"minimum", identity.AttributeInt64}, {"maximum", identity.AttributeInt64}, {"when", identity.AttributeTime}, {"tags", identity.AttributeStringList},
	} {
		cardinality := identity.CardinalityScalar
		if field.kind == identity.AttributeStringList {
			cardinality = identity.CardinalityList
		}
		schema.Fields = append(schema.Fields, identity.FieldPolicy{Name: field.name, Kind: field.kind, Cardinality: cardinality, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteAdministrator, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1})
	}
	return schema
}

func storageValues() []identity.AttributeUpdate {
	scalar := func(name string, value identity.AttributeScalar) identity.AttributeUpdate {
		return identity.AttributeUpdate{Name: name, Value: identity.AttributeValue{Kind: value.Kind, Scalar: value}}
	}
	return []identity.AttributeUpdate{
		scalar("empty", identity.AttributeScalar{Kind: identity.AttributeString}),
		scalar("flag", identity.AttributeScalar{Kind: identity.AttributeBool}),
		scalar("minimum", identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: math.MinInt64}),
		scalar("maximum", identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: math.MaxInt64}),
		scalar("when", identity.AttributeScalar{Kind: identity.AttributeTime, Time: time.Date(2026, 10, 2, 12, 1, 2, 3000, time.UTC)}),
		{Name: "tags", Value: identity.AttributeValue{Kind: identity.AttributeStringList, List: []identity.AttributeScalar{}}},
	}
}

func TestAttributeStorageLosslessAndCanonical(t *testing.T) {
	schema := storageSchema()
	values := storageValues()
	spec := identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: values}
	encoded, err := encodeStoredAttributes(spec, schema)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeStoredAttributes(spec.Binding, schema, encoded)
	if err != nil || !reflect.DeepEqual(decoded, values) {
		t.Fatal("typed values did not survive canonical storage")
	}
	decoded[0].Value.Scalar.String = "changed"
	again, err := decodeStoredAttributes(spec.Binding, schema, encoded)
	if err != nil || !reflect.DeepEqual(again, values) {
		t.Fatal("decode retained caller state")
	}
	if _, err := decodeStoredAttributes(spec.Binding, schema, append(bytes.Clone(encoded), 0)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := encodeStoredAttributes(identity.CreateUserCommand{Binding: spec.Binding, Status: spec.Status, Attributes: []identity.AttributeUpdate{{Name: "unknown", Value: values[0].Value}}}, schema); err == nil {
		t.Fatal("undeclared value stored")
	}
}

func TestAttributeSchemasOwnPolicyAndDefaults(t *testing.T) {
	schema := storageSchema()
	schema.Fields[5].Default = identity.AttributeValue{Kind: identity.AttributeStringList, List: []identity.AttributeScalar{{Kind: identity.AttributeString, String: "default"}}}
	frozen, err := freezeAttributeSchemas([]identity.AttributeSchema{schema})
	if err != nil {
		t.Fatal(err)
	}
	schema.Fields[5].Default.List[0].String = "changed"
	schema.Fields[0].Name = "changed"
	registered := frozen[schemaKey{"fields", 1}]
	if registered.schema.Fields[0].Name != "empty" || registered.schema.Fields[5].Default.List[0].String != "default" {
		t.Fatal("schema retained caller aliases")
	}
	if _, err := freezeAttributeSchemas([]identity.AttributeSchema{storageSchema(), storageSchema()}); err == nil {
		t.Fatal("duplicate declaration accepted")
	}
	for _, profile := range []string{"indexed", "secret", "wrong version"} {
		invalid := storageSchema()
		switch profile {
		case "indexed":
			invalid.Fields[0].Indexed = true
		case "secret":
			invalid.Fields[0].Sensitivity = identity.SensitivitySecret
			invalid.Fields[0].OutputPermission = identity.FieldDenied
		case "wrong version":
			invalid.Fields[0].MigrationVersion = 2
		}
		if _, err := freezeAttributeSchemas([]identity.AttributeSchema{invalid}); err == nil {
			t.Fatal("unsupported profile accepted", profile)
		}
	}
}

func TestAttributeStorageBoundsAndInactiveArms(t *testing.T) {
	schema := storageSchema()
	for _, value := range []identity.AttributeValue{
		{Kind: identity.AttributeBool, Scalar: identity.AttributeScalar{Kind: identity.AttributeBool, String: "inactive"}},
		{Kind: identity.AttributeStringList},
		{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: strings.Repeat("x", 4097)}},
		{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime, Time: time.Unix(1, 1)}},
	} {
		name := "empty"
		if value.Kind == identity.AttributeBool {
			name = "flag"
		}
		if value.Kind == identity.AttributeStringList {
			name = "tags"
		}
		if value.Kind == identity.AttributeTime {
			name = "when"
		}
		if _, err := encodeStoredAttributes(identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: []identity.AttributeUpdate{{Name: name, Value: value}}}, schema); err == nil {
			t.Fatal("invalid selected value stored")
		}
	}
	if _, err := decodeStoredAttributes(codecBinding(), schema, make([]byte, maxStoredAttributeBytes+1)); err == nil {
		t.Fatal("unbounded document accepted")
	}
	for _, bad := range [][]byte{nil, {0x82, 0x18, 1, 0x80}, {0x82, 1, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0x9f, 1, 0x80, 0xff}} {
		if _, err := decodeStoredAttributes(codecBinding(), schema, bad); err == nil {
			t.Fatal("noncanonical or hostile document accepted")
		}
	}
}

func FuzzStoredAttributes(f *testing.F) {
	schema := storageSchema()
	valid, err := encodeStoredAttributes(identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: storageValues()}, schema)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{0x82, 1, 0x80})
	f.Add([]byte{0x82, 1, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		values, err := decodeStoredAttributes(codecBinding(), schema, input)
		if err != nil {
			if values != nil {
				t.Fatal("failed decode disclosed a prefix")
			}
			return
		}
		encoded, err := encodeStoredAttributes(identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: values}, schema)
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("accepted noncanonical document")
		}
	})
}
