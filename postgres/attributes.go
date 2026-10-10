package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"slices"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// The private stored profile preserves explicit zero/empty values without JSON
// number conversion or escaping amplification. Its closed, nonrecursive CBOR
// grammar shares the existing command scalar encoding, not secret fingerprints.
// Stored bytes are private persistence, never diagnostics or public projections.
const maxStoredAttributeBytes = 512 << 10

type schemaKey struct {
	id      string
	version uint32
}
type registeredSchema struct {
	schema     identity.AttributeSchema
	definition []byte
}

func freezeAttributeSchemas(input []identity.AttributeSchema) (map[schemaKey]registeredSchema, error) {
	if len(input) > 32 {
		return nil, attributeStorageError()
	}
	result := make(map[schemaKey]registeredSchema, len(input))
	for _, schema := range input {
		if schema.Validate() != nil {
			return nil, attributeStorageError()
		}
		key := schemaKey{schema.ID, schema.Version}
		if _, duplicate := result[key]; duplicate {
			return nil, attributeStorageError()
		}
		schema.Fields = slices.Clone(schema.Fields)
		fields := make([][]byte, len(schema.Fields))
		for i, field := range schema.Fields {
			if field.Indexed || field.Sensitivity == identity.SensitivitySecret {
				return nil, attributeStorageError()
			}
			schema.Fields[i].Default.List = slices.Clone(field.Default.List)
			item := map[string][]byte{
				"name": cborText(field.Name), "kind": cborText(string(field.Kind)), "cardinality": cborText(string(field.Cardinality)),
				"normalization": cborText(string(field.Normalization)), "input": cborText(string(field.InputPermission)), "output": cborText(string(field.OutputPermission)),
				"write": cborText(string(field.WriteAuthorization)), "sensitivity": cborText(string(field.Sensitivity)), "migration": cborUint(uint64(field.MigrationVersion)),
			}
			if field.Default.Kind != "" {
				value, err := encodeAttribute(field.Default)
				if err != nil {
					return nil, attributeStorageError()
				}
				item["default"] = value
			}
			fields[i] = cborMap(item)
		}
		definition := cborMap(map[string][]byte{"profile": cborUint(1), "id": cborText(schema.ID), "version": cborUint(uint64(schema.Version)), "fields": cborArray(fields)})
		if len(definition) > maxStoredAttributeBytes {
			return nil, attributeStorageError()
		}
		result[key] = registeredSchema{schema: schema, definition: definition}
	}
	return result, nil
}

func (r *Repository) prepareCreationAttributes(spec identity.CreateUserCommand) (registeredSchema, []byte, error) {
	registered, ok := r.attributeSchemas[schemaKey{spec.Binding.SchemaID, spec.Binding.SchemaVersion}]
	if !ok {
		if len(spec.Attributes) == 0 {
			return registeredSchema{}, nil, nil
		}
		return registeredSchema{}, nil, attributeStorageError()
	}
	encoded, err := encodeStoredAttributes(spec, registered.schema)
	return registered, encoded, err
}

func persistCreationSchema(ctx context.Context, w Work, registered registeredSchema) error {
	if _, err := w.Exec(ctx, `INSERT INTO identity.attribute_schemas(tenant_id,schema_id,schema_version,definition) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, string(w.state.binding.TenantID), registered.schema.ID, registered.schema.Version, registered.definition); err != nil {
		return err
	}
	return checkCreationSchema(ctx, w, registered, false)
}

// An uninstalled declaration is valid for a prospective creation, but an
// existing version must agree even when the command creates no account.
// Callers hold the tenant fence; the shared read lock protects existing rows.
func checkCreationSchema(ctx context.Context, w Work, registered registeredSchema, allowAbsent bool) error {
	rows, err := w.Query(ctx, `SELECT definition FROM identity.attribute_schemas WHERE tenant_id=$1 AND schema_id=$2 AND schema_version=$3 FOR SHARE`, string(w.state.binding.TenantID), registered.schema.ID, registered.schema.Version)
	if err != nil {
		return err
	}
	defer rows.Close()
	var definition []byte
	if !rows.Next() {
		if allowAbsent && rows.Err() == nil {
			return nil
		}
		return w.fail(ctx, attributeStorageError())
	}
	if err := rows.Scan(&definition); err != nil {
		return err
	}
	if rows.Next() {
		return w.fail(ctx, attributeStorageError())
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !bytes.Equal(definition, registered.definition) {
		return w.fail(ctx, identity.ConflictError{})
	}
	return nil
}

func encodeStoredAttributes(spec identity.CreateUserCommand, schema identity.AttributeSchema) ([]byte, error) {
	if schema.Validate() != nil || spec.Binding.SchemaID != schema.ID || spec.Binding.SchemaVersion != schema.Version {
		return nil, attributeStorageError()
	}
	command, err := identity.NewUserCreationCommand(spec)
	if err != nil {
		return nil, attributeStorageError()
	}
	// The constructor owns shape/size validation and the private payload copy.
	spec, _ = command.CreateUser()
	return encodeAttributeDocument(schema, spec.Attributes)
}

// Reuse the public schema's intrinsic value and aggregate payload validation
// without fabricating command/actor authority for a primary read.
func encodeAttributeDocument(schema identity.AttributeSchema, values []identity.AttributeUpdate) ([]byte, error) {
	if len(values) > 128 || schema.Validate() != nil {
		return nil, attributeStorageError()
	}
	schema.Fields = slices.Clone(schema.Fields)
	for i := range schema.Fields {
		schema.Fields[i].Default = identity.AttributeValue{}
	}
	for i, value := range values {
		for _, previous := range values[:i] {
			if previous.Name == value.Name {
				return nil, attributeStorageError()
			}
		}
		found := false
		for j, field := range schema.Fields {
			if field.Name == value.Name {
				schema.Fields[j].Default = value.Value
				found = true
				break
			}
		}
		if !found {
			return nil, attributeStorageError()
		}
	}
	if schema.Validate() != nil {
		return nil, attributeStorageError()
	}
	entries := make([][]byte, len(values))
	for i, update := range values {
		admitted := false
		for _, field := range schema.Fields {
			if field.Name == update.Name {
				// These profiles require explicit index migrations or secret-envelope;
				// never silently store a secret in the ordinary scalar document.
				admitted = field.Kind == update.Value.Kind && !field.Indexed && field.Sensitivity != identity.SensitivitySecret && (field.InputPermission == identity.FieldWrite || field.InputPermission == identity.FieldReadWrite)
				break
			}
		}
		if !admitted {
			return nil, attributeStorageError()
		}
		value, err := encodeAttribute(update.Value)
		if err != nil {
			return nil, attributeStorageError()
		}
		entries[i] = cborArray([][]byte{cborText(update.Name), value})
	}
	encoded := cborArray([][]byte{cborUint(1), cborArray(entries)})
	if len(encoded) > maxStoredAttributeBytes {
		return nil, attributeStorageError()
	}
	return encoded, nil
}

func decodeStoredAttributes(binding identity.CommandBinding, schema identity.AttributeSchema, encoded []byte) ([]identity.AttributeUpdate, error) {
	values, err := decodeAttributeDocument(schema, encoded)
	if err != nil {
		return nil, err
	}
	if _, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: binding, Status: identity.StatusActive, Attributes: values}); err != nil {
		return nil, attributeStorageError()
	}
	return values, nil
}

func decodeAttributeDocument(schema identity.AttributeSchema, encoded []byte) ([]identity.AttributeUpdate, error) {
	if len(encoded) == 0 || len(encoded) > maxStoredAttributeBytes {
		return nil, attributeStorageError()
	}
	reader := attributeReader{data: encoded}
	if !reader.exact(4, 2) || !reader.exact(0, 1) {
		return nil, attributeStorageError()
	}
	count, ok := reader.head(4)
	if !ok || count > 128 {
		return nil, attributeStorageError()
	}
	values := make([]identity.AttributeUpdate, int(count))
	for i := range values {
		if !reader.exact(4, 2) {
			return nil, attributeStorageError()
		}
		name, ok := reader.text(128)
		if !ok || !reader.exact(5, 2) {
			return nil, attributeStorageError()
		}
		key, ok := reader.text(4)
		if !ok || key != "kind" {
			return nil, attributeStorageError()
		}
		kind, ok := reader.text(16)
		if !ok {
			return nil, attributeStorageError()
		}
		key, ok = reader.text(5)
		if !ok || key != "value" {
			return nil, attributeStorageError()
		}
		value, ok := reader.value(identity.AttributeKind(kind))
		if !ok {
			return nil, attributeStorageError()
		}
		values[i] = identity.AttributeUpdate{Name: name, Value: value}
	}
	if len(reader.data) != 0 {
		return nil, attributeStorageError()
	}
	canonical, err := encodeAttributeDocument(schema, values)
	// Reject duplicate names, nonminimal heads and every alternative spelling.
	if err != nil || !bytes.Equal(encoded, canonical) {
		return nil, attributeStorageError()
	}
	return values, nil
}

// Every count/length is checked before conversion or allocation. Only this
// fixed grammar is accepted: no tags, floats, indefinite items or recursion.
type attributeReader struct{ data []byte }

func (r *attributeReader) head(major byte) (uint64, bool) {
	if len(r.data) == 0 || r.data[0]>>5 != major {
		return 0, false
	}
	first := r.data[0] & 31
	r.data = r.data[1:]
	if first < 24 {
		return uint64(first), true
	}
	var size int
	switch first {
	case 24:
		size = 1
	case 25:
		size = 2
	case 26:
		size = 4
	case 27:
		size = 8
	default:
		return 0, false
	}
	if len(r.data) < size {
		return 0, false
	}
	var value uint64
	switch size {
	case 1:
		value = uint64(r.data[0])
	case 2:
		value = uint64(binary.BigEndian.Uint16(r.data))
	case 4:
		value = uint64(binary.BigEndian.Uint32(r.data))
	case 8:
		value = binary.BigEndian.Uint64(r.data)
	}
	r.data = r.data[size:]
	return value, true
}
func (r *attributeReader) exact(major byte, want uint64) bool {
	value, ok := r.head(major)
	return ok && value == want
}
func (r *attributeReader) text(max uint64) (string, bool) {
	size, ok := r.head(3)
	if !ok || size > max || size > uint64(len(r.data)) {
		return "", false
	}
	value := r.data[:int(size)]
	if !utf8.Valid(value) {
		return "", false
	}
	r.data = r.data[int(size):]
	return string(value), true
}
func (r *attributeReader) integer() (int64, bool) {
	if len(r.data) == 0 {
		return 0, false
	}
	major := r.data[0] >> 5
	if major > 1 {
		return 0, false
	}
	value, ok := r.head(major)
	if !ok || value > math.MaxInt64 {
		return 0, false
	}
	if major == 1 {
		return -int64(value) - 1, true
	}
	return int64(value), true
}
func (r *attributeReader) value(kind identity.AttributeKind) (identity.AttributeValue, bool) {
	value := identity.AttributeValue{Kind: kind, Scalar: identity.AttributeScalar{Kind: kind}}
	switch kind {
	case identity.AttributeString:
		text, ok := r.text(4096)
		value.Scalar.String = text
		return value, ok
	case identity.AttributeBool:
		if len(r.data) == 0 || (r.data[0] != 0xf4 && r.data[0] != 0xf5) {
			return identity.AttributeValue{}, false
		}
		value.Scalar.Bool = r.data[0] == 0xf5
		r.data = r.data[1:]
		return value, true
	case identity.AttributeInt64:
		number, ok := r.integer()
		value.Scalar.Int64 = number
		return value, ok
	case identity.AttributeTime:
		instant, ok := r.integer()
		if !ok {
			return identity.AttributeValue{}, false
		}
		value.Scalar.Time = time.UnixMicro(instant).UTC()
		return value, postgresExactTime(value.Scalar.Time)
	case identity.AttributeStringList:
		count, ok := r.head(4)
		if !ok || count > 64 {
			return identity.AttributeValue{}, false
		}
		value.Scalar = identity.AttributeScalar{}
		value.List = make([]identity.AttributeScalar, int(count))
		for i := range value.List {
			text, ok := r.text(4096)
			if !ok {
				return identity.AttributeValue{}, false
			}
			value.List[i] = identity.AttributeScalar{Kind: identity.AttributeString, String: text}
		}
		return value, true
	default:
		return identity.AttributeValue{}, false
	}
}

func attributeStorageError() error { return identity.InvalidInputError{Field: "attribute_storage"} }
