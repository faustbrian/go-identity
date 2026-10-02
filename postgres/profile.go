package postgres

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

// ProfileSchemaRef explicitly selects one frozen AttributeSchemas declaration
// for GetProfile. Both ID and Version must be present or both zero (disabled).
// This is storage configuration, not permission or schema migration authority.
type ProfileSchemaRef struct {
	ID      string
	Version uint32
}

func selectProfileSchema(ref ProfileSchemaRef, schemas map[schemaKey]registeredSchema) (schemaKey, error) {
	if ref == (ProfileSchemaRef{}) {
		return schemaKey{}, nil
	}
	key := schemaKey{ref.ID, ref.Version}
	registered, ok := schemas[key]
	if !ok || len(registered.schema.Fields) > 123 {
		return schemaKey{}, invalidProfileQuery()
	}
	for _, field := range registered.schema.Fields {
		if reservedProfileField(field.Name) {
			return schemaKey{}, invalidProfileQuery()
		}
	}
	return key, nil
}

func reservedProfileField(name string) bool {
	switch name {
	case "id", "tenant_id", "version", "name", "image", "email", "email_verified", "phone", "phone_verified", "username", "status", "role", "roles", "password", "credentials":
		return true
	}
	return false
}

// GetProfile implements the existing primary ProfileRepository port. One SQL
// statement observes the structural user, optional name/image and exact typed
// attribute document as one aggregate snapshot. It never fabricates defaults
// for old structural users or guesses a stored schema version. The selected
// ProfileSchema and immutable stored definition must agree exactly; corrupt or
// incompatible documents return Unavailable with no partial profile.
//
// Empty Fields selects all output-readable fields. Explicit fields must be
// unique, known and output-readable, at most 128. ID, tenant and version always
// identify the returned snapshot; name/image and attributes are selected only
// when requested. Full stored values are validated before subset projection.
// Returned lists own their memory. No pool ownership, callback, transaction,
// cache or background work is retained. Earlier caller deadlines win.
//
// This trusted storage port confers no human, tenant or read authority. Compose
// ProfileService for current-subject/active-state authorization, field redaction
// and image-origin policy. Stored images are never fetched or trusted as URLs.
// Profile writes and lifecycle/privacy erasure remain separate domain work.
func (r *Repository) GetProfile(ctx context.Context, q identity.ProfileQuery) (record identity.ProfileRecord, err error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || r.maximumDuration <= 0 || r.maximumDuration > time.Minute {
		return record, invalidProfileQuery()
	}
	registered, ok := r.attributeSchemas[r.profileSchema]
	shape := identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 1}
	if !ok || shape.Validate(q.TenantID) != nil {
		return record, invalidProfileQuery()
	}
	fields, err := profileFields(q.Fields, registered.schema)
	if err != nil {
		return record, err
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return record, readFailure(bounded, err)
	}
	var tenant, user, status, version string
	var name, image, schemaID, schemaVersion pgtype.Text
	var encoding pgtype.Int2
	var document, definition []byte
	err = r.pool.Raw().QueryRow(bounded, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,
 p.name,p.image,a.schema_id,a.schema_version::text,a.encoding_version,a.document,s.definition
 FROM identity.users u
 LEFT JOIN identity.user_profiles p USING(tenant_id,user_id)
 LEFT JOIN identity.user_attributes a USING(tenant_id,user_id)
 LEFT JOIN identity.attribute_schemas s ON s.tenant_id=a.tenant_id AND s.schema_id=a.schema_id AND s.schema_version=a.schema_version
 WHERE u.tenant_id=$1 AND u.user_id=$2`, string(q.TenantID), string(q.UserID)).Scan(&tenant, &user, &status, &version, &name, &image, &schemaID, &schemaVersion, &encoding, &document, &definition)
	if err != nil {
		return record, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return record, readFailure(bounded, err)
	}
	number, err := strconv.ParseUint(version, 10, 64)
	structural := identity.User{ID: identity.UserID(user), TenantID: identity.TenantID(tenant), Status: identity.Status(status), Version: number}
	if err != nil || strconv.FormatUint(number, 10) != version || structural.ID != q.UserID || structural.Validate(q.TenantID) != nil || name.Valid != image.Valid || len(name.String) > 256 || len(image.String) > 2048 || !utf8.ValidString(name.String) || !utf8.ValidString(image.String) {
		return record, identity.UnavailableError{}
	}
	var values []identity.AttributeUpdate
	if schemaID.Valid {
		if schemaID.String != r.profileSchema.id || schemaVersion.String != strconv.FormatUint(uint64(r.profileSchema.version), 10) || !schemaVersion.Valid || !encoding.Valid || encoding.Int16 != 1 || !bytes.Equal(definition, registered.definition) {
			return record, identity.UnavailableError{}
		}
		values, err = decodeAttributeDocument(registered.schema, document)
		if err != nil {
			return record, identity.UnavailableError{}
		}
	} else if schemaVersion.Valid || encoding.Valid || len(document) != 0 || len(definition) != 0 {
		return record, identity.UnavailableError{}
	}
	profile := identity.UserProfile{ID: structural.ID, TenantID: structural.TenantID, Version: structural.Version}
	if slices.Contains(fields, "name") {
		profile.Name = name.String
	}
	if slices.Contains(fields, "image") {
		profile.Image = image.String
	}
	for _, value := range values {
		if slices.Contains(fields, value.Name) {
			profile.AdditionalFields = append(profile.AdditionalFields, value)
		}
	}
	if err := bounded.Err(); err != nil {
		return record, readFailure(bounded, err)
	}
	return identity.ProfileRecord{User: structural, Profile: profile}, nil
}

func profileFields(input []identity.FieldName, schema identity.AttributeSchema) ([]string, error) {
	available := []string{"id", "tenant_id", "version", "name", "image"}
	for _, field := range schema.Fields {
		if field.OutputPermission == identity.FieldRead || field.OutputPermission == identity.FieldReadWrite {
			available = append(available, field.Name)
		}
	}
	if len(input) == 0 {
		return available, nil
	}
	if len(input) > 128 {
		return nil, invalidProfileQuery()
	}
	fields := make([]string, len(input))
	for i, field := range input {
		if !slices.Contains(available, field.Value) || slices.Contains(fields[:i], field.Value) {
			return nil, invalidProfileQuery()
		}
		fields[i] = field.Value
	}
	return fields, nil
}

func invalidProfileQuery() error { return identity.InvalidInputError{Field: "profile_query"} }
