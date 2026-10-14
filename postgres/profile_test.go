package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

var _ identity.ProfileRepository = (*Repository)(nil)

func TestProfileZeroRepository(t *testing.T) {
	for _, repo := range []*Repository{nil, {}} {
		if record, err := repo.GetProfile(context.Background(), identity.ProfileQuery{}); err == nil || record.User != (identity.User{}) || record.Profile.ID != "" || len(record.Profile.AdditionalFields) != 0 {
			t.Fatal("invalid repository disclosed profile")
		}
	}
}

func TestProfileSchemaSelectionAndProjection(t *testing.T) {
	schema := storageSchema()
	schema.Fields[0].OutputPermission = identity.FieldDenied
	schemas, err := freezeAttributeSchemas([]identity.AttributeSchema{schema})
	if err != nil {
		t.Fatal(err)
	}
	if key, err := selectProfileSchema(ProfileSchemaRef{ID: "fields", Version: 1}, schemas); err != nil || key != (schemaKey{"fields", 1}) {
		t.Fatal("explicit schema not selected", err)
	}
	for _, ref := range []ProfileSchemaRef{{ID: "fields"}, {Version: 1}, {ID: "unknown", Version: 1}, {ID: "fields", Version: 2}} {
		if _, err := selectProfileSchema(ref, schemas); err == nil {
			t.Fatal("missing schema selected")
		}
	}
	if fields, err := profileFields(nil, schema); err != nil || len(fields) != 10 {
		t.Fatal("default projection admitted output-denied field", err)
	}
	for _, fields := range [][]identity.FieldName{{{Value: "empty"}}, {{Value: "unknown"}}, {{Value: "name"}, {Value: "name"}}, make([]identity.FieldName, 129)} {
		if _, err := profileFields(fields, schema); err == nil {
			t.Fatal("invalid field projection admitted")
		}
	}
	for _, name := range []string{"name", "image", "email", "role", "password", "credentials"} {
		bad := storageSchema()
		bad.Fields[0].Name = name
		frozen, err := freezeAttributeSchemas([]identity.AttributeSchema{bad})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := selectProfileSchema(ProfileSchemaRef{ID: "fields", Version: 1}, frozen); err == nil {
			t.Fatal("privileged/core field aliased in profile", name)
		}
	}
}
