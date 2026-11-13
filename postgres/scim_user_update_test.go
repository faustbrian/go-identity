package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func scimUpdateIntentFixture(operation string) SCIMUserUpdateIntent {
	b := codecBinding()
	b.OperationID, b.SchemaID, b.RecordID = operation, operation+".native-v1", "scim-resource"
	b.ActorKind = authorization.SubjectServiceAccount
	return SCIMUserUpdateIntent{Binding: b, SchemaID: "fields", SchemaVersion: 1, ExpectedVersion: 17, Attributes: storageValues()[:1]}
}

func TestSCIMUserUpdateFieldsBindTypedInput(t *testing.T) {
	for _, operation := range []string{"identity.scim.user-replace", "identity.scim.user-patch"} {
		t.Run(operation, func(t *testing.T) {
			intent := scimUpdateIntentFixture(operation)
			schema := storageSchema()
			schema.Fields[0].WriteAuthorization = identity.FieldWriteSystem
			fields, err := SCIMUserUpdateFields(intent, schema)
			if err != nil || len(fields) != 5 {
				t.Fatal("real SCIM typed update fields rejected", err)
			}
			encode := func(fields []identity.FeatureField) []byte {
				t.Helper()
				value, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
				if err != nil {
					t.Fatal(err)
				}
				return cborMap(value)
			}
			original := encode(fields)
			for _, change := range []func(*SCIMUserUpdateIntent){
				func(v *SCIMUserUpdateIntent) { v.ExpectedVersion++ },
				func(v *SCIMUserUpdateIntent) { v.Attributes[0].Value.Scalar.String = "different" },
				func(v *SCIMUserUpdateIntent) { v.Attributes = nil },
			} {
				candidate := scimUpdateIntentFixture(operation)
				change(&candidate)
				changed, err := SCIMUserUpdateFields(candidate, schema)
				if err != nil || bytes.Equal(original, encode(changed)) {
					t.Fatal("changed typed input retained original commitment", err)
				}
			}
			intent.Attributes[0].Value.Scalar.String = "caller mutation"
			if !bytes.Equal(original, encode(fields)) {
				t.Fatal("returned fields alias caller input")
			}
		})
	}
}

func TestSCIMUserUpdateClosedTupleAndZeroWork(t *testing.T) {
	if d, err := NewSCIMUserUpdateDomain(nil); err == nil || d != nil {
		t.Fatal("nil repository admitted")
	}
	if user, err := (*SCIMUserUpdateDomain)(nil).Apply(context.Background(), Work{}, nil, identity.Command{}, SCIMUserUpdateIntent{}); err == nil || user != (identity.User{}) {
		t.Fatal("zero Work invented kernel update")
	}
	if user, err := (Work{}).SCIMUserUpdate(nil); err == nil || user != (identity.User{}) {
		t.Fatal("zero Work disclosed update")
	}
	for _, operation := range []string{"identity.scim.user-replace", "identity.scim.user-patch"} {
		op := identity.FeatureOperation{Owner: "scim", OperationID: operation, SchemaID: operation + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		if operation == "identity.scim.user-patch" {
			op.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
		}
		d := ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim", Version: 1}
		if !featureContributorOwns(d, op) {
			t.Fatal("exact SCIM update tuple rejected")
		}
		op.SchemaID = "scim-alias"
		if featureContributorOwns(d, op) {
			t.Fatal("SCIM alias skipped kernel update requirements")
		}
	}
}

func TestSCIMUserUpdatePreservesRegisteredFieldPolicyAndBounds(t *testing.T) {
	intent := scimUpdateIntentFixture("identity.scim.user-patch")
	schema := storageSchema()
	schema.Fields[0].WriteAuthorization = identity.FieldWriteSystem
	frozen, err := freezeAttributeSchemas([]identity.AttributeSchema{schema})
	if err != nil {
		t.Fatal(err)
	}
	repository := &Repository{attributeSchemas: frozen}
	if _, _, err := repository.prepareAttributeUpdates(schemaKey{schema.ID, schema.Version}, intent.Binding, intent.Attributes); err != nil {
		t.Fatal("system field was treated as self/admin authority", err)
	}
	for _, permission := range []identity.FieldPermission{identity.FieldRead, identity.FieldDenied} {
		changed := schema
		changed.Fields = append([]identity.FieldPolicy(nil), schema.Fields...)
		changed.Fields[0].InputPermission = permission
		frozen, err := freezeAttributeSchemas([]identity.AttributeSchema{changed})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := (&Repository{attributeSchemas: frozen}).prepareAttributeUpdates(schemaKey{schema.ID, schema.Version}, intent.Binding, intent.Attributes); err == nil {
			t.Fatal("SCIM bypassed registered input permission")
		}
	}
	schema.Fields[0].WriteAuthorization = identity.FieldWriteSelf
	frozen, err = freezeAttributeSchemas([]identity.AttributeSchema{schema})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&Repository{attributeSchemas: frozen}).prepareAttributeUpdates(schemaKey{schema.ID, schema.Version}, intent.Binding, intent.Attributes); err == nil {
		t.Fatal("service actor impersonated self field authority")
	}
	for _, change := range []func(*SCIMUserUpdateIntent){
		func(v *SCIMUserUpdateIntent) { v.ExpectedVersion = 0 },
		func(v *SCIMUserUpdateIntent) { v.ExpectedVersion = ^uint64(0) },
		func(v *SCIMUserUpdateIntent) { v.SchemaVersion++ },
		func(v *SCIMUserUpdateIntent) { v.Binding.ActorKind = authorization.SubjectUser },
		func(v *SCIMUserUpdateIntent) { v.Attributes = append(v.Attributes, v.Attributes[0]) },
		func(v *SCIMUserUpdateIntent) { v.Attributes[0].Value.Scalar.String = strings.Repeat("x", 4097) },
	} {
		candidate := scimUpdateIntentFixture("identity.scim.user-patch")
		change(&candidate)
		if fields, err := SCIMUserUpdateFields(candidate, storageSchema()); err == nil || fields != nil {
			t.Fatal("malformed SCIM typed commitment admitted")
		}
	}
	intent.Attributes[0].Value.Scalar.String = "private prepared value"
	if strings.Contains(fmt.Sprintf("%#v", intent), "private prepared value") {
		t.Fatal("prepared intent leaked through diagnostics")
	}
	if data, err := json.Marshal(intent); err == nil || len(data) != 0 {
		t.Fatal("prepared intent serialized")
	}
}
