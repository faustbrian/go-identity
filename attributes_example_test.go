package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-identity"
)

func ExampleAttributeSchema_Validate() {
	schema := identity.AttributeSchema{ID: "profile", Version: 1, Fields: []identity.FieldPolicy{{
		Name: "display_name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar,
		Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite,
		OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSelf,
		Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1,
	}}}
	fmt.Println(schema.Validate())
	// Output: <nil>
}
