package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPasswordSignupMappingPreservesOriginalSession(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, csrf := range []bool{false, true} {
			f, original, _, cookie := passwordSigninMappingFixture(t, anonymous, csrf)
			f.Binding.OperationID, f.Binding.SchemaID = "identity.password.signup", "password-signup"
			f.Operation.OperationID, f.Operation.SchemaID = f.Binding.OperationID, f.Binding.SchemaID
			var err error
			f.Fields, err = PasswordSignupSessionFields(original)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeaturePasswordSignupCommand(f, "$synthetic$prepared-signup", cookie)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := PasswordSignupSession(command)
			if err != nil {
				t.Fatal("valid paired signup session denied", err)
			}
			want, _, _ := encodeRecord(original)
			got, _, _ := encodeRecord(restored)
			if !bytes.Equal(want, got) {
				t.Fatal("original signup session changed")
			}
			if _, err := PasswordSigninSession(command); err == nil {
				t.Fatal("signup relabelled signin")
			}
			plain, _ := identity.NewFeatureCommand(f)
			if _, err := PasswordSignupSession(plain); err == nil {
				t.Fatal("metadata substituted paired signup")
			}
			for i := range f.Fields {
				changed := f
				changed.Fields = append([]identity.FeatureField{}, f.Fields[:i]...)
				changed.Fields = append(changed.Fields, f.Fields[i+1:]...)
				other, e := identity.NewFeaturePasswordSignupCommand(changed, "$synthetic$prepared-signup", cookie)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := PasswordSignupSession(other); e == nil {
					t.Fatalf("missing signup %s admitted", f.Fields[i].Name)
				}
			}
		}
	}
}
