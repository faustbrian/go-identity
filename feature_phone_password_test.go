package identity_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-password/v2"
)

func phonePasswordSigninSpec(anonymous bool) identity.FeatureCommandSpec {
	spec := passwordSigninSpec(anonymous)
	spec.Operation.Owner = "identity/phone"
	spec.Operation.OperationID = "identity.phone.password-signin"
	spec.Operation.SchemaID = "phone-password-signin"
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	return spec
}

func TestPhonePasswordSigninKeepsDistinctOriginalPairedCustody(t *testing.T) {
	secret, err := password.NewSecret([]byte(" synthetic phone password "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32))
	cookie := auth.NewBearerCredential(wire)
	for _, anonymous := range []bool{false, true} {
		spec := phonePasswordSigninSpec(anonymous)
		command, err := identity.NewFeaturePasswordSigninCommand(spec, secret, cookie)
		if err != nil {
			t.Fatal("phone password signin lost original paired custody", err)
		}
		projection, ok := command.PasswordSigninFeature()
		if !ok || projection.Operation != spec.Operation || projection.Binding != spec.Binding {
			t.Fatal("phone password signin was relabeled as another login method")
		}
		borrowed, originalCookie, ok := command.PasswordSigninCustody()
		if !ok || borrowed.Len() != secret.Len() || originalCookie.Token() != wire {
			t.Fatal("phone password signin replaced credential custody")
		}
		if _, _, signup := command.PasswordSignupCustody(); signup {
			t.Fatal("phone password signin became signup")
		}
		assertSigninLegacyClosed(t, command)
	}
	for _, alter := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/password" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID, s.Binding.SchemaID = "password-signin", "password-signin"
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID, s.Binding.OperationID = "identity.phone.signin", "identity.phone.signin"
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID, s.Binding.OperationID = "identity.phone.signup", "identity.phone.signup"
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID, s.Binding.OperationID = "identity.phone.password-reset", "identity.phone.password-reset"
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaVersion, s.Binding.SchemaVersion = 2, 2
		},
	} {
		spec := phonePasswordSigninSpec(true)
		alter(&spec)
		if _, err := identity.NewFeaturePasswordSigninCommand(spec, secret, cookie); err == nil {
			t.Fatal("foreign phone workflow or mixed password profile acquired signin custody")
		}
	}
}
