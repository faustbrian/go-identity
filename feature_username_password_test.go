package identity_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-password/v2"
)

func usernamePasswordSpec(signup bool) identity.FeatureCommandSpec {
	spec := passwordSigninSpec(true)
	spec.Operation.Owner = "identity/username"
	spec.Operation.OperationID, spec.Operation.SchemaID = "identity.username.signin", "username-signin"
	if signup {
		spec.Operation.OperationID, spec.Operation.SchemaID = "identity.username.signup", "username-signup"
	}
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	return spec
}

func TestUsernameUsesExistingPasswordCustodyWithExactOriginalOperation(t *testing.T) {
	secret, err := password.NewSecret([]byte("synthetic-username-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	signup := usernamePasswordSpec(true)
	input, err := identity.NewFeaturePasswordSignupInputCommand(signup, secret, cookie)
	if err != nil {
		t.Fatal("username signup cannot retain original password/preauth custody", err)
	}
	if got, ok := input.PasswordSignupInputFeature(); !ok || got.Binding != signup.Binding || got.Operation != signup.Operation {
		t.Fatal("username signup was relabeled as password route")
	}
	if _, _, ok := input.PasswordSignupCustody(); ok {
		t.Fatal("original input became generated execution")
	}
	generated, err := identity.NewFeaturePasswordSignupCommand(signup, "$synthetic$prepared-username-verifier", cookie)
	if err != nil {
		t.Fatal("username signup lost generated custody", err)
	}
	if got, ok := generated.PasswordSignupFeature(); !ok || got.Binding != signup.Binding {
		t.Fatal("generated signup lost original username operation")
	}
	if _, _, ok := generated.PasswordSigninCustody(); ok {
		t.Fatal("signup became signin")
	}
	signin := usernamePasswordSpec(false)
	command, err := identity.NewFeaturePasswordSigninCommand(signin, secret, cookie)
	if err != nil {
		t.Fatal("username signin cannot retain original password/preauth custody", err)
	}
	if got, ok := command.PasswordSigninFeature(); !ok || got.Binding != signin.Binding || got.Operation != signin.Operation {
		t.Fatal("username signin was relabeled as password route")
	}
	if _, _, ok := command.PasswordSignupCustody(); ok {
		t.Fatal("signin became signup")
	}
	assertSigninLegacyClosed(t, command)
	assertSigninLegacyClosed(t, generated)
	for _, wrong := range []identity.FeatureCommandSpec{signin, func() identity.FeatureCommandSpec {
		s := signup
		s.Operation.SchemaID = "password-signup"
		s.Binding.SchemaID = s.Operation.SchemaID
		return s
	}()} {
		if _, err := identity.NewFeaturePasswordSignupInputCommand(wrong, secret, cookie); err == nil {
			t.Fatal("cross-profile signup input admitted")
		}
		if _, err := identity.NewFeaturePasswordSignupCommand(wrong, "$synthetic$verifier", cookie); err == nil {
			t.Fatal("cross-profile generated signup admitted")
		}
	}
	if _, err := identity.NewFeaturePasswordSigninCommand(signup, secret, cookie); err == nil {
		t.Fatal("signup profile admitted as signin")
	}
}
