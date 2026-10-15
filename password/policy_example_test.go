package password_test

import (
	"fmt"

	password "github.com/faustbrian/go-identity/password"
	primitive "github.com/faustbrian/go-password/v2"
)

func ExampleRegistrationPolicy_CheckPassword() {
	policy := password.RegistrationPolicy{Enabled: true, MinimumBytes: 12, MaximumBytes: 128, RequireVerifiedEmail: true}
	secret, err := primitive.NewSecret([]byte("public-example-only"))
	if err != nil {
		return
	}
	defer secret.Destroy()
	fmt.Println(policy.CheckPassword(secret) == nil)
	// Output: true
}
