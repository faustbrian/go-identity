package password_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	password "github.com/faustbrian/go-identity/password"
	primitive "github.com/faustbrian/go-password"
)

func TestRegistrationPolicyBoundsAndDisabled(t *testing.T) {
	for _, policy := range []password.RegistrationPolicy{{}, {MinimumBytes: 1}, {MinimumBytes: 9, MaximumBytes: 8}, {MinimumBytes: 1, MaximumBytes: 1<<20 + 1}} {
		if !errors.Is(policy.Validate(), password.ErrInvalidPolicy) {
			t.Fatal("invalid registration policy admitted")
		}
	}
	policy := password.RegistrationPolicy{Enabled: true, MinimumBytes: 4, MaximumBytes: 8}
	for _, input := range []string{"abc", "abcd", " abc ", "éé", "abcdefgh", "abcdefghi"} {
		secret, err := primitive.NewSecret([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		accepted := len(input) >= 4 && len(input) <= 8
		if err := policy.CheckPassword(secret); (err == nil) != accepted {
			t.Fatal("raw inclusive password byte bounds changed")
		}
		if err := secret.Use(func(raw []byte) error {
			if string(raw) != input {
				t.Error("policy normalized or changed password")
			}
			return nil
		}); err != nil {
			t.Fatal("policy consumed caller secret", err)
		}
		secret.Destroy()
		if !errors.Is(policy.CheckPassword(secret), password.ErrInvalidPassword) {
			t.Fatal("destroyed secret admitted")
		}
	}
	if !errors.Is(policy.CheckPassword(primitive.Secret{}), password.ErrInvalidPassword) {
		t.Fatal("zero secret admitted")
	}
	policy.Enabled = false
	if !errors.Is(policy.CheckPassword(primitive.Secret{}), password.ErrRegistrationDisabled) {
		t.Fatal("disabled registration did not deny")
	}
	if !errors.Is((password.RegistrationPolicy{}).CheckPassword(primitive.Secret{}), password.ErrInvalidPolicy) {
		t.Fatal("zero policy bypassed configuration validation")
	}
}

func TestSignupAddressIsGenericBoundedAndRedacted(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", 4097), "\xff"} {
		if !errors.Is(password.SignupAddressInput(input).Validate(), password.ErrInvalidSignupAddress) {
			t.Fatal("invalid generic signup address admitted")
		}
	}
	for _, input := range []string{"not-an-email", " untouched@example.test ", strings.Repeat("é", 2048)} {
		address := password.SignupAddressInput(input)
		if address.Validate() != nil || string(address) != input {
			t.Fatal("generic address was parsed or normalized by password")
		}
		for _, verb := range []string{"%s", "%q", "%v", "%+v", "%#v", "%d"} {
			if strings.Contains(fmt.Sprintf(verb, address), input) {
				t.Fatal("signup address diagnostic leaked")
			}
		}
		if _, err := json.Marshal(address); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("signup address implicitly serialized")
		}
		if encoded, err := address.MarshalText(); len(encoded) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) || strings.Contains(address.LogValue().String(), input) {
			t.Fatal("signup address text/log projection leaked")
		}
	}
}
