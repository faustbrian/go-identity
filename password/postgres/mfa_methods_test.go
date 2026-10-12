package passwordpostgres

import (
	"reflect"
	"testing"
)

func TestMFACompletionMethodSelectionIsClosedAndOwned(t *testing.T) {
	methods, err := freezeMFACompletionMethods(nil)
	if err != nil || !reflect.DeepEqual(methods, []string{"totp"}) {
		t.Fatal("default method changed", err)
	}
	input := []string{"totp", "recovery-code"}
	methods, err = freezeMFACompletionMethods(input)
	if err != nil || !reflect.DeepEqual(methods, []string{"recovery-code", "totp"}) {
		t.Fatal("explicit recovery selection lost", err)
	}
	input[0] = "otp"
	if !reflect.DeepEqual(methods, []string{"recovery-code", "totp"}) {
		t.Fatal("caller mutated selected methods")
	}
	for _, bad := range [][]string{{"recovery-code"}, {"totp", "totp"}, {"otp"}, {"security-key"}, {""}, {"totp", "recovery-code", "totp"}} {
		if methods, err := freezeMFACompletionMethods(bad); err == nil || methods != nil {
			t.Fatal("unsupported method selected")
		}
	}
}
