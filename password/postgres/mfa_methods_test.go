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
	for _, selected := range [][]string{{"otp"}, {"otp", "recovery-code"}, {"totp", "otp"}, {"totp", "otp", "recovery-code"}} {
		methods, err := freezeMFACompletionMethods(selected)
		if err != nil || len(methods) != len(selected) {
			t.Fatal("explicit OTP selection denied", err)
		}
		selected[0] = "security-key"
		for _, method := range methods {
			if method == "security-key" {
				t.Fatal("caller mutated selected OTP methods")
			}
		}
	}
	for _, bad := range [][]string{{"recovery-code"}, {"totp", "totp"}, {"otp", "otp"}, {"otp", "security-key"}, {"security-key"}, {""}, {"totp", "recovery-code", "totp"}, {"totp", "otp", "recovery-code", "otp"}} {
		if methods, err := freezeMFACompletionMethods(bad); err == nil || methods != nil {
			t.Fatal("unsupported method selected")
		}
	}
}
