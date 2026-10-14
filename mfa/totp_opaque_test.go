package mfa

import (
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
)

func TestTOTPOpaqueCodeComparison(t *testing.T) {
	secret := []byte("12345678901234567890")
	code, err := auth.NewOneTimeCode("94287082")
	if err != nil {
		t.Fatal("public fixture rejected")
	}
	now := time.Unix(59, 0)
	key := [32]byte{1}
	binding := []byte("fixture/tenant/subject/factor/challenge/key-version-1")
	step, ok := totpOpaqueMatchingStep(secret, "SHA1", 8, 30*time.Second, 0, now, 0, false, code, key, binding)
	if !ok || step != 1 {
		t.Fatal("valid opaque code rejected")
	}
	_, ok = totpOpaqueMatchingStep(secret, "SHA1", 8, 30*time.Second, 0, now, 1, true, code, key, binding)
	if ok {
		t.Fatal("opaque code replay accepted")
	}
	wrong, _ := auth.NewOneTimeCode("94287083")
	for _, input := range []auth.OneTimeCode{wrong, {}} {
		if _, ok := totpOpaqueMatchingStep(secret, "SHA1", 8, 30*time.Second, 0, now, 0, false, input, key, binding); ok {
			t.Fatal("invalid opaque code accepted")
		}
	}
	for _, b := range [][]byte{nil, make([]byte, 4097)} {
		if _, ok := totpOpaqueMatchingStep(secret, "SHA1", 8, 30*time.Second, 0, now, 0, false, code, key, b); ok {
			t.Fatal("unbounded comparison scope accepted")
		}
	}
	if _, ok := totpOpaqueMatchingStep(secret, "SHA1", 8, 30*time.Second, 0, now, 0, false, code, [32]byte{}, binding); ok {
		t.Fatal("missing trusted key accepted")
	}
}
