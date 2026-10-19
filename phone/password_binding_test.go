package phone_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	phone "github.com/faustbrian/go-identity/phone"
)

func TestPhonePasswordBindingRetainsCanonicalTenantAndPurpose(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US", PreserveDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	national, err := policy.Canonicalize(context.Background(), "2025550123")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	original, err := phone.PasswordSigninIdentifierBinding(number, "tenant-a", key)
	if err != nil || original == ([32]byte{}) {
		t.Fatal("canonical phone cannot bind original password flow", err)
	}
	// Independent Ruby pack/OpenSSL::HMAC framing, not a production helper.
	if hex.EncodeToString(original[:]) != "dbfbab3b2b114d463fe188aa15f5bf7ecb2fa0abbaa7fc8883d79032795f3538" {
		t.Fatal("original phone/password binding framing changed")
	}
	same, err := phone.PasswordSigninIdentifierBinding(national, "tenant-a", key)
	if err != nil || same != original {
		t.Fatal("display or national spelling retargeted canonical identifier")
	}
	otherNumber, err := policy.Canonicalize(context.Background(), "+12025550124")
	if err != nil {
		t.Fatal(err)
	}
	other, err := phone.PasswordSigninIdentifierBinding(otherNumber, "tenant-a", key)
	if err != nil || other == original {
		t.Fatal("another canonical phone reused original flow commitment")
	}
	other, err = phone.PasswordSigninIdentifierBinding(number, "tenant-b", key)
	if err != nil || other == original {
		t.Fatal("another tenant reused original flow commitment")
	}
	other, err = phone.PasswordSigninIdentifierBinding(number, "tenant-a", bytes.Repeat([]byte{8}, 32))
	if err != nil || other == original {
		t.Fatal("another key reused original flow commitment")
	}
}

func TestPhonePasswordBindingRejectsInvalidOriginalInputs(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 65)} {
		if got, err := phone.PasswordSigninIdentifierBinding(number, "tenant-a", key); err == nil || got != ([32]byte{}) {
			t.Fatal("invalid key returned usable identifier commitment")
		}
	}
	key := bytes.Repeat([]byte{7}, 32)
	if got, err := phone.PasswordSigninIdentifierBinding(phone.Number{}, "tenant-a", key); err == nil || got != ([32]byte{}) {
		t.Fatal("missing canonical number returned usable identifier commitment")
	}
	if got, err := phone.PasswordSigninIdentifierBinding(number, "", key); err == nil || got != ([32]byte{}) {
		t.Fatal("missing tenant returned usable identifier commitment")
	}
}
