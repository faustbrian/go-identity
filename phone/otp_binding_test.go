package phone_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	identity "github.com/faustbrian/go-identity"
	phone "github.com/faustbrian/go-identity/phone"
)

func TestPhoneOTPBindingSeparatesOriginalSigninTarget(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US", PreserveDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	canonical := func(raw string) phone.Number {
		t.Helper()
		number, err := policy.Canonicalize(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		return number
	}
	number := canonical("+12025550123")
	key := bytes.Repeat([]byte{7}, 32)
	original, err := phone.OTPSigninIdentifierBinding(number, "tenant-a", key)
	if err != nil || original == ([32]byte{}) {
		t.Fatal("canonical phone cannot bind original OTP signin", err)
	}
	// Literal independently derived with Ruby pack/OpenSSL HMAC. The password
	// domain must remain distinct even for the same tenant, number and key.
	if hex.EncodeToString(original[:]) != "a5a31f2cc070a6e6a731381d50b5825fbbb249d59632de4a5a600b1001662b04" {
		t.Fatal("original phone/OTP signin framing changed")
	}
	same, err := phone.OTPSigninIdentifierBinding(canonical("2025550123"), "tenant-a", key)
	if err != nil || same != original {
		t.Fatal("display/national spelling changed original canonical target")
	}
	password, err := phone.PasswordSigninIdentifierBinding(number, "tenant-a", key)
	if err != nil || password == original {
		t.Fatal("OTP signin reused a password-signin commitment")
	}
	for _, changed := range []struct {
		number phone.Number
		tenant string
		key    []byte
	}{
		{canonical("+12025550124"), "tenant-a", key},
		{number, "tenant-b", key},
		{number, "tenant-a", bytes.Repeat([]byte{8}, 32)},
	} {
		other, err := phone.OTPSigninIdentifierBinding(changed.number, identity.TenantID(changed.tenant), changed.key)
		if err != nil || other == original {
			t.Fatal("another number/tenant/key reused original OTP target")
		}
	}
}

func TestPhoneOTPBindingRejectsInvalidOriginalInput(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	for _, invalid := range []struct {
		number phone.Number
		tenant string
		key    []byte
	}{
		{phone.Number{}, "tenant-a", key},
		{number, "", key},
		{number, "tenant-a", nil},
		{number, "tenant-a", make([]byte, 31)},
		{number, "tenant-a", make([]byte, 65)},
	} {
		got, err := phone.OTPSigninIdentifierBinding(invalid.number, identity.TenantID(invalid.tenant), invalid.key)
		if err == nil || got != ([32]byte{}) {
			t.Fatal("invalid input returned usable original OTP target binding")
		}
	}
}
