package phone_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	phone "github.com/faustbrian/go-identity/phone"
)

func TestPhonePasswordRecoveryBindingCannotReuseSigninIntent(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US"})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	original, err := phone.PasswordResetIdentifierBinding(number, "tenant-a", key)
	if err != nil || original == ([32]byte{}) {
		t.Fatal("recovery cannot bind original canonical target", err)
	}
	// Independently spell the protocol frame; neither signin commitment nor a
	// caller-selected digest may authorize retargeting the sessionless flow.
	record, err := number.Record()
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte("identity-phone-password-reset-binding-v1\x00")
	frame = binary.BigEndian.AppendUint32(frame, record.Profile.Version)
	for _, value := range []string{"tenant-a", "identity.phone.password-reset-request", record.Profile.ID, record.Profile.MetadataVersion, "+12025550123"} {
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(value)))
		frame = append(frame, value...)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(frame)
	if !hmac.Equal(original[:], mac.Sum(nil)) {
		t.Fatal("recovery commitment changed its original-purpose framing")
	}
	passwordSignin, err := phone.PasswordSigninIdentifierBinding(number, "tenant-a", key)
	if err != nil || passwordSignin == original {
		t.Fatal("password signin substituted for recovery", err)
	}
	otpSignin, err := phone.OTPSigninIdentifierBinding(number, "tenant-a", key)
	if err != nil || otpSignin == original {
		t.Fatal("OTP signin substituted for recovery", err)
	}
	national, err := policy.Canonicalize(context.Background(), "2025550123")
	if err != nil {
		t.Fatal(err)
	}
	same, err := phone.PasswordResetIdentifierBinding(national, "tenant-a", key)
	if err != nil || same != original {
		t.Fatal("canonical alias changed recovery target", err)
	}
	other, err := phone.PasswordResetIdentifierBinding(number, "tenant-b", key)
	if err != nil || other == original {
		t.Fatal("recovery commitment crossed tenant", err)
	}
	other, err = phone.PasswordResetIdentifierBinding(number, "tenant-a", bytes.Repeat([]byte{8}, 32))
	if err != nil || other == original {
		t.Fatal("recovery commitment ignored retained deployment key", err)
	}
	changed, err := policy.Canonicalize(context.Background(), "+12025550124")
	if err != nil {
		t.Fatal(err)
	}
	other, err = phone.PasswordResetIdentifierBinding(changed, "tenant-a", key)
	if err != nil || other == original {
		t.Fatal("recovery flow can be retargeted to another number", err)
	}
	for _, invalid := range [][]byte{nil, make([]byte, 31), make([]byte, 65)} {
		got, err := phone.PasswordResetIdentifierBinding(number, "tenant-a", invalid)
		if !errors.Is(err, phone.ErrPasswordResetBinding) || got != ([32]byte{}) {
			t.Fatal("invalid key created recovery commitment")
		}
	}
	if got, err := phone.PasswordResetIdentifierBinding(phone.Number{}, "tenant-a", key); !errors.Is(err, phone.ErrPasswordResetBinding) || got != ([32]byte{}) {
		t.Fatal("unowned number created recovery commitment")
	}
	if got, err := phone.PasswordResetIdentifierBinding(number, "", key); !errors.Is(err, phone.ErrPasswordResetBinding) || got != ([32]byte{}) {
		t.Fatal("missing tenant created recovery commitment")
	}
}
