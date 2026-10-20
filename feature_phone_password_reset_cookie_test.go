package identity_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestPhoneResetPreAuthCookieRetainsJointCustodyWithoutLegacyAccess(t *testing.T) {
	proof, _ := passwordResetProof(t, 0)
	secret, _ := primitive.NewSecret([]byte("synthetic phone reset password"))
	defer secret.Destroy()
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	input, _ := identity.NewFeaturePhonePasswordResetInputCommand(phonePasswordResetSpec(), secret, proof, sms, totp)
	generated, _ := identity.NewFeaturePhonePasswordResetCommand(phonePasswordResetSpec(), "synthetic-hash", proof, sms, totp)
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, original := range []identity.Command{input, generated} {
		bound, err := identity.BindPhonePasswordResetPreAuth(original, auth.NewBearerCredential(wire))
		if err != nil {
			t.Fatal("joint recovery cannot retain original browser cookie", err)
		}
		cookie, ok := bound.PhonePasswordResetPreAuthCookie()
		if !ok || cookie.Token() != wire {
			t.Fatal("original recovery cookie changed")
		}
		if _, ok := original.PhonePasswordResetPreAuthCookie(); ok {
			t.Fatal("binding mutated the original command")
		}
		if _, ok := bound.PreAuthCookie(); ok {
			t.Fatal("generic cookie access downgraded joint recovery")
		}
		if _, ok := bound.Feature(); ok {
			t.Fatal("generic feature lost independent factors")
		}
		if _, ok := bound.OneTimeCode(); ok {
			t.Fatal("ordinary OTP lost independent factor custody")
		}
		_, inputVariant := original.PhonePasswordResetInputFeature()
		if _, got := bound.PhonePasswordResetInputFeature(); got != inputVariant {
			t.Fatal("binding changed input/generated variant")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, bound), wire) {
				t.Fatal("joint cookie leaked through diagnostics")
			}
		}
		if out, err := identity.BindPhonePasswordResetPreAuth(bound, auth.NewBearerCredential(wire)); err == nil || out != (identity.Command{}) {
			t.Fatal("already frozen cookie rebound")
		}
	}
	for _, bad := range []string{"", "short", wire + "=", strings.Repeat("x", 87)} {
		if out, err := identity.BindPhonePasswordResetPreAuth(input, auth.NewBearerCredential(bad)); err == nil || out != (identity.Command{}) {
			t.Fatal("malformed cookie retained")
		}
	}
	plain, _ := identity.NewFeatureCommand(phonePasswordResetSpec())
	for _, bad := range []identity.Command{{}, plain} {
		if out, err := identity.BindPhonePasswordResetPreAuth(bad, auth.NewBearerCredential(wire)); err == nil || out != (identity.Command{}) {
			t.Fatal("cookie manufactured joint recovery custody")
		}
	}
}
