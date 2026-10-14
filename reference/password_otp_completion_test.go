package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func TestPasswordOTPLoginCompletionRequiresActualNativeOwners(t *testing.T) {
	if service, err := NewPasswordOTPLoginCompletionService(PasswordOTPLoginCompletionConfig{}); err == nil || service != nil {
		t.Fatal("missing native sender/primary/OTP/session owners became a verifier")
	}
	var zero PasswordOTPLoginCompletionService
	if _, err := zero.OtpVerify(context.Background(), mfa.OtpVerifyRequest{}); err == nil {
		t.Fatal("zero verifier accepted a login")
	}
	if _, err := zero.RecoverOtpVerify(context.Background(), identity.RecoveryQuery{}, nativeTOTPRequest(t).Caller); err == nil {
		t.Fatal("zero verifier disclosed historical outcome")
	}
	if user, child, lifetime, err := zero.OtpVerificationRateSource(context.Background(), mfa.OtpVerifyRequest{}); err == nil || user != "" || child != "" || lifetime != 0 {
		t.Fatal("zero verifier exported OTP quota identity")
	}
	for _, v := range []any{zero, PasswordOTPLoginCompletionConfig{}} {
		if _, err := json.Marshal(v); err == nil || !strings.Contains(fmt.Sprintf("%#v", v), "redacted") {
			t.Fatal("completion runtime/configuration escaped diagnostics")
		}
	}
}
