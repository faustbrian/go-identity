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

func TestPasswordOTPLoginSendRejectsAbsentNativeOwners(t *testing.T) {
	if _, err := NewPasswordOTPLoginSendService(nil, PasswordOTPLoginSendConfig{}, nil); err == nil {
		t.Fatal("missing native password/OTP/browser/risk owners became a sender")
	}
	var zero PasswordOTPLoginSendService
	if destination, err := zero.OtpSendingRateSource(context.Background(), mfa.OtpSendRequest{}); err == nil || destination != "" {
		t.Fatal("zero sender disclosed a quota destination")
	}
	if _, err := zero.OtpSend(context.Background(), mfa.OtpSendRequest{}); err == nil {
		t.Fatal("zero sender accepted a login send")
	}
	if _, err := zero.RecoverOtpSend(context.Background(), identity.RecoveryQuery{}, nativeTOTPRequest(t).Caller); err == nil {
		t.Fatal("zero sender granted historical outcome")
	}
	for _, value := range []any{zero, PasswordOTPLoginSendConfig{}} {
		if _, err := json.Marshal(value); err == nil || !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("sender or deployment custody escaped implicit serialization")
		}
	}
}
