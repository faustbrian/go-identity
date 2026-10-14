package mfapostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
)

func TestOTPReaderRejectsMissingOriginalAuthority(t *testing.T) {
	if _, err := NewOTPFactorReader(nil, time.Second); err == nil {
		t.Fatal("nil primary pool accepted")
	}
	for _, ctx := range []context.Context{nil, t.Context()} {
		if _, err := (*OTPFactorReader)(nil).Read(ctx, capability.Grant{}, "https://identity.test", "AAAAAAAAAAAAAAAAAAAAAQ"); err == nil {
			t.Fatal("zero reader granted OTP recipient custody")
		}
	}
	var snapshot OTPFactorSnapshot
	if _, err := snapshot.Metadata(); err == nil {
		t.Fatal("zero returned factor metadata")
	}
	if _, err := snapshot.Recipient(); err == nil {
		t.Fatal("zero returned recipient")
	}
	for _, value := range []any{snapshot, OTPFactorMetadata{}} {
		if _, err := json.Marshal(value); err == nil || !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("OTP reader custody disclosed through diagnostics")
		}
	}
}
