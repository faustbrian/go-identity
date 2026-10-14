package mfapostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOTPSessionFactorReaderFailsClosedWithoutAuthority(t *testing.T) {
	if r, err := NewOTPSessionFactorReader(nil, time.Second); err == nil || r != nil {
		t.Fatal("missing primary became OTP session authority")
	}
	var r OTPSessionFactorReader
	if _, err := r.Read(context.Background(), "tenant", "user", "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
		t.Fatal("zero reader authenticated a factor")
	}
	if _, err := r.Read(nil, "tenant", "user", "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
		t.Fatal("nil context authenticated a factor")
	}
	if _, err := json.Marshal(&r); err == nil || !strings.Contains(fmt.Sprintf("%#v", &r), "redacted") {
		t.Fatal("native reader escaped diagnostics")
	}
}
