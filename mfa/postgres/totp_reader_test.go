package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func TestTOTPReaderRejectsMissingAuthority(t *testing.T) {
	if _, err := NewTOTPFactorReader(nil, time.Second); err == nil {
		t.Fatal("nil primary pool accepted")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := (*TOTPFactorReader)(nil).Read(ctx, capability.Grant{}, "https://identity.test", "AAAAAAAAAAAAAAAAAAAAAQ"); err == nil {
			t.Fatal("zero reader granted encrypted factor custody")
		}
	}
	if _, err := (TOTPFactorSnapshot{}).Envelope(); err == nil {
		t.Fatal("zero factor snapshot accepted")
	}
}
