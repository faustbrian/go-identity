package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestTOTPListReaderRequiresExistingNativeOwner(t *testing.T) {
	for _, owner := range []*TOTPEnrollmentService{nil, {}} {
		if reader, err := NewTOTPListReader(owner); err == nil || reader != nil {
			t.Fatal("missing native owner manufactured an inventory reader")
		}
	}
	for _, reader := range []*TOTPListReader{nil, {}} {
		if out, err := reader.ReadFactors(context.Background(), mfa.FactorListQuery{}); err == nil || len(out.Factors) != 0 || out.AuthorityVersion != 0 {
			t.Fatal("zero reader manufactured known-empty metadata")
		}
	}
	var _ mfa.FactorListReader = (*TOTPListReader)(nil)
}
