package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestOTPListReaderRequiresActualEnrollmentOwner(t *testing.T) {
	for _, owner := range []*OTPEnrollmentService{nil, {}} {
		if reader, err := NewOTPListReader(owner); err == nil || reader != nil {
			t.Fatal("missing OTP owner manufactured inventory authority")
		}
		if reader, err := NewOTPManagementListReader(owner, nil); err == nil || reader != nil {
			t.Fatal("missing management owner manufactured labels")
		}
	}
	for _, reader := range []*OTPListReader{nil, {}} {
		if out, err := reader.ReadFactors(context.Background(), mfa.FactorListQuery{}); err == nil || len(out.Factors) != 0 || out.AuthorityVersion != 0 {
			t.Fatal("missing OTP reader manufactured an authoritative empty inventory")
		}
	}
	var _ mfa.FactorListReader = (*OTPListReader)(nil)
}
