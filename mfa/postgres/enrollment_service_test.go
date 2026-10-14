package mfapostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func TestTOTPEnrollmentServiceRejectsUnownedConfiguration(t *testing.T) {
	if service, err := NewTOTPEnrollmentService(nil, TOTPEnrollmentConfig{}, nil); err == nil || service != nil {
		t.Fatal("missing native owners manufactured an enrollment service")
	}
	for _, service := range []*TOTPEnrollmentService{nil, {}} {
		result, err := service.Enable(context.Background(), mfa.EnableRequest{})
		if err == nil || result.Outcome != 0 || len(result.RecoveryMaterial.Codes) != 0 || result.CommandID != "" {
			t.Fatal("zero native service created enrollment or recovery material")
		}
	}
	var _ mfa.EnrollmentService = (*TOTPEnrollmentService)(nil)
	var _ = identity.CommitOutcomeCommitted
}
