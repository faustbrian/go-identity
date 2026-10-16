package reference

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestEmailOTPChangeRequiresSelectedLiveGraph(t *testing.T) {
	if _, err := (FeatureSet{}).EmailOTPChange(); err == nil {
		t.Fatal("unselected graph exposed change workflow")
	}
	var service *EmailOTPChangeService
	if out, err := service.EmailChangeRequest(context.Background(), otp.EmailChangeRequest{}); err == nil || out.CommandID != "" {
		t.Fatal("zero handle issued change code")
	}
	if out, err := service.EmailChangeConfirm(context.Background(), otp.EmailChangeConfirmRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("zero handle replaced primary")
	}
	if out, err := service.RecoverEmailChange(context.Background(), otp.EmailChangeRecoveryRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("zero handle disclosed change")
	}
}
