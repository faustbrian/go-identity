package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/otp"
)

// Direct callers must retain the core classification for malformed public
// requests without a database or custody read, including code-free recovery.
func TestPublicCheckPreservesRequestValidation(t *testing.T) {
	service := &CheckService{sender: &SendService{}}
	if result, err := service.Check(context.Background(), otp.CheckRequest{}); !errors.Is(err, otp.ErrInvalidAttempt) || result != (otp.CheckResult{}) {
		t.Fatal("Check replaced core validation classification")
	}
	if result, err := service.RecoverCheck(context.Background(), otp.CheckRecoveryRequest{}); !errors.Is(err, otp.ErrInvalidAttempt) || result != (otp.CheckResult{}) {
		t.Fatal("RecoverCheck replaced core validation classification")
	}
}
