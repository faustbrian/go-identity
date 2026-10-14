package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/faustbrian/go-identity/otp"
)

func TestPublicSigninPreservesRequestValidation(t *testing.T) {
	service := &SigninService{sender: &SendService{}}
	if result, err := service.Signin(context.Background(), otp.SigninRequest{}); !errors.Is(err, otp.ErrInvalidAttempt) || !reflect.DeepEqual(result, otp.SigninResult{}) {
		t.Fatal("Signin replaced core validation classification")
	}
	if result, err := service.RecoverSignin(context.Background(), otp.SigninRecoveryRequest{}); !errors.Is(err, otp.ErrInvalidAttempt) || !reflect.DeepEqual(result, otp.SigninResult{}) {
		t.Fatal("RecoverSignin replaced core validation classification")
	}
	if s, err := NewSigninService(nil, SigninConfig{}); s != nil || err == nil {
		t.Fatal("zero composition enabled signin")
	}
}
