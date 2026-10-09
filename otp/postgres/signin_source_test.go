package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/otp"
)

func TestSigninSourcePreservesMalformedSelectionWithoutIO(t *testing.T) {
	s := &SigninService{sender: &SendService{}}
	if result, err := s.ResolveSigninSource(context.Background(), otp.SigninSourceRequest{}); !errors.Is(err, otp.ErrInvalidAttempt) || result != (otp.SigninSource{}) {
		t.Fatal("source reader replaced core selection classification")
	}
	for _, service := range []*SigninService{nil, {}, s} {
		if result, err := service.ResolveSigninSource(nil, otp.SigninSourceRequest{}); err == nil || result != (otp.SigninSource{}) {
			t.Fatal("nil context/service disclosed source")
		}
	}
}
