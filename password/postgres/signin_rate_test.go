package passwordpostgres

import (
	"context"
	"testing"

	password "github.com/faustbrian/go-identity/password"
)

func TestNativeSigninRateSourceRejectsUnownedWork(t *testing.T) {
	for _, service := range []*SigninService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if source, err := service.SigninRateSource(ctx, password.SigninRequest{}); err == nil || source != "" {
				t.Fatal("unowned signin source disclosed metadata")
			}
		}
	}
}
