package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
)

func TestEmailChangeRequiresNativeOwners(t *testing.T) {
	if _, err := otppg.NewEmailChangeService(nil, otppg.EmailChangeConfig{}, nil); err == nil {
		t.Fatal("missing native owners enabled primary replacement")
	}
	var s *otppg.EmailChangeService
	for _, ctx := range []context.Context{nil, context.Background()} {
		if out, err := s.EmailChangeRequest(ctx, otp.EmailChangeRequest{}); err == nil || out.CommandID != "" {
			t.Fatal("zero source issued a change code")
		}
		if out, err := s.EmailChangeConfirm(ctx, otp.EmailChangeConfirmRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("zero source replaced a primary")
		}
		if out, err := s.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{}); err == nil || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("zero source disclosed change recovery")
		}
	}
}

func TestEmailChangeNativeCompositionNeverExportsCustody(t *testing.T) {
	for _, item := range []struct {
		value  any
		marker string
	}{
		{otppg.EmailChangeConfig{}, "otp.postgres.EmailChangeConfig(redacted)"},
		{(*otppg.EmailChangeService)(nil), "otp.postgres.EmailChangeService(redacted)"},
	} {
		if fmt.Sprintf("%#v", item.value) != item.marker {
			t.Fatal("native composition disclosed retained fields")
		}
		if slog.AnyValue(item.value).Resolve().String() != item.marker {
			t.Fatal("native composition disclosed structured diagnostics")
		}
	}
	for _, value := range []any{otppg.EmailChangeConfig{}, &otppg.EmailChangeService{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("native composition implicitly exported")
		}
	}
}
