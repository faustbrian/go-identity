package passwordpostgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestKeyedEmailRequiresNativeCustody(t *testing.T) {
	if _, err := passwordpg.NewKeyedEmailManagementConfig(kernel.RequestKeyConfig{}, [32]byte{1}); err == nil {
		t.Fatal("invalid mapping enabled keyed email")
	}
	if _, err := passwordpg.NewKeyedEmailManagementConfig(kernel.RequestKeyConfig{}, [32]byte{}); err == nil {
		t.Fatal("absent key enabled keyed email")
	}
	if _, err := passwordpg.NewKeyedEmailManagementService(nil, passwordpg.KeyedEmailManagementConfig{}); err == nil {
		t.Fatal("absent owners enabled keyed email")
	}
	var owner *passwordpg.KeyedEmailManagementService
	for _, ctx := range []context.Context{nil, t.Context()} {
		if user, address, err := owner.RequestRateSource(ctx, passwordpg.EmailManagementRequest{}, identity.IdempotencyKey{}, false); err == nil || user != "" || address != "" {
			t.Fatal("absent keyed owner disclosed rate metadata")
		}
		for _, call := range []func(context.Context, passwordpg.EmailManagementRequest, identity.IdempotencyKey) (passwordpg.EmailManagementResult, error){owner.VerificationSend, owner.VerificationResend, owner.ChangeRequest} {
			if out, err := call(ctx, passwordpg.EmailManagementRequest{}, identity.IdempotencyKey{}); err == nil || out.AddressID != "" || out.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("absent keyed owner disclosed or mutated email")
			}
		}
	}
	for _, value := range []any{passwordpg.KeyedEmailManagementConfig{}, passwordpg.KeyedEmailManagementService{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("sensitive keyed custody serialized")
		}
		got := fmt.Sprintf("%+v", value)
		if got != "passwordpostgres.KeyedEmailManagementConfig(redacted)" && got != "passwordpostgres.KeyedEmailManagementService(redacted)" {
			t.Fatal("keyed custody diagnostics traversed fields")
		}
	}
}
