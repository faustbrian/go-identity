package apikeyvalkey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
	apikeyvalkey "github.com/faustbrian/go-identity/apikey/valkey"
)

func TestProjectionCacheRejectsSourceFreeAndUnselectedConstruction(t *testing.T) {
	cache, err := apikeyvalkey.New(context.Background(), apikeyvalkey.Config{}, apikey.PositiveProjectionConfig{})
	if err == nil || cache != nil {
		t.Fatal("source-free Valkey became verification/quota authority")
	}
}

func TestProjectionCacheZeroAndClosedInputsCannotInvokeSources(t *testing.T) {
	var cache *apikeyvalkey.Cache
	cache.Close()
	if out, err := cache.VerifyAndConsume(context.Background(), apikey.AtomicVerificationRequest{}); !errors.Is(err, apikeyvalkey.ErrInvalidInput) || out.Result != nil {
		t.Fatal("zero cache fabricated verification")
	}
	if out, err := cache.ReconcileVerifyAndConsume(context.Background(), apikey.VerificationReconcileQuery{}); !errors.Is(err, apikeyvalkey.ErrInvalidInput) || out.Result != nil {
		t.Fatal("zero cache fabricated original verification status")
	}
	if out, err := cache.ApplyPermissionReduction(context.Background(), apikey.PermissionReductionDecision{}); !errors.Is(err, apikeyvalkey.ErrInvalidInput) || out.Record != nil {
		t.Fatal("zero cache became permission maintenance authority")
	}
	if out, err := cache.ReconcilePermissionReduction(context.Background(), apikey.PermissionReductionReconcileQuery{}); !errors.Is(err, apikeyvalkey.ErrInvalidInput) || out.Record != nil {
		t.Fatal("zero cache fabricated original maintenance status")
	}
}
