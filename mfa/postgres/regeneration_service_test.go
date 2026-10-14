package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestRecoveryRegenerationRequiresRealProofSessionAndDispositionOwners(t *testing.T) {
	if s, err := NewRecoveryRegenerationService(nil, nil, RecoveryRegenerationConfig{}); err == nil || s != nil {
		t.Fatal("missing native owners admitted recovery rotation")
	}
	for _, s := range []*RecoveryRegenerationService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := s.RecoveryRegenerate(ctx, mfa.RecoveryRegenerateRequest{})
			if err == nil || out.Outcome != 0 || len(out.RecoveryCodes.Codes) != 0 {
				t.Fatal("unconfigured rotation produced recovery material")
			}
		}
	}
}
