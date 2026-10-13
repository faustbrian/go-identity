package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func TestDisableRequiresNativeOwnersAndExplicitRecovery(t *testing.T) {
	if owner, err := NewDisableService(nil, nil, DisableConfig{}); err == nil || owner != nil {
		t.Fatal("unconfigured disable fabricated native authority")
	}
	for _, owner := range []*DisableService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := owner.Disable(ctx, mfa.DisableRequest{})
			if err == nil || out.CommandID != "" || out.Outcome != 0 || out.Factors != nil {
				t.Fatal("missing native owner published disable outcome")
			}
			out, err = owner.RecoverDisable(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{})
			if err == nil || out.CommandID != "" || out.Outcome != 0 || out.Factors != nil {
				t.Fatal("missing native owner fabricated recovered disable")
			}
		}
	}
}
