package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestFactorManagementRequiresNativePrimaryProofAndSessionOwners(t *testing.T) {
	if service, err := NewFactorUpdateService(nil, nil, FactorUpdateConfig{}); err == nil || service != nil {
		t.Fatal("missing factor-management owners admitted a mutation")
	}
	for _, service := range []*FactorUpdateService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := service.FactorUpdate(ctx, mfa.FactorUpdateRequest{})
			if err == nil || out.Outcome != 0 || out.CommandID != "" || out.Factor.ID != "" {
				t.Fatal("unconfigured factor management fabricated a mutation outcome")
			}
		}
	}
}
