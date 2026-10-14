package postgres

import (
	"context"
	"testing"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

var _ identitypostgres.CaptchaExecutionContributor = (*Repository)(nil)

func TestCaptchaUseExecutionRejectsUnownedHandles(t *testing.T) {
	for _, r := range []*Repository{nil, {}, {schema: "risk_store"}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if err := r.CheckCaptchaEvidence(ctx, identitypostgres.CaptchaApplyWork{}); err == nil {
				t.Fatal("zero current-use authority accepted")
			}
			if err := r.FinalizeCaptchaEvidence(ctx, identitypostgres.CaptchaFinalizeWork{}); err == nil {
				t.Fatal("zero finalize authority accepted")
			}
			if err := r.ReleaseCaptchaEvidence(ctx, identitypostgres.CaptchaReleaseWork{}); err == nil {
				t.Fatal("zero release authority accepted")
			}
		}
	}
}
