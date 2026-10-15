//go:build integration

package passwordintegration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func testPublicTOTPURIAmbiguity(t *testing.T, ctx context.Context, pool *database.Pool, source *passworddb.ReauthenticationService, verification passworddb.ReauthenticationRequest, enable mfa.EnableRequest, enroller *mfapg.TOTPEnrollmentService, cfg mfapg.TOTPEnrollmentConfig, keys *keyring.Provider, primary *passworddb.MFAEnablePrimarySource, reveal mfa.TotpUriRequest, before bool) {
	t.Helper()
	issued, err := source.Verify(ctx, verification)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh enrollment proof unavailable for ambiguity")
	}
	enable.Reauthentication = issued.Proof
	enable.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(fmt.Sprintf("uri-fault-%t", before)))
	pending, err := enroller.Enable(ctx, enable)
	defer func() {
		for _, code := range pending.RecoveryMaterial.Codes {
			code.Destroy()
		}
	}()
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh native pending enrollment unavailable for URI ambiguity")
	}
	reveal.EnrollmentID = pending.Enrollment.ID
	reveal.CommandID, _ = identity.NewCommandID()
	fault := &reauthenticationCommitFault{before: before, marker: []byte("UPDATE identity_mfa.totp_factors SET reveal_consumed=true")}
	faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
	if err != nil {
		t.Fatal("isolated URI protocol-fault pool unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if faultPool.Close(cleanup) != nil {
			t.Error("URI fault pool cleanup failed")
		}
	}()
	cfg.Coordinator.LeaseDuration = 500 * time.Millisecond
	faultEnroller, err := mfapg.NewTOTPEnrollmentService(faultPool, cfg, keys)
	if err != nil {
		t.Fatal("URI fault native composition rejected")
	}
	service, err := mfapg.NewTOTPURIService(faultEnroller, mfapg.TOTPURIConfig{Primary: primary, AllowedOrigins: []string{"https://app.test"}})
	if err != nil {
		t.Fatal("URI fault source composition rejected")
	}
	out, err := service.TotpUri(ctx, reveal)
	if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.URI.URI != "" || !fault.hit.Load() {
		t.Fatal("ambiguous URI commit disclosed material or fabricated a known outcome")
	}
	q := identity.RecoveryQuery{TenantID: enable.TenantID, UserID: identity.UserID(reveal.Caller.Request.Subject.ID), ActorID: identity.ActorID(reveal.Caller.Request.Subject.ID), ActorKind: reveal.Caller.Request.Subject.Kind, RecordID: string(reveal.EnrollmentID), OperationID: "identity.mfa.totp-uri", CommandID: reveal.CommandID}
	want := identity.CommitOutcomeCommitted
	if before {
		want = identity.CommitOutcomeNotCommitted
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		recovered, recoveryErr := service.RecoverTotpUri(bounded, q, reveal.Caller)
		if recovered.URI.URI != "" {
			t.Fatal("URI recovery redelivered material")
		}
		if recovered.Outcome == want {
			if !before && recoveryErr != nil {
				t.Fatal("committed URI receipt did not reconcile")
			}
			break
		}
		select {
		case <-bounded.Done():
			t.Fatalf("URI ambiguity did not reconcile: outcome=%d error=%T", recovered.Outcome, recoveryErr)
		case <-ticker.C:
		}
	}
	var consumed bool
	if pool.Raw().QueryRow(ctx, `SELECT reveal_consumed FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(enable.TenantID), string(reveal.EnrollmentID)).Scan(&consumed) != nil || consumed == before {
		t.Fatal("URI recovery contradicted actual durable reveal marker")
	}
	retry, err := service.TotpUri(ctx, reveal)
	if retry.URI.URI != "" || retry.Outcome != want {
		t.Fatalf("URI unknown retry generated successor disclosure: outcome=%d error=%T", retry.Outcome, err)
	}
}
