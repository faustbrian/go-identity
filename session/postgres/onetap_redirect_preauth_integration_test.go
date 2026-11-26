//go:build integration

package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOneTapRedirectPreAuthDurableStagingReadAndConsumption(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	for _, source := range []migrations.Source{
		PreAuthMigrationSource{Schema: c.Schema, Version: 70},
		PreAuthIssueMigrationSource{Schema: c.Schema, Version: 71},
		OneTapStartPreAuthMigrationSource{Schema: c.Schema, Version: 72, ValidationVersion: 73},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("install existing pre-auth history", err)
			}
		}
	}
	b, record, selected := oneTapRedirectStorageFixture(t)
	id := mustCommandBytes(t, b.CommandID)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, id, string(b.TenantID), b.OperationID, make([]byte, 32), []byte{0xa0}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal(err)
	}
	stage := func(commit bool) {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := stagePreAuthIssue(ctx, preAuthTestTx{tx}, c, b, record, selected); err != nil {
			t.Fatal("stage exact redirect in original Work storage", err)
		}
		if commit {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	stage(false)
	if status, err := readPreAuthIssueEvidence(ctx, pool.Raw(), c, b); err != nil || status != kernel.RecoveryNotCommitted {
		t.Fatal("rolled-back redirect retained committed evidence", status, err)
	}
	if _, err := ReadProviderPreAuth(ctx, pool.Raw(), c, b.TenantID, identity.PreAuthTransactionID(b.RecordID), selected); err == nil {
		t.Fatal("rolled-back redirect became readable")
	}
	stage(true)
	loaded, err := ReadProviderPreAuth(ctx, pool.Raw(), c, b.TenantID, identity.PreAuthTransactionID(b.RecordID), selected)
	if err != nil {
		t.Fatal("restart read lost exact redirect", err)
	}
	want, _ := encodePreAuth(record)
	got, err := encodePreAuth(loaded)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatal("restart changed canonical redirect", err)
	}
	if _, err := ReadPreAuth(ctx, pool.Raw(), c, b.TenantID, identity.PreAuthTransactionID(b.RecordID)); err == nil {
		t.Fatal("legacy read borrowed redirect authority")
	}
	popup := selected
	popup.Mode = session.PreAuthProviderCallback
	if _, err := ReadProviderPreAuth(ctx, pool.Raw(), c, b.TenantID, identity.PreAuthTransactionID(b.RecordID), popup); err == nil {
		t.Fatal("popup read borrowed redirect authority")
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := preAuthTestTx{tx}
	defer tx.Rollback(ctx)
	callbackID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	callback := b
	callback.CommandID, callback.OperationID, callback.SchemaID = callbackID, "identity.oauth.onetap-callback", "oauth-onetap-callback-v1"
	use := PreAuthUse{Command: callback, Fingerprint: [32]byte{29}, Generation: 1}
	var substitutions []session.PreAuthTransaction
	for _, change := range []func(*session.ProviderPreAuthTransactionSpec){
		func(p *session.ProviderPreAuthTransactionSpec) {
			p.Transaction.Binding.Intent.CallbackURL = p.Transaction.Binding.Intent.Origin + "/another-endpoint"
		},
		func(p *session.ProviderPreAuthTransactionSpec) {
			p.Provider.Mode = session.PreAuthProviderCallback
			p.Transaction.Binding.Intent.CallbackURL = ""
		},
	} {
		projection, _ := record.ProviderBindings()
		change(&projection)
		changed, err := session.NewProviderPreAuthTransaction(projection)
		if err != nil {
			t.Fatal(err)
		}
		if err := RequireProviderPreAuth(ctx, q, c, changed, projection.Provider); err == nil {
			t.Fatal("substituted mode or endpoint matched stored redirect")
		}
		if err := ReserveProviderPreAuth(ctx, q, c, changed, projection.Provider, use); err == nil {
			t.Fatal("substituted mode or endpoint reserved stored redirect")
		}
		substitutions = append(substitutions, changed)
	}
	if err := RequireProviderPreAuth(ctx, q, c, record, selected); err != nil {
		t.Fatal("exact redirect was not admitted", err)
	}
	if err := ReserveProviderPreAuth(ctx, q, c, record, selected, use); err != nil {
		t.Fatal("reserve exact original redirect", err)
	}
	for _, changed := range substitutions {
		projection, _ := changed.ProviderBindings()
		if err := FinalizeProviderPreAuth(ctx, q, c, changed, projection.Provider, use); err == nil {
			t.Fatal("substituted mode or endpoint consumed reserved redirect")
		}
	}
	if err := FinalizeProviderPreAuth(ctx, q, c, record, selected, use); err != nil {
		t.Fatal("consume exact original redirect", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	testIssuedProviderPreAuthConsumption(t, ctx, pool, c, loaded, selected, b.ActorID)
	if status, err := readPreAuthIssueEvidence(ctx, pool.Raw(), c, b); err != nil || status != kernel.RecoveryCommitted {
		t.Fatal("consumption changed original historical issuance evidence", status, err)
	}
	terminal, err := ReadProviderPreAuth(ctx, pool.Raw(), c, b.TenantID, identity.PreAuthTransactionID(b.RecordID), selected)
	terminalBytes, encodeErr := encodePreAuth(terminal)
	if err != nil || encodeErr != nil || !bytes.Equal(want, terminalBytes) {
		t.Fatal("terminal history changed original redirect bytes", err, encodeErr)
	}

	expiredProjection, _ := record.ProviderBindings()
	flowID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	expiredProjection.Transaction.Binding.ID = flowID
	expiredProjection.Transaction.Binding.ExpiresAt = time.Now().UTC().Add(-time.Second)
	expiredProjection.Transaction.Binding.IssuedAt = expiredProjection.Transaction.Binding.ExpiresAt.Add(-5 * time.Minute)
	copy(expiredProjection.Transaction.Cookie.Sum[:], string(flowID))
	expired, err := session.NewProviderPreAuthTransaction(expiredProjection)
	if err != nil {
		t.Fatal(err)
	}
	expiredTx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer expiredTx.Rollback(ctx)
	if err := insertSelectedPreAuth(ctx, preAuthTestTx{expiredTx}, c, expired, selected); err != nil {
		t.Fatal(err)
	}
	if err := RequireProviderPreAuth(ctx, preAuthTestTx{expiredTx}, c, expired, selected); err == nil {
		t.Fatal("locked primary time renewed expired redirect")
	}
	expiredUse := use
	expiredUse.Command.RecordID, expiredUse.Command.AnonymousFlowID = string(flowID), string(flowID)
	if err := ReserveProviderPreAuth(ctx, preAuthTestTx{expiredTx}, c, expired, selected, expiredUse); err == nil {
		t.Fatal("expired redirect acquired callback reservation")
	}
}
