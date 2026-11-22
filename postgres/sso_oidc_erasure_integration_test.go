//go:build integration

package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestEnterpriseOIDCStartJournalErasesOnlyTerminalPreparation(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	prefix := unlinkPreparationInstalledPrefix()
	unlink := AccountUnlinkPreparationMigrationSource{Base: prefix, Version: 20}
	validated := AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 21}
	refresh := OAuthProviderRefreshErasureMigrationSource{Base: validated, Version: 22}
	installUnlinkPreparationHistory(t, ctx, pool, refresh)
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	binding, _, _ := enterpriseOIDCStartPlans(t)
	op := ssoOIDCStartOperation()
	q := claimRequest{commandID: binding.CommandID, tenant: binding.TenantID, purpose: binding.OperationID, feature: &op, canonical: []byte{0xa0}, safeFields: commandSafeFields(binding, &op)}
	owner := [16]byte{0x35}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	disposition, err := lockCommandClaim(ctx, tx, q, keys)
	if err != nil || disposition != claimNew {
		t.Fatal("allocate original enterprise preparation", err)
	}
	if _, err := reservePreparationJournal(ctx, tx, q, disposition, owner, time.Minute, 2); err == nil {
		t.Fatal("enterprise start accepted a profile without a retained declaration")
	}
	reservation, err := reservePreparationJournal(ctx, tx, q, disposition, owner, time.Minute, 4)
	if err != nil || !reservation.generate {
		t.Fatal("reserve original generation", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
	if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1`, raw); err != nil {
		t.Fatal("freeze original declaration", err)
	}
	if err := startJournalPreparation(ctx, tx, q, reservation.journal, owner); err != nil {
		t.Fatal("record original start", err)
	}
	output := []byte("synthetic-original-sealed-enterprise-checkpoint")
	if err := retainJournalPreparation(ctx, tx, q, reservation.journal, owner, output); err != nil {
		t.Fatal("retain original output", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	installUnlinkPreparationHistory(t, ctx, pool, SSOOIDCPreparationErasureMigrationSource{Base: refresh, Version: 23})
	var retained []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext FROM identity.commands WHERE command_id=$1`, raw).Scan(&retained); err != nil || !bytes.Equal(retained, output) {
		t.Fatal("schema expansion changed a pending original", err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw); err == nil {
		t.Fatal("pending enterprise output could be erased")
	}
	terminal, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Rollback(ctx)
	result := featureOutcome(binding, &op, identity.CommitOutcomeNotCommitted, 0)
	if err := terminalizeJournal(ctx, terminal, q, reservation.journal, owner, result, "denied"); err != nil {
		t.Fatal("terminal enterprise output erasure", err)
	}
	if err := terminal.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var declaration, receipt []byte
	var outputGeneration *string
	var started, state string
	if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,preparation_declaration,result,state FROM identity.commands WHERE command_id=$1`, raw).Scan(&retained, &outputGeneration, &started, &declaration, &receipt, &state); err != nil || retained != nil || outputGeneration != nil || started != "1" || !bytes.Equal(declaration, []byte{0xa0}) || len(receipt) == 0 || state != "aborted" {
		t.Fatal("terminal erasure lost outcome or retained output", err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, raw, output); err == nil {
		t.Fatal("terminal enterprise output could be resurrected")
	}
	replayTx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer replayTx.Rollback(ctx)
	disposition, err = lockCommandClaim(ctx, replayTx, q, keys)
	if err != nil || disposition != claimReplay {
		t.Fatal("repeat did not correlate to original enterprise claim", err)
	}
	replay, err := reservePreparationJournal(ctx, replayTx, q, disposition, [16]byte{0x36}, time.Minute, 4)
	if err != nil || replay.journal.disposition != journalTerminal || replay.generate || replay.output != nil || replay.journal.result == nil || replay.journal.result.Binding != result.Binding || replay.journal.result.Outcome != result.Outcome {
		t.Fatal("terminal repeat lost its original receipt or regenerated custody", err)
	}
}
