//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func installProviderRefreshErasureHistory(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, schema := range []string{accountUnlinkPreparationSQL, accountUnlinkPreparationValidationSQL, oauthProviderRefreshErasureSQL} {
		if _, err := pool.Exec(ctx, schema); err != nil {
			t.Fatal("install provider refresh erasure history", err)
		}
	}
}

func TestProviderRefreshTerminalErasesOnlyPreparedProviderOutput(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, oauthRPPreparationErasureSQL,
		accountLinkPreparationSchemaSQL, accountLinkPreparationErasureSQL, accountLinkPreparationErasureValidationSQL} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal("install populated-compatible preparation history", err)
		}
	}
	installProviderRefreshErasureHistory(t, ctx, pool.Raw())
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	for profile := int16(1); profile <= 4; profile++ {
		for _, committed := range []bool{true, false} {
			op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.refresh-token", SchemaID: "identity.account.refresh-token.pg-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			s := featureCodecSpec()
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			s.Operation = op
			s.Binding.CommandID, s.Binding.RecordID = id, "provider-account"
			s.Binding.OperationID, s.Binding.SchemaID, s.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command := featureCodecCommand(t, s)
			q, err := prepareClaim(command, keys.retained[keys.current])
			if err != nil {
				t.Fatal(err)
			}
			owner := [16]byte{1}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			d, err := lockCommandClaim(ctx, tx, q, keys)
			if err != nil {
				t.Fatal(err)
			}
			r, err := reservePreparationJournal(ctx, tx, q, d, owner, time.Minute, profile)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(id))
			if profile >= 3 {
				if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
				t.Fatal(err)
			}
			ciphertext := []byte("synthetic-prepared-refresh-output")
			if err := retainJournalPreparation(ctx, tx, q, r.journal, owner, ciphertext); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `UPDATE identity.commands SET command_plan='\xa0'::bytea WHERE command_id=$1`, raw); err != nil || tx.Commit(ctx) != nil {
				t.Fatal("persist pending output and plan", err)
			}
			snapshot := readAccountLinkErasureSnapshot(t, ctx, pool, id)
			if snapshot.state != "pending" || !bytes.Equal(snapshot.ciphertext, ciphertext) {
				t.Fatal("pending provider output was not available for recovery")
			}
			result := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: op}}
			class, state := "denied", "aborted"
			if committed {
				class, state = "committed", "committed"
				result.Outcome, result.AuditEventID = identity.CommitOutcomeCommitted, "refresh-audit"
				result.Feature.BeforeVersion, result.Feature.AfterVersion = 1, 2
			}
			terminal, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer terminal.Rollback(ctx)
			if err := terminalizeJournal(ctx, terminal, q, r.journal, owner, result, class); err != nil || terminal.Commit(ctx) != nil {
				t.Fatal("terminal result could not finalize the refresh", err)
			}
			snapshot = readAccountLinkErasureSnapshot(t, ctx, pool, id)
			erases := profile == 2 || profile == 4
			stored := bytes.Equal(snapshot.ciphertext, ciphertext) && snapshot.ciphertextGeneration != nil && *snapshot.ciphertextGeneration == "1"
			erased := snapshot.ciphertext == nil && snapshot.ciphertextGeneration == nil
			if snapshot.state != state || snapshot.started != "1" || erases && !erased || !erases && !stored {
				t.Fatalf("terminal %s profile %d violated selected preparation custody", state, profile)
			}
			if erases {
				_, err := pool.Raw().Exec(ctx, `UPDATE identity.commands
SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation
WHERE command_id=$1 AND purpose='identity.account.refresh-token'`, raw, ciphertext)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.Message != "identity command preparation immutable" {
					t.Fatal("terminal refresh guard did not prohibit ciphertext resurrection", err)
				}
			}
			replay, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer replay.Rollback(ctx)
			d, err = lockCommandClaim(ctx, replay, q, keys)
			if err != nil {
				t.Fatal(err)
			}
			again, err := reservePreparationJournal(ctx, replay, q, d, [16]byte{2}, time.Minute, profile)
			if err != nil || again.generate || again.output != nil || again.journal.result == nil || !reflect.DeepEqual(*again.journal.result, result) {
				t.Fatal("terminal refresh did not replay its original receipt", err)
			}
			if err := replay.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}
