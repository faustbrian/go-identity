//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func installUnlinkPreparationHistory(t *testing.T, ctx context.Context, pool *database.Pool, source migrations.Source) {
	t.Helper()
	db := stdlib.OpenDBFromPool(pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("forward original-journal migration", err)
	}
}

func unlinkPreparationInstalledPrefix() migrations.Source {
	accounts := AccountMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	preparation := PreparationMigrationSource{Base: accounts, Version: 13}
	admission := AdmissionPreparationMigrationSource{Base: preparation, Version: 14}
	counters := CounterPreparationMigrationSource{Base: admission, Version: 15}
	links := AccountLinkPreparationMigrationSource{Base: counters, Version: 16}
	rpErasure := OAuthRPPreparationErasureMigrationSource{Base: links, Version: 17}
	linkErasure := AccountLinkPreparationErasureMigrationSource{Base: rpErasure, Version: 18}
	return AccountLinkPreparationErasureValidationMigrationSource{Base: linkErasure, Version: 19}
}

// This proves the real journal's storage/lease/erasure protocol, not fresh
// password validation, cryptographic child issuance or a usable unlink service.
func TestAccountUnlinkPreparationJournal(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	prefix := unlinkPreparationInstalledPrefix()
	installUnlinkPreparationHistory(t, ctx, pool, prefix)
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	newRequest := func(purpose string) (claimRequest, identity.CommandBinding) {
		t.Helper()
		binding := recordBinding(purpose, "identity-account", "account-a")
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		binding.CommandID = id
		return claimRequest{commandID: id, tenant: binding.TenantID, purpose: purpose, canonical: []byte{0xa0}, safeFields: commandSafeFields(binding, nil)}, binding
	}
	reserve := func(t *testing.T, q claimRequest, owner [16]byte, profile int16) preparationReservation {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		disposition, err := lockCommandClaim(ctx, tx, q, keys)
		if err != nil || disposition == claimConflict {
			t.Fatal("original journal claim", err)
		}
		reservation, err := reservePreparationJournal(ctx, tx, q, disposition, owner, time.Minute, profile)
		if err != nil {
			t.Fatal("selected journal preparation reservation", profile, err)
		}
		if disposition == claimNew && profile >= 3 {
			raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
			if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return reservation
	}
	for profile := int16(1); profile <= 5; profile++ {
		purpose := "identity.otp.send"
		if profile == 5 {
			purpose = "identity.account.link-token"
		}
		q, _ := newRequest(purpose)
		reserve(t, q, [16]byte{1}, profile)
	}
	const snapshot = `SELECT json_agg(j ORDER BY command_id)::text FROM identity.commands j`
	var before, after string
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	expansion := AccountUnlinkPreparationMigrationSource{Base: prefix, Version: 20}
	installUnlinkPreparationHistory(t, ctx, pool, expansion)
	var validated bool
	const validationState = `SELECT convalidated FROM pg_catalog.pg_constraint WHERE conrelid='identity.commands'::regclass AND conname='identity_preparation_shape'`
	if err := pool.Raw().QueryRow(ctx, validationState).Scan(&validated); err != nil || validated {
		t.Fatal("expansion unexpectedly scanned and validated populated history", err)
	}
	installUnlinkPreparationHistory(t, ctx, pool, AccountUnlinkPreparationValidationMigrationSource{Base: expansion, Version: 21})
	if err := pool.Raw().QueryRow(ctx, validationState).Scan(&validated); err != nil || !validated {
		t.Fatal("separate journal validation missing", err)
	}
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("unlink migration changed populated predecessor journal rows", err)
	}
	for _, retainOutput := range []bool{false, true} {
		name := "lost-start-acknowledgment"
		if retainOutput {
			name = "retained-original-and-terminal-erasure"
		}
		t.Run(name, func(t *testing.T) {
			q, binding := newRequest("identity.account.unlink")
			firstOwner, nextOwner := [16]byte{2}, [16]byte{3}
			first := reserve(t, q, firstOwner, 6)
			if !first.generate || first.journal.generation != 1 {
				t.Fatal("first original preparation has no unique generation")
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
			pending := "pending"
			var leaseUntil time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT lease_until FROM identity.commands WHERE command_id=$1`, raw).Scan(&leaseUntil); err != nil {
				t.Fatal(err)
			}
			fingerprint := claimFingerprint(keys.retained[1], q.canonical)
			observed := commandObservation{tenant: string(q.tenant), purpose: q.purpose, scope: q.safeFields, fingerprint: fingerprint[:], state: &pending, until: &leaseUntil}
			if err := readObservedCounterPreparation(ctx, pool.Raw(), raw, &observed); err != nil || observed.preparationProfile == nil || *observed.preparationProfile != 6 || !bytes.Equal(observed.declaration, []byte{0xa0}) {
				t.Fatal("current original unlink observation omitted preparation custody", err)
			}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if err := startJournalPreparation(ctx, tx, q, first.journal, firstOwner); err != nil {
				t.Fatal("original unlink generation start", err)
			}
			output := []byte("synthetic-authenticated-original-issuance-checkpoint")
			if retainOutput {
				if err := retainJournalPreparation(ctx, tx, q, first.journal, firstOwner, output); err != nil {
					t.Fatal("retain original unlink output", err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			next := reserve(t, q, nextOwner, 6)
			if !retainOutput {
				if next.journal.disposition != journalBusy || next.generate || next.output != nil || next.journal.generation != 1 {
					t.Fatal("uncertain original generation authorized signing again")
				}
				return
			}
			if next.journal.disposition != journalOwned || next.generate || next.outputGeneration != 1 || next.journal.generation != 2 || next.journal.previousGeneration != 1 || !bytes.Equal(next.output, output) {
				t.Fatal("takeover replaced original ciphertext or generation")
			}
			for _, rewrite := range []string{
				`UPDATE identity.commands SET preparation_declaration='\xa1'::bytea WHERE command_id=$1`,
				`UPDATE identity.commands SET preparation_profile=5 WHERE command_id=$1`,
				`UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`,
			} {
				if _, err := pool.Raw().Exec(ctx, rewrite, raw); err == nil {
					t.Fatal("pending original custody permitted rewriting or erasure")
				}
			}
			terminal, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer terminal.Rollback(ctx)
			result := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted}
			if err := terminalizeJournal(ctx, terminal, q, next.journal, nextOwner, result, "denied"); err != nil {
				t.Fatal("terminal original unlink journal", err)
			}
			if err := terminal.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var ciphertext, declaration, receipt []byte
			var ciphertextGeneration *string
			var started, state string
			if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,preparation_declaration,result,state FROM identity.commands WHERE command_id=$1`, raw).Scan(&ciphertext, &ciphertextGeneration, &started, &declaration, &receipt, &state); err != nil || ciphertext != nil || ciphertextGeneration != nil || started != "1" || !bytes.Equal(declaration, []byte{0xa0}) || len(receipt) == 0 || state != "aborted" {
				t.Fatal("terminal receipt retained temporary ciphertext or lost original custody", err)
			}
			replay := reserve(t, q, [16]byte{4}, 6)
			if replay.journal.disposition != journalTerminal || replay.generate || replay.output != nil || replay.journal.result == nil || replay.journal.result.Outcome != result.Outcome || replay.journal.result.Binding != binding {
				t.Fatal("terminal replay regenerated or changed original receipt")
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, raw, output); err == nil {
				t.Fatal("terminal erased ciphertext could be recreated")
			}
		})
	}
	for _, purpose := range []string{"identity.account.link-token", "identity.otp.send", "identity.account.unlink"} {
		q, _ := newRequest(purpose)
		if purpose == "identity.account.unlink" {
			q.feature = &identity.FeatureOperation{}
		}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reservePreparationJournal(ctx, tx, q, claimNew, [16]byte{5}, time.Minute, 6); err == nil {
			t.Error("profile six admitted another operation or generic feature")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
