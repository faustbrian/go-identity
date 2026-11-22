//go:build integration

package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// The real callback journey separately proves the native token-vault handoff.
// These opaque synthetic bytes isolate the journal's duplicate-custody lifetime
// under its actual terminal owner, not token encryption or provider behavior.
func TestSSOOIDCCallbackJournalErasesOnlyTerminalProfileFour(t *testing.T) {
	for _, committed := range []bool{true, false} {
		for _, profile := range []int16{4, 2} {
			name := "aborted"
			if committed {
				name = "committed"
			}
			if profile == 2 {
				name += "/unselected-profile-two"
			} else {
				name += "/selected-profile-four"
			}
			t.Run(name, func(t *testing.T) {
				ctx, pool, _ := newAccountAuthorityStore(t)
				unlink := AccountUnlinkPreparationMigrationSource{Base: unlinkPreparationInstalledPrefix(), Version: 20}
				validated := AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 21}
				refresh := OAuthProviderRefreshErasureMigrationSource{Base: validated, Version: 22}
				start := SSOOIDCPreparationErasureMigrationSource{Base: refresh, Version: 23}
				installUnlinkPreparationHistory(t, ctx, pool, start)

				binding, plan := ssoOIDCSigninPlanFixture(t)
				op := ssoOIDCSigninOperation()
				if plan.Feature.Operation != op || !validSSOOIDCSigninBinding(binding) {
					t.Fatal("fixture lost the exact enterprise callback operation")
				}
				q := claimRequest{commandID: binding.CommandID, tenant: binding.TenantID, purpose: binding.OperationID, feature: &op, canonical: []byte{0xa0}, safeFields: commandSafeFields(binding, &op)}
				keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
				owner := [16]byte{0x45}
				raw, err := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				declaration := []byte{0xa0}
				output := []byte("synthetic-sealed-enterprise-callback-token-deposit")
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				disposition, err := lockCommandClaim(ctx, tx, q, keys)
				if err != nil || disposition != claimNew {
					t.Fatal("allocate original callback claim", err)
				}
				reservation, err := reservePreparationJournal(ctx, tx, q, disposition, owner, time.Minute, profile)
				if err != nil || !reservation.generate || reservation.journal.generation != 1 {
					t.Fatal("reserve original callback preparation", err)
				}
				if profile == 4 {
					if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration=$2 WHERE command_id=$1`, raw, declaration); err != nil {
						t.Fatal("retain original callback declaration", err)
					}
				}
				if err := startJournalPreparation(ctx, tx, q, reservation.journal, owner); err != nil {
					t.Fatal("mark callback generation before output", err)
				}
				if err := retainJournalPreparation(ctx, tx, q, reservation.journal, owner, output); err != nil {
					t.Fatal("retain original sealed callback output", err)
				}
				// A real prepared callback retains a final plan. Keeping this nonnil
				// makes replay prove the selected erased-output exception as well.
				if _, err := tx.Exec(ctx, `UPDATE identity.commands SET command_plan=$2 WHERE command_id=$1`, raw, declaration); err != nil {
					t.Fatal("retain original callback plan", err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}

				installUnlinkPreparationHistory(t, ctx, pool, SSOOIDCCallbackPreparationErasureMigrationSource{Base: start, Version: 24})
				assertPending := func() {
					t.Helper()
					var stored, originalDeclaration, originalPlan, receipt []byte
					var generation, started, ciphertextGeneration, state string
					if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,generation::text,preparation_declaration,command_plan,result,state FROM identity.commands WHERE command_id=$1`, raw).Scan(&stored, &ciphertextGeneration, &started, &generation, &originalDeclaration, &originalPlan, &receipt, &state); err != nil {
						t.Fatal("read original pending callback", err)
					}
					if state != "pending" || generation != "1" || started != "1" || ciphertextGeneration != "1" || !bytes.Equal(stored, output) || !bytes.Equal(originalPlan, declaration) || receipt != nil || profile == 4 && !bytes.Equal(originalDeclaration, declaration) || profile == 2 && originalDeclaration != nil {
						t.Fatal("pending or uncertain callback lost original recovery custody")
					}
				}
				assertPending()
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw); err == nil {
					t.Fatal("arbitrary pre-terminal callback erasure was accepted")
				}
				assertPending()

				unknown, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer unknown.Rollback(ctx)
				unknownResult := featureOutcome(binding, &op, identity.CommitOutcomeUnknown, 0)
				if err := terminalizeJournal(ctx, unknown, q, reservation.journal, owner, unknownResult, "dependency-failure"); err == nil {
					t.Fatal("an unknown observation terminalized and erased callback custody")
				}
				if err := unknown.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				assertPending()

				result := featureOutcome(binding, &op, identity.CommitOutcomeNotCommitted, 0)
				class, state := "denied", "aborted"
				if committed {
					class, state = "committed", "committed"
					result.Outcome, result.AuditEventID = identity.CommitOutcomeCommitted, "callback-audit"
					result.Feature.BeforeVersion, result.Feature.AfterVersion = 1, 2
				}
				rolledBack, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rolledBack.Rollback(ctx)
				if err := terminalizeJournal(ctx, rolledBack, q, reservation.journal, owner, result, class); err != nil {
					t.Fatal("stage rollback-only callback terminalization", err)
				}
				if err := rolledBack.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				assertPending()

				terminal, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer terminal.Rollback(ctx)
				if err := terminalizeJournal(ctx, terminal, q, reservation.journal, owner, result, class); err != nil {
					t.Fatal("finalize actual callback terminal owner", err)
				}
				if err := terminal.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				var stored, originalDeclaration, originalPlan, receipt []byte
				var storedState, started, generation, terminalClass string
				var ciphertextGeneration *string
				if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,generation::text,preparation_declaration,command_plan,result,state,terminal_class FROM identity.commands WHERE command_id=$1`, raw).Scan(&stored, &ciphertextGeneration, &started, &generation, &originalDeclaration, &originalPlan, &receipt, &storedState, &terminalClass); err != nil {
					t.Fatal("read definitive callback custody", err)
				}
				if storedState != state || terminalClass != class || generation != "1" || started != "1" || !bytes.Equal(originalPlan, declaration) || len(receipt) == 0 || profile == 4 && !bytes.Equal(originalDeclaration, declaration) || profile == 2 && originalDeclaration != nil {
					t.Fatal("terminal erasure changed original declaration, provenance or receipt")
				}
				if profile == 4 {
					if stored != nil || ciphertextGeneration != nil {
						t.Fatal("terminal callback retained temporary recoverable sealed token output")
					}
					_, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, raw, output)
					var guarded *pgconn.PgError
					if !errors.As(err, &guarded) || guarded.Code != "23514" || guarded.Message != "identity command preparation immutable" {
						t.Fatal("terminal callback output could be resurrected", err)
					}
				} else if !bytes.Equal(stored, output) || ciphertextGeneration == nil || *ciphertextGeneration != "1" {
					t.Fatal("callback erasure widened to an unselected preparation profile")
				}

				replayTx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer replayTx.Rollback(ctx)
				disposition, err = lockCommandClaim(ctx, replayTx, q, keys)
				if err != nil || disposition != claimReplay {
					t.Fatal("repeat did not correlate to original callback", err)
				}
				replay, err := reservePreparationJournal(ctx, replayTx, q, disposition, [16]byte{0x46}, time.Minute, profile)
				if err != nil || replay.journal.disposition != journalTerminal || replay.journal.generation != 1 || replay.generate || replay.output != nil || replay.journal.result == nil || !reflect.DeepEqual(*replay.journal.result, result) {
					t.Fatal("callback replay lost original receipt or regenerated encrypted output", err)
				}
			})
		}
	}
}
