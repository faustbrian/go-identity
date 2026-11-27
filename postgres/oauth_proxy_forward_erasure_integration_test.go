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
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgconn"
)

// The native proxy tests separately prove the provider/result handoff. These
// opaque bytes isolate duplicate journal custody under the real terminal owner.
func TestOAuthProxyForwardJournalErasesOnlyDefinitiveProfileFour(t *testing.T) {
	for _, committed := range []bool{true, false} {
		for _, variant := range []string{"proxy-profile-four", "proxy-profile-two", "onetap-sibling"} {
			name := "aborted/" + variant
			if committed {
				name = "committed/" + variant
			}
			t.Run(name, func(t *testing.T) {
				ctx, pool, _ := newAccountAuthorityStore(t)
				unlink := AccountUnlinkPreparationMigrationSource{Base: unlinkPreparationInstalledPrefix(), Version: 20}
				validated := AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 21}
				refresh := OAuthProviderRefreshErasureMigrationSource{Base: validated, Version: 22}
				start := SSOOIDCPreparationErasureMigrationSource{Base: refresh, Version: 23}
				oidc := SSOOIDCCallbackPreparationErasureMigrationSource{Base: start, Version: 24}
				oauth := SSOOAuth2CallbackPreparationErasureMigrationSource{Base: oidc, Version: 25}
				grant := SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: oauth, Version: 26}
				acs := SSOSAMLCallbackPreparationErasureMigrationSource{Base: grant, Version: 27}
				samlStart := SSOSAMLStartPreparationErasureMigrationSource{Base: acs, Version: 28}
				confirmation := SSOSAMLIDPConfirmationPreparationErasureMigrationSource{Base: samlStart, Version: 29}
				relay := SSOSAMLLogoutRelayIssuePreparationErasureMigrationSource{Base: confirmation, Version: 30}
				oneTapStart := OneTapStartPreparationErasureMigrationSource{Base: relay, Version: 31}
				prior := OneTapCallbackPreparationErasureMigrationSource{Base: oneTapStart, Version: 32}
				installUnlinkPreparationHistory(t, ctx, pool, prior)

				binding, _ := proxyForwardPlanFixture(t)
				op, profile := OAuthProxyForwardOperation(), int16(4)
				if variant == "proxy-profile-two" {
					profile = 2
				} else if variant == "onetap-sibling" {
					binding, _ = oneTapCallbackPlanFixture(t)
					op = OneTapCallbackOperation()
				}
				q := claimRequest{commandID: binding.CommandID, tenant: binding.TenantID, purpose: binding.OperationID, feature: &op, canonical: []byte{0xa0}, safeFields: commandSafeFields(binding, &op)}
				keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
				owner := [16]byte{0x51}
				raw, err := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				declaration := []byte{0xa0}
				output := []byte("synthetic-sealed-proxy-preparation")
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
						t.Fatal(err)
					}
				}
				if err := startJournalPreparation(ctx, tx, q, reservation.journal, owner); err != nil {
					t.Fatal(err)
				}
				if err := retainJournalPreparation(ctx, tx, q, reservation.journal, owner, output); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `UPDATE identity.commands SET command_plan=$2 WHERE command_id=$1`, raw, declaration); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}

				assertPending := func() {
					t.Helper()
					var stored, originalDeclaration, originalPlan, receipt []byte
					var state, generation, started, ciphertextGeneration string
					if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,generation::text,preparation_declaration,command_plan,result,state FROM identity.commands WHERE command_id=$1`, raw).Scan(&stored, &ciphertextGeneration, &started, &generation, &originalDeclaration, &originalPlan, &receipt, &state); err != nil {
						t.Fatal(err)
					}
					if state != "pending" || generation != "1" || started != "1" || ciphertextGeneration != "1" || !bytes.Equal(stored, output) || !bytes.Equal(originalPlan, declaration) || receipt != nil || profile == 4 && !bytes.Equal(originalDeclaration, declaration) || profile == 2 && originalDeclaration != nil {
						t.Fatal("pending callback lost original recovery custody")
					}
				}
				assertPending()
				if variant == "proxy-profile-four" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw); err == nil {
						t.Fatal("prior guard allowed pending erasure")
					}
				}

				source := OAuthProxyForwardPreparationErasureMigrationSource{Base: prior, Version: 33}
				before, err := prior.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				history, err := source.Load(ctx)
				if err != nil || len(history) != len(before)+1 || !reflect.DeepEqual(history[:len(before)], before) || history[len(before)].Version() != migrations.Version(33) || history[len(before)].DownSQL() != "" {
					t.Fatal("proxy erasure rewrote predecessor history or added destructive rollback", err)
				}
				installUnlinkPreparationHistory(t, ctx, pool, source)
				assertPending()
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw); err == nil {
					t.Fatal("pending erasure was accepted after migration")
				}
				assertPending()
				unknown, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer unknown.Rollback(ctx)
				if err := terminalizeJournal(ctx, unknown, q, reservation.journal, owner, featureOutcome(binding, &op, identity.CommitOutcomeUnknown, 0), "dependency-failure"); err == nil {
					t.Fatal("unknown observation terminalized custody")
				}
				if err := unknown.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				assertPending()

				result := featureOutcome(binding, &op, identity.CommitOutcomeNotCommitted, 0)
				class, state := "denied", "aborted"
				if committed {
					class, state = "committed", "committed"
					result.Outcome, result.AuditEventID = identity.CommitOutcomeCommitted, "proxy-audit"
					result.Feature.BeforeVersion, result.Feature.AfterVersion = 1, 2
				}
				rolledBack, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rolledBack.Rollback(ctx)
				if err := terminalizeJournal(ctx, rolledBack, q, reservation.journal, owner, result, class); err != nil {
					t.Fatal("stage rollback-only terminalization", err)
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
					t.Fatal("settle definitive callback receipt", err)
				}
				if err := terminal.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				var stored, originalDeclaration, originalPlan, receipt []byte
				var storedState, terminalClass, generation, started string
				var ciphertextGeneration *string
				if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,generation::text,preparation_declaration,command_plan,result,state,terminal_class FROM identity.commands WHERE command_id=$1`, raw).Scan(&stored, &ciphertextGeneration, &started, &generation, &originalDeclaration, &originalPlan, &receipt, &storedState, &terminalClass); err != nil {
					t.Fatal(err)
				}
				if storedState != state || terminalClass != class || generation != "1" || started != "1" || !bytes.Equal(originalPlan, declaration) || len(receipt) == 0 || profile == 4 && !bytes.Equal(originalDeclaration, declaration) || profile == 2 && originalDeclaration != nil {
					t.Fatal("terminal erasure changed original declaration, provenance or receipt")
				}
				if profile == 4 {
					if stored != nil || ciphertextGeneration != nil {
						t.Fatal("terminal proxy callback retained duplicate encrypted preparation")
					}
					_, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, raw, output)
					var guarded *pgconn.PgError
					if !errors.As(err, &guarded) || guarded.Code != "23514" || guarded.Message != "identity command preparation immutable" {
						t.Fatal("terminal output could be resurrected", err)
					}
				} else if !bytes.Equal(stored, output) || ciphertextGeneration == nil || *ciphertextGeneration != "1" {
					t.Fatal("proxy erasure widened to an older preparation profile")
				}
				replayTx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer replayTx.Rollback(ctx)
				disposition, err = lockCommandClaim(ctx, replayTx, q, keys)
				if err != nil || disposition != claimReplay {
					t.Fatal("repeat lost original callback correlation", err)
				}
				replay, err := reservePreparationJournal(ctx, replayTx, q, disposition, [16]byte{0x52}, time.Minute, profile)
				if err != nil || replay.journal.disposition != journalTerminal || replay.journal.generation != 1 || replay.generate || replay.output != nil || replay.journal.result == nil || !reflect.DeepEqual(*replay.journal.result, result) {
					t.Fatal("replay lost receipt or regenerated encrypted output", err)
				}
			})
		}
	}
}
