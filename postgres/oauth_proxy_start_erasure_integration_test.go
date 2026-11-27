//go:build integration

package postgres

import (
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// The native start journey owns PKCE/state generation. These opaque bytes
// isolate its duplicate journal custody under the existing terminal owner.
func TestOAuthProxyStartJournalErasesOnlyDefinitiveProfileFour(t *testing.T) {
	for _, committed := range []bool{true, false} {
		for _, variant := range []string{"start-profile-four", "start-profile-two", "forward-sibling"} {
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
				oneTapCallback := OneTapCallbackPreparationErasureMigrationSource{Base: oneTapStart, Version: 32}
				prior := OAuthProxyForwardPreparationErasureMigrationSource{Base: oneTapCallback, Version: 33}
				installUnlinkPreparationHistory(t, ctx, pool, prior)

				binding, _, plan := proxyStartPlanFixture(t)
				op, profile := plan.Feature.Operation, int16(4)
				if variant == "start-profile-two" {
					profile = 2
				} else if variant == "forward-sibling" {
					binding, plan = proxyForwardPlanFixture(t)
					op = plan.Feature.Operation
				}
				q := claimRequest{commandID: binding.CommandID, tenant: binding.TenantID, purpose: binding.OperationID, feature: &op, canonical: []byte{0xa0}, safeFields: commandSafeFields(binding, &op)}
				keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
				owner := [16]byte{0x61}
				raw, err := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				declaration := []byte{0xa0}
				output := []byte("synthetic-sealed-proxy-start-preparation")
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				disposition, err := lockCommandClaim(ctx, tx, q, keys)
				if err != nil || disposition != claimNew {
					t.Fatal("allocate original proxy claim", err)
				}
				reservation, err := reservePreparationJournal(ctx, tx, q, disposition, owner, time.Minute, profile)
				if err != nil || !reservation.generate || reservation.journal.generation != 1 {
					t.Fatal("reserve original proxy preparation", err)
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

				type snapshot struct {
					ciphertext, declaration, plan, receipt []byte
					ciphertextGeneration                   *string
					started, generation, state             string
					terminalClass                          *string
				}
				read := func() snapshot {
					t.Helper()
					var s snapshot
					if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,preparation_started_generation::text,generation::text,preparation_declaration,command_plan,result,state,terminal_class FROM identity.commands WHERE command_id=$1`, raw).Scan(&s.ciphertext, &s.ciphertextGeneration, &s.started, &s.generation, &s.declaration, &s.plan, &s.receipt, &s.state, &s.terminalClass); err != nil {
						t.Fatal(err)
					}
					return s
				}
				pending := read()
				if pending.state != "pending" || pending.generation != "1" || pending.started != "1" || pending.ciphertextGeneration == nil || *pending.ciphertextGeneration != "1" || !reflect.DeepEqual(pending.ciphertext, output) || !reflect.DeepEqual(pending.plan, declaration) || pending.receipt != nil || pending.terminalClass != nil || profile == 4 && !reflect.DeepEqual(pending.declaration, declaration) || profile == 2 && pending.declaration != nil {
					t.Fatal("fixture lost original pending custody")
				}
				assertPending := func() {
					t.Helper()
					if !reflect.DeepEqual(read(), pending) {
						t.Fatal("undecided proxy lost original recovery custody")
					}
				}
				assertGuarded := func(err error) {
					t.Helper()
					var guarded *pgconn.PgError
					if !errors.As(err, &guarded) || guarded.Code != "23514" || guarded.Message != "identity command preparation immutable" {
						t.Fatal("original preparation custody was mutable", err)
					}
				}
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw)
				assertGuarded(err)
				assertPending()
				source := OAuthProxyStartPreparationErasureMigrationSource{Base: prior, Version: 34}
				before, err := prior.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				history, err := source.Load(ctx)
				if err != nil || len(history) != len(before)+1 || !reflect.DeepEqual(history[:len(before)], before) || history[len(before)].Version() != 34 || history[len(before)].DownSQL() != "" {
					t.Fatal("start erasure rewrote history or added destructive rollback", err)
				}
				installUnlinkPreparationHistory(t, ctx, pool, source)
				assertPending()
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw)
				assertGuarded(err)
				assertPending()
				unknown, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer unknown.Rollback(ctx)
				if err := terminalizeJournal(ctx, unknown, q, reservation.journal, owner, featureOutcome(binding, &op, identity.CommitOutcomeUnknown, 0), "dependency-failure"); err == nil {
					t.Fatal("unknown observation settled preparation custody")
				}
				if err := unknown.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				assertPending()

				result := featureOutcome(binding, &op, identity.CommitOutcomeNotCommitted, 0)
				class, state := "denied", "aborted"
				if committed {
					class, state = "committed", "committed"
					result.Outcome, result.AuditEventID = identity.CommitOutcomeCommitted, "proxy-start-audit"
					result.Feature.BeforeVersion, result.Feature.AfterVersion = 0, 1
					if variant == "forward-sibling" {
						result.Feature.BeforeVersion, result.Feature.AfterVersion = 1, 2
					}
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
					t.Fatal("settle definitive proxy receipt", err)
				}
				if err := terminal.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				settled := read()
				expected := pending
				expected.state, expected.terminalClass, expected.receipt = state, &class, settled.receipt
				if profile == 4 {
					expected.ciphertext, expected.ciphertextGeneration = nil, nil
				}
				if len(settled.receipt) == 0 || !reflect.DeepEqual(settled, expected) {
					t.Fatal("terminal start retained duplicate custody or changed original provenance")
				}
				if profile == 4 {
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, raw, output)
					assertGuarded(err)
				}
				replayTx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer replayTx.Rollback(ctx)
				disposition, err = lockCommandClaim(ctx, replayTx, q, keys)
				if err != nil || disposition != claimReplay {
					t.Fatal("repeat lost original proxy correlation", err)
				}
				replay, err := reservePreparationJournal(ctx, replayTx, q, disposition, [16]byte{0x62}, time.Minute, profile)
				if err != nil || replay.journal.disposition != journalTerminal || replay.journal.generation != 1 || replay.generate || replay.output != nil || replay.journal.result == nil || !reflect.DeepEqual(*replay.journal.result, result) {
					t.Fatal("replay lost original receipt or regenerated encrypted output", err)
				}
			})
		}
	}
}
