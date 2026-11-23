//go:build integration

package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// The real callback journey separately proves the native token-vault handoff.
// These opaque synthetic bytes isolate the journal's duplicate-custody lifetime
// under its actual terminal owner, not token encryption or provider behavior.
func TestSSOOIDCCallbackJournalErasesOnlyTerminalProfileFour(t *testing.T) {
	testSSOJournalErasure(t, ssoOIDCSigninOperation(), []int16{4, 2})
}

func TestSSOOAuth2CallbackJournalErasesOnlyAfterDefinitiveCommit(t *testing.T) {
	testSSOJournalErasure(t, SSOOAuth2SigninOperation(), []int16{4})
}

func TestSSOEnterpriseGrantRefreshJournalErasesOnlyAfterDefinitiveCommit(t *testing.T) {
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider-token.refresh", SchemaID: "identity.sso.provider-token.refresh.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	testSSOJournalErasure(t, op, []int16{4})
}

func TestSSOSAMLCallbackJournalErasesOnlyAfterDefinitiveCommit(t *testing.T) {
	testSSOJournalErasure(t, SSOSAMLSigninOperation(), []int16{4})
}

func testSSOJournalErasure(t *testing.T, op identity.FeatureOperation, profiles []int16) {
	t.Helper()
	for _, committed := range []bool{true, false} {
		for _, profile := range profiles {
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

				binding, _ := ssoOIDCSigninPlanFixture(t)
				switch op.OperationID {
				case ssoOAuth2SigninPurpose:
					binding, _ = ssoOAuth2SigninPlanFixture(t)
				case ssoSAMLSigninPurpose:
					binding, _ = samlSigninPlanFixture(t)
				case "identity.sso.provider-token.refresh":
					binding.OperationID, binding.SchemaID = op.OperationID, op.SchemaID
					binding.UserID, binding.ActorID = "refresh-owner", "refresh-owner"
					binding.ActorKind, binding.AnonymousFlowID = authorization.SubjectUser, ""
				}
				if binding.ValidateFor(op) != nil {
					t.Fatal("fixture lost the exact enterprise operation binding")
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

				oidc := SSOOIDCCallbackPreparationErasureMigrationSource{Base: start, Version: 24}
				installUnlinkPreparationHistory(t, ctx, pool, oidc)
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
				if op.OperationID != ssoOIDCSigninPurpose {
					oauth := SSOOAuth2CallbackPreparationErasureMigrationSource{Base: oidc, Version: 25}
					refresh := SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: oauth, Version: 26}
					if op.OperationID != ssoOAuth2SigninPurpose {
						installUnlinkPreparationHistory(t, ctx, pool, oauth)
					}
					if op.OperationID == ssoSAMLSigninPurpose {
						installUnlinkPreparationHistory(t, ctx, pool, refresh)
					}
					beforeExpansion, err := pool.Raw().Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					err = terminalizeJournal(ctx, beforeExpansion, q, reservation.journal, owner, result, class)
					if rollbackErr := beforeExpansion.Rollback(ctx); rollbackErr != nil {
						t.Fatal(rollbackErr)
					}
					if err == nil {
						t.Fatal("prior guard allowed enterprise operation to discard custody before migration")
					}
					assertPending()
					switch op.OperationID {
					case ssoOAuth2SigninPurpose:
						installUnlinkPreparationHistory(t, ctx, pool, oauth)
					case ssoSAMLSigninPurpose:
						installUnlinkPreparationHistory(t, ctx, pool, SSOSAMLCallbackPreparationErasureMigrationSource{Base: refresh, Version: 27})
					default:
						installUnlinkPreparationHistory(t, ctx, pool, refresh)
					}
					assertPending()
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
