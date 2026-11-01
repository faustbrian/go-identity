//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This exercises the existing journal's fifth preparation profile in real SQL;
// it is not proof of OAuth exchange, capability ownership or session composition.
func TestAccountLinkPreparationJournalNeverRepeatsUncertainExchange(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal("install forward preparation profile", err)
		}
	}
	assertAccountLinkPreparationUpgradeRetainsLegacyRows(t, ctx, pool)
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	newRequest := func() claimRequest {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return claimRequest{commandID: id, tenant: "tenant-a", purpose: "identity.account.link-token", canonical: []byte{0xa0}, safeFields: []byte{0xa0}}
	}
	reserve := func(q claimRequest, owner [16]byte) preparationReservation {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		d, err := lockCommandClaim(ctx, tx, q, keys)
		if err != nil || d == claimConflict {
			t.Fatal("original claim not acquired", err)
		}
		r, err := reservePreparationJournal(ctx, tx, q, d, owner, time.Minute, 5)
		if err != nil {
			t.Fatal("profile-five reservation rejected", err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1 AND preparation_declaration IS NULL`, id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return r
	}
	expire := func(q claimRequest) {
		t.Helper()
		id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	start := func(q claimRequest, r preparationReservation, owner [16]byte) error {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	t.Run("lost-start-acknowledgment", func(t *testing.T) {
		q := newRequest()
		first := reserve(q, [16]byte{1})
		if !first.generate || first.journal.generation != 1 {
			t.Fatal("first caller does not own unstarted generation")
		}
		if err := start(q, first, [16]byte{1}); err != nil {
			t.Fatal(err)
		}
		expire(q)
		second := reserve(q, [16]byte{2})
		if second.journal.disposition != journalBusy || second.generate || second.output != nil || second.journal.generation != 1 {
			t.Fatal("missing retained output authorized another exchange")
		}
	})
	t.Run("retained-output-keeps-original-generation", func(t *testing.T) {
		q := newRequest()
		first := reserve(q, [16]byte{3})
		if err := start(q, first, [16]byte{3}); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		output := []byte("synthetic-authenticated-ciphertext")
		if err := retainJournalPreparation(ctx, tx, q, first.journal, [16]byte{3}, output); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		expire(q)
		second := reserve(q, [16]byte{4})
		if second.journal.disposition != journalOwned || second.generate || second.outputGeneration != 1 || second.journal.generation != 2 || second.journal.previousGeneration != 1 || !bytes.Equal(output, second.output) {
			t.Fatal("takeover renewed or replaced original exchange output")
		}
		if err := start(q, first, [16]byte{3}); err == nil {
			t.Fatal("stale owner restarted exchange")
		}
		if err := start(q, second, [16]byte{4}); err == nil {
			t.Fatal("retained output permitted another exchange")
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa1'::bytea WHERE command_id=$1`, id); err == nil {
			t.Fatal("original declaration could change after takeover")
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_profile=4 WHERE command_id=$1`, id); err == nil {
			t.Fatal("original preparation profile could change")
		}
	})
	// Other preparation profiles must not silently select this root-link route.
	t.Run("wrong-operation-rejected", func(t *testing.T) {
		q := newRequest()
		q.purpose = "identity.otp.send"
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		d, err := lockCommandClaim(ctx, tx, q, keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reservePreparationJournal(ctx, tx, q, d, [16]byte{5}, time.Minute, 5); err == nil {
			t.Fatal("OAuth root preparation admitted another operation")
		}
	})
}

func assertAccountLinkPreparationUpgradeRetainsLegacyRows(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	for profile := int16(1); profile <= 4; profile++ {
		commandID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		q := claimRequest{commandID: commandID, tenant: "tenant-a", purpose: "identity.otp.send", canonical: []byte{0xa0}, safeFields: []byte{0xa0}}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		d, err := lockCommandClaim(ctx, tx, q, keys)
		if err != nil {
			t.Fatal(err)
		}
		owner := [16]byte{1}
		r, err := reservePreparationJournal(ctx, tx, q, d, owner, time.Minute, profile)
		if err != nil {
			t.Fatal(err)
		}
		if profile >= 3 {
			id, _ := base64.RawURLEncoding.DecodeString(string(commandID))
			if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1`, id); err != nil {
				t.Fatal(err)
			}
		}
		if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
			t.Fatal(err)
		}
		if err := retainJournalPreparation(ctx, tx, q, r.journal, owner, []byte("synthetic-legacy-encrypted-output")); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var before, after string
	const snapshot = `SELECT json_agg(j ORDER BY command_id)::text FROM identity.commands j`
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, accountLinkPreparationSchemaSQL); err != nil {
		t.Fatal("forward account-link profile upgrade", err)
	}
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("forward profile changed populated legacy preparations", err)
	}
}

// Commit acknowledgment is a coordinator boundary. The capability/counter
// owners here are explicit SQL phase doubles; actual cryptographic composition
// is covered independently by the public capability consumer.
func TestAccountLinkPreparationStartRequiresCommitAcknowledgment(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before-commit"
		if committed {
			name = "after-commit"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool, repo := newAccountAuthorityStore(t)
			for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, accountLinkPreparationSchemaSQL, `CREATE TABLE public.link_capability_effect(command_id text PRIMARY KEY,state text NOT NULL)`} {
				if _, err := pool.Raw().Exec(ctx, schema); err != nil {
					t.Fatal(err)
				}
			}
			_, original, _, declaration, phase := preparedAccountLinkPlanFixture(t)
			registry, err := NewContributorRegistry([]Contributor{repo, &accountLinkSQLAudit{}, &recoveryLifecyclePhase{}, &accountLinkSQLCapability{}, &accountLinkCounterProbe{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			declaration.Contributors = registry.Descriptors()
			q, plan, _, err := c.prepareAccountLinkPreparation(original, declaration)
			if err != nil {
				t.Fatal(err)
			}
			c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
				if committed {
					if err := tx.Commit(ctx); err != nil {
						return err
					}
				}
				return identity.UnavailableError{}
			}
			bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			r, result, err := c.startAccountLinkPreparation(bounded, original, q, plan, phase, [16]byte{1})
			if !errors.As(err, new(identity.UnknownCommitError)) || result.Outcome != identity.CommitOutcomeUnknown || r.journal.disposition == journalOwned || r.generate || r.output != nil {
				t.Fatal("lost start acknowledgment granted exchange custody", result.Outcome, err)
			}
			var commands, reservations int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands),(SELECT count(*) FROM public.link_capability_effect)`).Scan(&commands, &reservations); err != nil {
				t.Fatal(err)
			}
			if !committed {
				if commands != 0 || reservations != 0 {
					t.Fatal("uncommitted start leaked a reservation prefix")
				}
				return
			}
			if commands != 1 || reservations != 1 {
				t.Fatal("acknowledged source did not preserve original start atomically")
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
			var started, retained, attached bool
			var generation string
			if err := pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&started, &retained, &attached, &generation); err != nil || !started || retained || attached || generation != "1" {
				t.Fatal("lost acknowledgment renewed or changed original custody", err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			c.preparationCommit = nil
			r, result, err = c.startAccountLinkPreparation(bounded, original, q, plan, phase, [16]byte{2})
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress || r.journal.disposition != journalBusy || r.generate || r.journal.generation != 1 {
				t.Fatal("lost original start acknowledgment allowed another generation", result.Outcome, err)
			}
		})
	}
}
