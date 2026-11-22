//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type unlinkPreparationSQLCounter struct{ accountLinkCounterProbe }

func (p *unlinkPreparationSQLCounter) CheckCommandCounters(_ context.Context, h CommandCounterAdmissionWork) error {
	_, err := h.Binding(p)
	return err
}

func (p *unlinkPreparationSQLCounter) ReserveCommandCounters(ctx context.Context, h CommandCounterWork) (CommandCounterDisposition, error) {
	bound, err := h.Binding(p)
	if err != nil {
		return 0, err
	}
	_, err = h.Exec(ctx, `INSERT INTO public.unlink_preparation_charge(command_id) VALUES($1) ON CONFLICT DO NOTHING`, string(bound.Command.CommandID))
	return CommandCounterAllowed, err
}

// SQL phase doubles isolate coordinator acknowledgement/atomicity. They do not
// validate a password, mint a grant or prove the complete native unlink owner.
func TestAccountUnlinkPreparationStartRequiresCommitAcknowledgment(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before-commit"
		if committed {
			name = "after-commit"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool, repo := newAccountAuthorityStore(t)
			prefix := unlinkPreparationInstalledPrefix()
			expansion := AccountUnlinkPreparationMigrationSource{Base: prefix, Version: 20}
			installUnlinkPreparationHistory(t, ctx, pool, AccountUnlinkPreparationValidationMigrationSource{Base: expansion, Version: 21})
			if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.unlink_preparation_charge(command_id text PRIMARY KEY)`); err != nil {
				t.Fatal(err)
			}
			_, original, declaration, phase := unlinkPreparationFixture(t)
			registry, err := NewContributorRegistry([]Contributor{repo, &accountLinkSQLAudit{}, &recoveryLifecyclePhase{}, &capabilityExecutionProbe{}, &unlinkPreparationSQLCounter{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			declaration.Contributors = registry.Descriptors()
			q, admitted, _, err := c.prepareAccountUnlinkPreparation(original, declaration)
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
			r, result, err := c.startAccountUnlinkPreparation(bounded, original, q, admitted, phase, [16]byte{1})
			if !errors.As(err, new(identity.UnknownCommitError)) || result.Outcome != identity.CommitOutcomeUnknown || r.journal.disposition == journalOwned || r.generate || r.output != nil {
				t.Fatal("unacknowledged unlink start granted generation custody", result.Outcome, err)
			}
			var commands, charges int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands),(SELECT count(*) FROM public.unlink_preparation_charge)`).Scan(&commands, &charges); err != nil {
				t.Fatal(err)
			}
			if !committed {
				if commands != 0 || charges != 0 {
					t.Fatal("uncommitted unlink start leaked journal or attempt charge")
				}
				return
			}
			if commands != 1 || charges != 1 {
				t.Fatal("lost acknowledgement did not retain original start and one charge")
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
			var started, retained, attached bool
			var generation string
			if err := pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&started, &retained, &attached, &generation); err != nil || !started || retained || attached || generation != "1" {
				t.Fatal("unacknowledged original unlink start changed custody", err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			c.preparationCommit = nil
			r, result, err = c.startAccountUnlinkPreparation(bounded, original, q, admitted, phase, [16]byte{2})
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress || r.journal.disposition != journalBusy || r.generate || r.journal.generation != 1 {
				t.Fatal("lost unlink start acknowledgement allowed another generation", result.Outcome, err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.unlink_preparation_charge`).Scan(&charges); err != nil || charges != 1 {
				t.Fatal("uncertain start charged a second protected attempt", err)
			}
		})
	}
}
