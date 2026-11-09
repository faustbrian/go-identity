//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Native AEAD/HTTPS behavior is tested in oauth/postgres. This registered SQL
// participant isolates the coordinator's retained refusal and terminal fence.
type providerRefusalSQLPhase struct {
	*accountLinkErasureProvider
	cleanupFailure, generationUnknown bool
	decodeCalls, cleanupCalls         int
}

func (p *providerRefusalSQLPhase) AdmitAccountLinkPreparation(_ context.Context, w AccountLinkPreparationWork, original identity.Command) error {
	spec, err := w.Command(p)
	want, _, _, ok := original.AccountLinkPreparationInput()
	if err != nil || !ok || spec.Binding != want.Binding {
		return invalidWork()
	}
	return nil
}

func (p *providerRefusalSQLPhase) GenerateAccountLinkPreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	p.generateCalls++
	if p.generationUnknown {
		return nil, identity.UnavailableError{}
	}
	return bytes.Clone(p.wire), nil
}

func (p *providerRefusalSQLPhase) RestoreAccountLinkPreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	p.restoreCalls++
	return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, invalidPreparation()
}

func (p *providerRefusalSQLPhase) RestoreAccountLinkPreparationRefusal(_ context.Context, binding identity.CommandBinding, state CapabilityPlan, generation uint64, wire []byte) (AccountLinkPreparationRefusal, error) {
	p.decodeCalls++
	spec, _, _ := p.generated.AccountLinkCounterCommand()
	if binding != spec.Binding || state != *p.final.AccountLinkState || generation != 1 || !bytes.Equal(wire, p.wire) {
		return AccountLinkPreparationRefusal{}, invalidPreparation()
	}
	return AccountLinkPreparationRefusal{Binding: binding, State: state, Generation: generation}, nil
}

func (p *providerRefusalSQLPhase) CleanupAccountLink(ctx context.Context, w AccountLinkCleanupWork) error {
	p.cleanupCalls++
	b, state, err := w.Scope(p)
	if err != nil || state != *p.final.AccountLinkState {
		return invalidWork()
	}
	if p.cleanupFailure {
		return identity.UnavailableError{}
	}
	n, err := w.Exec(ctx, `UPDATE public.provider_refusal_secrets SET ciphertext=NULL WHERE command_id=$1 AND ciphertext IS NOT NULL`, string(b.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func providerRefusalSQLFixture(t *testing.T) (context.Context, *database.Pool, *AccountLinkUnitOfWork, *providerRefusalSQLPhase, identity.Command, CommandPlan) {
	t.Helper()
	ctx, pool, owner, base, _, original, declaration := newAccountLinkErasureFixture(t, true)
	phase := &providerRefusalSQLPhase{accountLinkErasureProvider: base}
	entries := make([]Contributor, len(owner.coordinator.registry.state.entries))
	for i, entry := range owner.coordinator.registry.state.entries {
		entries[i] = entry.contributor
		if entry.descriptor == phase.Descriptor() {
			entries[i] = phase
		}
	}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	owner.coordinator.registry, owner.provider = registry, phase
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.provider_refusal_secrets(command_id text PRIMARY KEY,ciphertext bytea)`); err != nil {
		t.Fatal(err)
	}
	spec, _, _, _ := original.AccountLinkPreparationInput()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.provider_refusal_secrets(command_id,ciphertext) VALUES($1,$2)`, string(spec.Binding.CommandID), []byte("synthetic-rp-secret-ciphertext")); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, owner, phase, original, declaration
}

func TestAccountLinkProviderRefusalRetainsAndTerminallyReplaysWithoutAttachment(t *testing.T) {
	for _, mode := range []string{"direct", "lost-retention-ack", "cleanup-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, owner, phase, original, declaration := providerRefusalSQLFixture(t)
			spec, _, _, _ := original.AccountLinkPreparationInput()
			phase.cleanupFailure = mode == "cleanup-failure"
			if mode == "lost-retention-ack" {
				commits := 0
				owner.coordinator.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
					commits++
					if err := tx.Commit(ctx); err != nil {
						return err
					}
					if commits == 2 {
						return identity.UnavailableError{}
					}
					return nil
				}
			}
			result, err := owner.ExecutePrepared(ctx, original, declaration)
			if mode != "direct" {
				assertProviderRefusalPending(t, ctx, pool, spec.Binding.CommandID, phase.wire)
				if err == nil || result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatalf("unacknowledged retention/cleanup fabricated terminal refusal: outcome=%v error=%T", result.Outcome, err)
				}
				foreignSpec := spec
				foreignSpec.ProviderConfigVersion++
				_, input, bearer, _ := original.AccountLinkPreparationInput()
				foreign, foreignErr := identity.NewAccountLinkPreparationCommand(foreignSpec, input, bearer)
				if foreignErr != nil {
					t.Fatal(foreignErr)
				}
				if changed, _ := owner.ExecutePrepared(ctx, foreign, declaration); changed.Outcome != identity.CommitOutcomeConflict {
					t.Fatal("altered original intent adopted retained refusal")
				}
				phase.cleanupFailure = false
				expireDenialTerminalLease(t, ctx, pool, spec.Binding.CommandID)
				if mode == "cleanup-failure" {
					// Historical recovery has no live original code/state custody.
					input.Destroy()
					result, err = owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
				} else {
					result, err = owner.ExecutePrepared(ctx, original, declaration)
				}
			}
			if err != nil || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatalf("known refusal did not settle: outcome=%v error=%T", result.Outcome, err)
			}
			after := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			if after.state != "aborted" || len(after.receipt) == 0 || after.plan != nil || after.ciphertext != nil || after.ciphertextGeneration != nil || phase.generateCalls != 1 || phase.restoreCalls != 0 {
				t.Fatal("refusal attached/restored a final grant, re-exchanged or retained temporary output")
			}
			var intact bool
			var released, issuance, accounts, effects, lifecycle, audits int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT ciphertext IS NOT NULL FROM public.provider_refusal_secrets),(SELECT count(*) FROM public.link_capability_effect WHERE state='released'),(SELECT count(*) FROM public.identity_test_issuance),(SELECT count(*) FROM identity.accounts),(SELECT count(*) FROM public.link_provider_effect),(SELECT count(*) FROM public.identity_test_lifecycle),(SELECT count(*) FROM public.identity_test_audits WHERE no_change AND reason='not_authorized')`).Scan(&intact, &released, &issuance, &accounts, &effects, &lifecycle, &audits); err != nil || intact || released != 1 || issuance != 0 || accounts != 0 || effects != 0 || lifecycle != 0 || audits != 1 {
				t.Fatal("refusal omitted cleanup/audit/release or issued domain effects", err)
			}
			replay, err := owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
			if err != nil || !reflect.DeepEqual(replay, result) {
				t.Fatal("terminal historical refusal replay changed receipt", err)
			}
			if mode != "cleanup-failure" {
				replay, err = owner.ExecutePrepared(ctx, original, declaration)
				if err != nil || !reflect.DeepEqual(replay, result) || phase.generateCalls != 1 || phase.restoreCalls != 0 {
					t.Fatal("same-command refusal replay restored/exchanged or changed receipt", err)
				}
			}
		})
	}
}

func assertProviderRefusalPending(t *testing.T, ctx context.Context, pool *database.Pool, id identity.CommandID, wire []byte) {
	t.Helper()
	s := readAccountLinkErasureSnapshot(t, ctx, pool, id)
	if s.state != "pending" || s.receipt != nil || s.plan != nil || s.started != "1" || !bytes.Equal(s.ciphertext, wire) || s.ciphertextGeneration == nil || *s.ciphertextGeneration != "1" {
		t.Fatal("failed refusal retention/cleanup changed original recoverable custody")
	}
}

func TestAccountLinkProviderRefusalCrashBeforeRetentionStaysUnknown(t *testing.T) {
	for _, mode := range []string{"generation-failure", "retention-rollback"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, owner, phase, original, declaration := providerRefusalSQLFixture(t)
			phase.generationUnknown = mode == "generation-failure"
			if mode == "retention-rollback" {
				commits := 0
				owner.coordinator.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
					commits++
					if commits == 2 {
						if err := tx.Rollback(ctx); err != nil {
							return err
						}
						return identity.UnavailableError{}
					}
					return tx.Commit(ctx)
				}
			}
			result, err := owner.ExecutePrepared(ctx, original, declaration)
			if err == nil || result.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("pre-retention crash was classified as definitive refusal", err)
			}
			spec, _, _, _ := original.AccountLinkPreparationInput()
			expireDenialTerminalLease(t, ctx, pool, spec.Binding.CommandID)
			result, err = owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("unretained refusal or ambiguous exchange became negative evidence", err)
			}
			result, _ = owner.ExecutePrepared(ctx, original, declaration)
			s := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			if result.Outcome != identity.CommitOutcomeInProgress || s.state != "pending" || s.ciphertext != nil || s.plan != nil || phase.generateCalls != 1 || phase.cleanupCalls != 0 {
				t.Fatal("uncertain exchange regenerated, released custody or fabricated an attachment")
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
			var reserved int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.link_capability_effect WHERE state='reserved' AND command_id=$1`, string(spec.Binding.CommandID)).Scan(&reserved); err != nil || reserved != 1 || len(raw) != 16 {
				t.Fatal("uncertain exchange lost original state reservation", err)
			}
		})
	}
}
