//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This is the coordinator's native participant contract, not an OAuth-provider
// or session acceptance fixture. Its sole native-owned row represents erasure.
type accountLinkCleanupSQLProbe struct {
	*accountLinkSQLProvider
	failCleanup bool
	retained    AccountLinkCleanupWork
}

func (*accountLinkCleanupSQLProbe) ValidateAccountLinkPreparation(identity.Command, CommandPlan) error {
	return nil
}
func (p *accountLinkCleanupSQLProbe) AdmitAccountLinkPreparation(_ context.Context, w AccountLinkPreparationWork, command identity.Command) error {
	spec, err := w.Command(p)
	want, _, _, ok := command.AccountLinkPreparationInput()
	if err != nil || !ok || spec.Binding != want.Binding {
		return invalidWork()
	}
	return nil
}
func (*accountLinkCleanupSQLProbe) GenerateAccountLinkPreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}
func (*accountLinkCleanupSQLProbe) RestoreAccountLinkPreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, invalidPreparation()
}
func (p *accountLinkCleanupSQLProbe) CleanupAccountLink(ctx context.Context, w AccountLinkCleanupWork) error {
	p.retained = w
	if _, _, err := w.Scope(p); err != nil {
		return err
	}
	if p.failCleanup {
		return identity.UnavailableError{}
	}
	spec, ok := p.command.LinkAccount()
	if !ok {
		return invalidWork()
	}
	_, err := w.Exec(ctx, `UPDATE public.link_test_secrets SET erased=true WHERE command_id=$1`, string(spec.Binding.CommandID))
	return err
}

func TestAccountLinkCounterDenialErasesOriginalCustodyAtomically(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		name := "terminal-and-replay"
		if failCleanup {
			name = "erasure-failure-rolls-back-terminalization"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool, repo := newAccountAuthorityStore(t)
			for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, accountLinkPreparationSchemaSQL} {
				if _, err := pool.Raw().Exec(ctx, schema); err != nil {
					t.Fatal("install original custody", err)
				}
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,no_change boolean,outcome smallint,reason text);
CREATE TABLE public.link_test_secrets(command_id text PRIMARY KEY,erased boolean NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			command := liveAccountLinkOwnerCommand(t)
			spec, _ := command.LinkAccount()
			grant := spec.Proof.Payload()
			base := &accountLinkSQLProvider{command: command, capability: CapabilityPlan{CapabilityID: grant.ID, Purpose: "identity.account.link-token", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: grant.ExpiresAt, MaxUses: 1}}
			owner := &accountLinkCleanupSQLProbe{accountLinkSQLProvider: base, failCleanup: failCleanup}
			registry, err := NewContributorRegistry([]Contributor{repo, &accountLinkSQLAudit{}, &recoveryLifecyclePhase{}, &accountLinkSQLCapability{}, &accountLinkCounterProbe{deny: true}, owner})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			generated, counters, _, err := base.PrepareAccountLink(ctx, command)
			if err != nil {
				t.Fatal(err)
			}
			original := originalAccountLinkPreparation(t, generated)
			_, _, declaration := accountLinkOwnerPlanFixture(t)
			state := base.capability
			state.Purpose, state.CapabilityID = "identity.oauth.callback", "original-state"
			declaration.Contributors, declaration.CommandCounters, declaration.Capability, declaration.AccountLinkState = registry.Descriptors(), &counters, nil, &state
			seed, err := kernelMutationAudit(ctx, spec.Binding, 0, base.commandTime(), "committed")
			if err != nil {
				t.Fatal(err)
			}
			declaration.Audits[0].BindingDigest, err = AuditBindingDigest(spec.Binding, seed)
			if err != nil {
				t.Fatal(err)
			}
			q, plan, phase, err := c.prepareAccountLinkPreparation(original, declaration)
			if err != nil {
				t.Fatal("admit original flow", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.link_test_secrets VALUES($1,false)`, string(spec.Binding.CommandID)); err != nil {
				t.Fatal(err)
			}
			_, result, executionErr := c.startAccountLinkPreparation(ctx, original, q, plan, phase, [16]byte{1})
			if _, _, err := owner.retained.Scope(owner); err == nil {
				t.Fatal("returned cleanup handle retained original custody access")
			}
			if _, err := owner.retained.Exec(ctx, `UPDATE public.link_test_secrets SET erased=true`); err == nil {
				t.Fatal("returned cleanup handle retained terminal SQL authority")
			}
			var erased bool
			var audits, commands int
			if err := pool.Raw().QueryRow(ctx, `SELECT erased,(SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM identity.commands WHERE purpose='identity.account.link-token') FROM public.link_test_secrets WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&erased, &audits, &commands); err != nil {
				t.Fatal(err)
			}
			if failCleanup {
				if executionErr == nil || erased || audits != 0 || commands != 0 {
					t.Fatal("failed erasure committed terminal custody or audit")
				}
				return
			}
			if executionErr == nil || result.Outcome != identity.CommitOutcomeNotCommitted || !erased || audits != 1 || commands != 1 {
				t.Fatal("counter denial did not atomically erase original exchange custody")
			}
			_, replay, err := c.startAccountLinkPreparation(ctx, original, q, plan, phase, [16]byte{2})
			if err != nil || replay.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("terminal denial replay changed outcome", err)
			}
		})
	}
}
