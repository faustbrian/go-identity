//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// The journal, account owner and signed grant are real. Provider exchange,
// capability persistence and audit/outbox persistence are explicit phase seams,
// as in the neighboring terminal-erasure fixture. The OAuth codec's matching
// expiry behavior is independently covered in its own module.
type expiredAttachmentProvider struct {
	*accountLinkErasureProvider
	token          string
	keys           *capability.KeySet
	cleanupCalls   int
	cleanupFailure bool
	startUnknown   bool
	cleanupHandle  AccountLinkCleanupWork
}

func (p *expiredAttachmentProvider) AdmitAccountLinkPreparation(_ context.Context, w AccountLinkPreparationWork, original identity.Command) error {
	spec, err := w.Command(p)
	want, _, _, ok := original.AccountLinkPreparationInput()
	if err != nil || !ok || spec.Binding != want.Binding {
		return invalidWork()
	}
	return nil
}

func (p *expiredAttachmentProvider) CheckAccountLink(_ context.Context, w AccountLinkWork) error {
	_, _, err := w.Command(p)
	return err
}

func (p *expiredAttachmentProvider) PersistAccountLink(ctx context.Context, w AccountLinkWork) error {
	spec, final, err := w.Command(p)
	if err != nil || final {
		return invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.link_provider_effect(command_id,finalized,ciphertext) VALUES($1,false,$2)`, string(spec.Binding.CommandID), []byte("synthetic-durable-provider-ciphertext"))
	return err
}

func (p *expiredAttachmentProvider) FinalizeAccountLink(ctx context.Context, w AccountLinkWork) error {
	spec, final, err := w.Command(p)
	if err != nil || !final {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE public.link_provider_effect SET finalized=true WHERE command_id=$1 AND NOT finalized`, string(spec.Binding.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *expiredAttachmentProvider) GenerateAccountLinkPreparation(ctx context.Context, original identity.Command, generation uint64) ([]byte, error) {
	if p.startUnknown {
		p.generateCalls++
		return nil, identity.UnavailableError{}
	}
	return p.accountLinkErasureProvider.GenerateAccountLinkPreparation(ctx, original, generation)
}

func (p *expiredAttachmentProvider) RestoreAccountLinkPreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	// Use the canonical verifier and actual clock, not a fabricated expired
	// Grant. A retry must reach negative recovery without restoring authority.
	if _, err := capability.Verify(ctx, p.token, p.keys, capability.VerifyOptions{Issuer: "https://identity.example.test", Now: time.Now().UTC(), Limits: capability.DefaultLimits()}); err != nil {
		p.restoreCalls++
		return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, err
	}
	return p.accountLinkErasureProvider.RestoreAccountLinkPreparation(ctx, original, generation, wire)
}

func (p *expiredAttachmentProvider) CleanupAccountLink(ctx context.Context, w AccountLinkCleanupWork) error {
	p.cleanupCalls++
	p.cleanupHandle = w
	_, state, err := w.Scope(p)
	if err != nil || state != *p.final.AccountLinkState {
		return identity.ForbiddenError{}
	}
	if p.cleanupFailure {
		return identity.UnavailableError{}
	}
	spec, _, ok := p.generated.AccountLinkCounterCommand()
	if !ok {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE public.link_expiry_secrets SET erased=true WHERE command_id=$1 AND NOT erased`, string(spec.Binding.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func newExpiredAttachmentFixture(t *testing.T) (context.Context, *AccountLinkUnitOfWork, *expiredAttachmentProvider, identity.Command, CommandPlan, *[]string) {
	t.Helper()
	ctx, pool, owner, base, _, original, declaration := newAccountLinkErasureFixture(t, true)
	spec, counters, ok := base.generated.AccountLinkCounterCommand()
	if !ok {
		t.Fatal("missing final command")
	}
	payload := spec.Proof.Payload()
	now := time.Now().UTC().Truncate(time.Second)
	payload.IssuedAt, payload.ExpiresAt = now.Add(-time.Second), now.Add(3*time.Second)
	key := bytes.Repeat([]byte{1}, 32)
	signer, err := capability.NewHMACSHA256Signer("proof-key", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: payload.Issuer, ID: "proof-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	spec.Proof, err = capability.Verify(ctx, token, keys, capability.VerifyOptions{Issuer: payload.Issuer, Now: now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewAccountLinkCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	base.generated, err = identity.NewAccountLinkCounterCommand(command, counters)
	if err != nil {
		t.Fatal(err)
	}
	grant := *base.final.Capability
	grant.ProofFingerprint, grant.ExpiresAt = spec.Proof.EnvelopeDigest(), payload.ExpiresAt
	base.final.Capability = &grant
	base.issuance.Grants = []CapabilityPlan{grant}
	provider := &expiredAttachmentProvider{accountLinkErasureProvider: base, token: token, keys: keys}
	releases := new([]string)
	entries := make([]Contributor, len(owner.coordinator.registry.state.entries))
	for i, entry := range owner.coordinator.registry.state.entries {
		entries[i] = entry.contributor
		if entry.descriptor == provider.Descriptor() {
			entries[i] = provider
		}
		if participant, ok := entry.contributor.(*accountLinkErasureCapabilities); ok {
			participant.inspectRelease = func(w CapabilityReleaseWork) error {
				binding, err := w.Binding(participant)
				if err == nil {
					*releases = append(*releases, binding.Plan.CapabilityID)
				}
				return err
			}
		}
	}
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	owner.coordinator.registry, owner.provider = registry, provider
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.link_expiry_secrets(command_id text PRIMARY KEY,erased boolean NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.link_expiry_secrets VALUES($1,false)`, string(spec.Binding.CommandID)); err != nil {
		t.Fatal(err)
	}
	return ctx, owner, provider, original, declaration, releases
}

func expireAttachedLink(t *testing.T, ctx context.Context, owner *AccountLinkUnitOfWork, provider *expiredAttachmentProvider, command identity.Command) {
	t.Helper()
	spec, _, _, _ := command.AccountLinkPreparationInput()
	raw, err := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	// Wait only for the short real final grant. The original state remains
	// valid for minutes; the lease change models the abandoned process.
	expires := provider.final.Capability.ExpiresAt
	if _, err := owner.coordinator.pool.Raw().Exec(ctx, `SELECT pg_sleep(greatest(0,extract(epoch FROM $1::timestamptz-clock_timestamp()))+0.01)`, expires); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.coordinator.pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND state='pending'`, raw); err != nil {
		t.Fatal(err)
	}
	var finalExpired, stateLive bool
	if err := owner.coordinator.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()>=$1,clock_timestamp()<$2`, expires, provider.final.AccountLinkState.ExpiresAt).Scan(&finalExpired, &stateLive); err != nil || !finalExpired || !stateLive {
		t.Fatal("fixture missed final-expired/original-state-live boundary", err)
	}
}

func TestAccountLinkAttachedExpiredProofRefusesWithoutRestoringAuthority(t *testing.T) {
	for _, route := range []string{"original-retry", "generic-recovery"} {
		t.Run(route, func(t *testing.T) {
			ctx, owner, provider, original, declaration, releases := newExpiredAttachmentFixture(t)
			prepared, err := owner.PrepareLink(ctx, original, declaration)
			if _, _, ready := prepared.Intent(); err != nil || !ready {
				t.Fatal("prepare and attach final issuance", err)
			}
			spec, _, _, _ := original.AccountLinkPreparationInput()
			before := readAccountLinkErasureSnapshot(t, ctx, owner.coordinator.pool, spec.Binding.CommandID)
			if before.state != "pending" || len(before.plan) == 0 || len(before.ciphertext) == 0 {
				t.Fatal("crash point did not follow committed final attachment")
			}
			// Drop the ready handle without beginning WithinLink: this is the
			// real process-stop boundary, not a rolled-back final transaction.
			prepared = PreparedAccountLink{}
			expireAttachedLink(t, ctx, owner, provider, original)
			var result identity.CommandResult
			if route == "original-retry" {
				result, err = owner.ExecutePrepared(ctx, original, declaration)
			} else {
				result, err = owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
			}
			if result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatalf("attached known output did not reach terminal refusal: outcome=%v error=%T", result.Outcome, err)
			}
			after := readAccountLinkErasureSnapshot(t, ctx, owner.coordinator.pool, spec.Binding.CommandID)
			before.generation = after.generation // Existing recovery owns a new fence.
			assertAccountLinkImmutableCustody(t, before, after)
			if after.state != "aborted" || len(after.receipt) == 0 || after.ciphertext != nil || after.ciphertextGeneration != nil {
				t.Fatal("terminal refusal retained temporary provider output or lost receipt")
			}
			var erased bool
			var accounts, effects, issuances, audits int
			if err := owner.coordinator.pool.Raw().QueryRow(ctx, `SELECT erased,(SELECT count(*) FROM identity.accounts),(SELECT count(*) FROM public.link_provider_effect),(SELECT count(*) FROM public.identity_test_issuance),(SELECT count(*) FROM public.identity_test_audits) FROM public.link_expiry_secrets WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&erased, &accounts, &effects, &issuances, &audits); err != nil {
				t.Fatal(err)
			}
			if !erased || accounts != 0 || effects != 0 || issuances != 1 || audits != 1 || provider.generateCalls != 1 || provider.restoreCalls != 1 || provider.cleanupCalls != 1 || len(*releases) != 2 || (*releases)[0] == (*releases)[1] {
				t.Fatal("refusal renewed/restored authority, omitted cleanup/releases or committed a link")
			}
			if _, _, err := provider.cleanupHandle.Scope(provider); err == nil {
				t.Fatal("returned cleanup handle retained custody")
			}
			replay, replayErr := owner.ExecutePrepared(ctx, original, declaration)
			if replayErr != nil || !reflect.DeepEqual(replay, result) || provider.generateCalls != 1 || provider.restoreCalls != 1 || provider.cleanupCalls != 1 || len(*releases) != 2 {
				t.Fatal("terminal retry restored output or changed refusal", replayErr)
			}
		})
	}
}

func TestAccountLinkExpiredAttachmentPreservesUnprovenCustody(t *testing.T) {
	for _, mode := range []string{"attached-unknown", "started-without-output", "cleanup-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, owner, provider, original, declaration, releases := newExpiredAttachmentFixture(t)
			provider.unknownRecovery = mode == "attached-unknown"
			provider.startUnknown = mode == "started-without-output"
			provider.cleanupFailure = mode == "cleanup-failure"
			prepared, err := owner.PrepareLink(ctx, original, declaration)
			if mode == "started-without-output" {
				if observed, ok := prepared.Observation(); err == nil || !ok || observed.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("unknown exchange did not preserve uncertainty", err)
				}
			} else if _, _, ready := prepared.Intent(); err != nil || !ready {
				t.Fatal("attach known output", err)
			}
			spec, _, _, _ := original.AccountLinkPreparationInput()
			before := readAccountLinkErasureSnapshot(t, ctx, owner.coordinator.pool, spec.Binding.CommandID)
			expireAttachedLink(t, ctx, owner, provider, original)
			result, _ := owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
			if result.Outcome == identity.CommitOutcomeNotCommitted || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("incomplete evidence terminalized expired custody")
			}
			after := readAccountLinkErasureSnapshot(t, ctx, owner.coordinator.pool, spec.Binding.CommandID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("unproven recovery changed retained custody or generation")
			}
			var erased bool
			var audits int
			if err := owner.coordinator.pool.Raw().QueryRow(ctx, `SELECT erased,(SELECT count(*) FROM public.identity_test_audits) FROM public.link_expiry_secrets WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&erased, &audits); err != nil || erased || audits != 0 || len(*releases) != 0 {
				t.Fatal("failed recovery committed erasure, failure audit or release", err)
			}
		})
	}
}

func TestAccountLinkCommittedReceiptReplaysAfterFinalProofExpiry(t *testing.T) {
	ctx, owner, provider, original, declaration, releases := newExpiredAttachmentFixture(t)
	result, err := owner.ExecutePrepared(ctx, original, declaration)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("positive control could not commit", err)
	}
	expireAttachedLink(t, ctx, owner, provider, original)
	replay, err := owner.ExecutePrepared(ctx, original, declaration)
	if err != nil || !reflect.DeepEqual(replay, result) || provider.generateCalls != 1 || provider.restoreCalls != 1 || provider.cleanupCalls != 0 || len(*releases) != 0 {
		t.Fatal("expired final proof replaced a committed receipt", err)
	}
}

func TestAccountLinkExpiredAttachmentRejectsChangedOriginalInputBeforeRecovery(t *testing.T) {
	for _, mode := range []string{"browser", "counter-network"} {
		t.Run(mode, func(t *testing.T) {
			ctx, owner, provider, original, declaration, releases := newExpiredAttachmentFixture(t)
			prepared, err := owner.PrepareLink(ctx, original, declaration)
			if _, _, ready := prepared.Intent(); err != nil || !ready {
				t.Fatal("attach original output", err)
			}
			spec, input, browser, _ := original.AccountLinkPreparationInput()
			before := readAccountLinkErasureSnapshot(t, ctx, owner.coordinator.pool, spec.Binding.CommandID)
			expireAttachedLink(t, ctx, owner, provider, original)
			if mode == "browser" {
				browser = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{33}, 32)))
			} else {
				spec.Counters.Network = "192.0.2.99"
			}
			foreign, err := identity.NewAccountLinkPreparationCommand(spec, input, browser)
			if err != nil {
				t.Fatal(err)
			}
			result, _ := owner.ExecutePrepared(ctx, foreign, declaration)
			if result.Outcome != identity.CommitOutcomeConflict {
				t.Fatal("changed original intent reached historical recovery", result.Outcome)
			}
			after := readAccountLinkErasureSnapshot(t, ctx, owner.coordinator.pool, spec.Binding.CommandID)
			if !reflect.DeepEqual(before, after) || provider.cleanupCalls != 0 || len(*releases) != 0 || provider.generateCalls != 1 || provider.restoreCalls != 1 {
				t.Fatal("foreign retry changed original custody or invoked cleanup/release")
			}
		})
	}
}
