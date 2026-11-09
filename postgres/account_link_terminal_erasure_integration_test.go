//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// These native SQL phase doubles exercise the root coordinator's journal
// custody, not provider cryptography or the independently owned token vault.
// The provider effect's ciphertext represents its separate durable custody.
type accountLinkErasureProvider struct {
	preparedAccountLinkOwnerProbe
	generated       identity.Command
	final           CommandPlan
	issuance        CapabilityIssuancePlan
	wire            []byte
	generateCalls   int
	restoreCalls    int
	refuse          bool
	unknownRecovery bool
}

func (p *accountLinkErasureProvider) PrepareAccountLink(context.Context, identity.Command) (identity.Command, CommandCounterPlan, CapabilityPlan, error) {
	return p.generated, *p.final.CommandCounters, *p.final.Capability, nil
}

func (p *accountLinkErasureProvider) AdmitAccountLinkPreparation(_ context.Context, w AccountLinkPreparationWork, original identity.Command) error {
	spec, err := w.Command(p)
	want, _, _, ok := original.AccountLinkPreparationInput()
	if err != nil || !ok || spec.Binding != want.Binding {
		return invalidWork()
	}
	return nil
}

func (p *accountLinkErasureProvider) GenerateAccountLinkPreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	p.generateCalls++
	return bytes.Clone(p.wire), nil
}

func (p *accountLinkErasureProvider) RestoreAccountLinkPreparation(_ context.Context, _ identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	p.restoreCalls++
	if generation != 1 || !bytes.Equal(wire, p.wire) {
		return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, invalidPreparation()
	}
	return p.generated, p.final, p.issuance, nil
}

func (p *accountLinkErasureProvider) CheckAccountLink(_ context.Context, w AccountLinkWork) error {
	if _, _, err := w.Command(p); err != nil {
		return err
	}
	if p.refuse {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *accountLinkErasureProvider) PersistAccountLink(ctx context.Context, w AccountLinkWork) error {
	spec, final, err := w.Command(p)
	if err != nil || final {
		return invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.link_provider_effect(command_id,finalized,ciphertext) VALUES($1,false,$2)`, string(spec.Binding.CommandID), []byte("synthetic-durable-provider-ciphertext"))
	return err
}

func (p *accountLinkErasureProvider) FinalizeAccountLink(ctx context.Context, w AccountLinkWork) error {
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

func (p *accountLinkErasureProvider) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if p.unknownRecovery {
		return RecoveryUnknown, nil
	}
	return recoveryTestEvidence(ctx, w, "public.link_provider_effect")
}

// Unlike the older single-input SQL fixture, this participant distinguishes
// the original callback capability from the attached final-link capability.
type accountLinkErasureCapabilities struct {
	inspectRelease func(CapabilityReleaseWork) error
}

func (*accountLinkErasureCapabilities) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
}

func (p *accountLinkErasureCapabilities) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO public.link_capability_effect(command_id,capability_id,state) VALUES($1,$2,'reserved')`, string(b.Command.CommandID), b.Plan.CapabilityID)
	return err
}

func (p *accountLinkErasureCapabilities) RebindCapability(_ context.Context, w CapabilityReservationWork) error {
	_, err := w.Binding(p)
	return err
}

func (p *accountLinkErasureCapabilities) ApplyCapability(ctx context.Context, w CapabilityApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.link_capability_effect SET state='applied' WHERE command_id=$1 AND capability_id=$2 AND state='reserved'`, string(b.Command.CommandID), b.Plan.CapabilityID)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *accountLinkErasureCapabilities) FinalizeCapability(ctx context.Context, w CapabilityFinalizeWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.link_capability_effect SET state='finalized' WHERE command_id=$1 AND capability_id=$2 AND state='applied'`, string(b.Command.CommandID), b.Plan.CapabilityID)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *accountLinkErasureCapabilities) ReleaseCapability(ctx context.Context, w CapabilityReleaseWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if p.inspectRelease != nil {
		if err := p.inspectRelease(w); err != nil {
			return err
		}
	}
	n, err := w.Exec(ctx, `UPDATE public.link_capability_effect SET state='released' WHERE command_id=$1 AND capability_id=$2 AND state='reserved'`, string(b.Command.CommandID), b.Plan.CapabilityID)
	if err == nil && n != 1 {
		return identity.ConflictError{}
	}
	return err
}

func (p *accountLinkErasureCapabilities) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.CapabilityBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT state FROM public.link_capability_effect WHERE command_id=$1 AND capability_id=$2`, string(b.Command.CommandID), b.Plan.CapabilityID)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var state string
	if !rows.Next() || rows.Scan(&state) != nil || rows.Next() || rows.Err() != nil || state != "reserved" {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

func newAccountLinkErasureFixture(t *testing.T, preparation bool) (context.Context, *database.Pool, *AccountLinkUnitOfWork, *accountLinkErasureProvider, *accountLinkSQLAudit, identity.Command, CommandPlan) {
	t.Helper()
	return newAccountLinkErasureFixtureHistory(t, preparation, []string{accountLinkPreparationErasureSQL, accountLinkPreparationErasureValidationSQL})
}

func newAccountLinkErasureFixtureHistory(t *testing.T, preparation bool, forwardHistory []string) (context.Context, *database.Pool, *AccountLinkUnitOfWork, *accountLinkErasureProvider, *accountLinkSQLAudit, identity.Command, CommandPlan) {
	t.Helper()
	ctx, pool, repo := newAccountAuthorityStore(t)
	if preparation {
		for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, oauthRPPreparationErasureSQL, accountLinkPreparationSchemaSQL} {
			if _, err := pool.Raw().Exec(ctx, schema); err != nil {
				t.Fatal("install optional preparation history", err)
			}
		}
		for _, schema := range forwardHistory {
			if _, err := pool.Raw().Exec(ctx, schema); err != nil {
				t.Fatal("install forward erasure history", err)
			}
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,no_change boolean,outcome smallint,reason text);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.link_provider_effect(command_id text PRIMARY KEY,finalized boolean NOT NULL,ciphertext bytea NOT NULL);
CREATE TABLE public.link_capability_effect(command_id text NOT NULL,capability_id text NOT NULL,state text NOT NULL,PRIMARY KEY(command_id,capability_id));
CREATE TABLE public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	command := liveAccountLinkOwnerCommand(t)
	spec, _ := command.LinkAccount()
	proof := spec.Proof.Payload()
	base := &accountLinkSQLProvider{command: command, capability: CapabilityPlan{CapabilityID: proof.ID, Purpose: "identity.account.link-token", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: proof.ExpiresAt, MaxUses: 1}}
	generated, counters, grant, err := base.PrepareAccountLink(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	provider := &accountLinkErasureProvider{generated: generated, wire: []byte("synthetic-retained-provider-response-and-issuance-checkpoint")}
	audits := &accountLinkSQLAudit{}
	capabilities := &accountLinkErasureCapabilities{}
	issuer := &issuanceSQLPhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, audits, &recoveryLifecyclePhase{}, capabilities, &accountLinkCounterProbe{}, provider, issuer})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewAccountLinkUnitOfWork(c, repo, AccountLinkUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, _, final := accountLinkOwnerPlanFixture(t)
	final.Contributors, final.CommandCounters, final.Capability = owner.contributors, &counters, &grant
	seed, err := kernelMutationAudit(ctx, spec.Binding, 0, base.commandTime(), "committed")
	if err != nil {
		t.Fatal(err)
	}
	final.Audits[0].BindingDigest, err = AuditBindingDigest(spec.Binding, seed)
	if err != nil {
		t.Fatal(err)
	}
	state := grant
	state.CapabilityID, state.Purpose = "original-state", "identity.oauth.callback"
	state.ReplayDigest, state.ProofFingerprint = [32]byte{8}, [32]byte{9}
	final.AccountLinkState = &state
	provider.final = final
	provider.issuance = CapabilityIssuancePlan{Contributor: issuer.Descriptor(), Grants: []CapabilityPlan{grant}}
	declaration := final
	declaration.Capability = nil
	return ctx, pool, owner, provider, audits, originalAccountLinkPreparation(t, generated), declaration
}

type accountLinkErasureSnapshot struct {
	fingerprint, scope, declaration, plan []byte
	keyVersion                            int64
	started, generation, state            string
	ciphertext, receipt                   []byte
	ciphertextGeneration                  *string
}

func readAccountLinkErasureSnapshot(t *testing.T, ctx context.Context, pool *database.Pool, id identity.CommandID) accountLinkErasureSnapshot {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(string(id))
	if err != nil {
		t.Fatal(err)
	}
	var s accountLinkErasureSnapshot
	err = pool.Raw().QueryRow(ctx, `SELECT c.fingerprint,c.safe_fields,c.fingerprint_key_version,j.preparation_declaration,j.command_plan,
coalesce(j.preparation_started_generation::text,''),j.generation::text,j.state,j.preparation_ciphertext,j.preparation_ciphertext_generation::text,j.result
FROM identity.identity_command_id_claims c JOIN identity.commands j USING(command_id,tenant_id,purpose) WHERE c.command_id=$1`, raw).Scan(&s.fingerprint, &s.scope, &s.keyVersion, &s.declaration, &s.plan, &s.started, &s.generation, &s.state, &s.ciphertext, &s.ciphertextGeneration, &s.receipt)
	if err != nil {
		t.Fatal("read original prepared custody", err)
	}
	return s
}

func installAccountLinkErasure(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	// Separate committed operations keep validation outside the exclusive DDL
	// transaction, as the two forward migration sources require.
	for _, schema := range []string{accountLinkPreparationErasureSQL, accountLinkPreparationErasureValidationSQL} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal("install forward terminal erasure", err)
		}
	}
	var validated bool
	if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_catalog.pg_constraint WHERE conrelid='identity.commands'::regclass AND conname='identity_preparation_shape'`).Scan(&validated); err != nil || !validated {
		t.Fatal("forward custody check not validated", err)
	}
}

func assertAccountLinkImmutableCustody(t *testing.T, before, after accountLinkErasureSnapshot) {
	t.Helper()
	if !bytes.Equal(before.fingerprint, after.fingerprint) || !bytes.Equal(before.scope, after.scope) || before.keyVersion != after.keyVersion || !bytes.Equal(before.declaration, after.declaration) || !bytes.Equal(before.plan, after.plan) || before.started != after.started || before.generation != after.generation {
		t.Fatal("terminalization replaced original intent, generation, fingerprint or final plan")
	}
}

func assertAccountLinkTerminalErasureRollback(t *testing.T, ctx context.Context, pool *database.Pool, original identity.Command, before accountLinkErasureSnapshot) {
	t.Helper()
	spec, _, _, _ := original.AccountLinkPreparationInput()
	q, err := prepareClaim(original, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	// Scope-only recovery has no original callback/browser input. Terminal
	// erasure must select the stored preparation profile rather than that input.
	q.source = nil
	raw, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var storedOwner []byte
	if err := tx.QueryRow(ctx, `SELECT lease_owner FROM identity.commands WHERE command_id=$1 FOR UPDATE`, raw).Scan(&storedOwner); err != nil || len(storedOwner) != 16 {
		t.Fatal("read original journal owner", err)
	}
	var owner [16]byte
	copy(owner[:], storedOwner)
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeNotCommitted}
	if err := terminalizeJournal(ctx, tx, q, journalReservation{disposition: journalOwned, generation: 1}, owner, result, "denied"); err != nil {
		t.Fatal("stage terminal receipt and erasure in original transaction", err)
	}
	var terminalAndErased bool
	if err := tx.QueryRow(ctx, `SELECT state='aborted' AND result IS NOT NULL AND preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL FROM identity.commands WHERE command_id=$1`, raw).Scan(&terminalAndErased); err != nil || !terminalAndErased {
		t.Error("terminal receipt and temporary ciphertext erasure were not staged together", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if after := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID); !reflect.DeepEqual(before, after) {
		t.Fatal("rolled-back terminalization lost original recovery ciphertext or retained a receipt")
	}
}

func TestAccountLinkTerminalErasesPreparationAndReplaysOriginalReceipt(t *testing.T) {
	for _, mode := range []string{"success", "refusal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, owner, provider, _, original, declaration := newAccountLinkErasureFixtureHistory(t, true, nil)
			provider.refuse = mode == "refusal"
			prepared, err := owner.PrepareLink(ctx, original, declaration)
			intent, participants, ready := prepared.Intent()
			if err != nil || !ready {
				t.Fatal("prepare original root link", err)
			}
			spec, _, _, _ := original.AccountLinkPreparationInput()
			before := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			if before.state != "pending" || before.started != "1" || before.ciphertextGeneration == nil || *before.ciphertextGeneration != "1" || !bytes.Equal(before.ciphertext, provider.wire) || len(before.plan) == 0 || len(before.declaration) == 0 {
				t.Fatal("prepared fixture did not retain original output and final attachment")
			}
			installAccountLinkErasure(t, ctx, pool)
			if upgraded := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID); !reflect.DeepEqual(before, upgraded) {
				t.Fatal("forward migration changed populated original custody")
			}
			if mode == "success" {
				assertAccountLinkTerminalErasureRollback(t, ctx, pool, original, before)
			}
			linked, executionErr := prepared.WithinLink(ctx, intent, participants)
			result, hasReceipt := linked.Receipt()
			want, state := identity.CommitOutcomeCommitted, "committed"
			if provider.refuse {
				want, state = identity.CommitOutcomeNotCommitted, "aborted"
			}
			if !hasReceipt || result.Outcome != want || !provider.refuse && executionErr != nil {
				t.Fatal("root link did not reach selected terminal outcome", result.Outcome, executionErr)
			}
			after := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			assertAccountLinkImmutableCustody(t, before, after)
			if after.state != state || len(after.receipt) == 0 {
				t.Fatal("terminal receipt missing")
			}
			if after.ciphertext != nil || after.ciphertextGeneration != nil {
				t.Error("terminal account link retained temporary provider-response/issuance ciphertext or its generation")
			}
			again, err := owner.ExecutePrepared(ctx, original, declaration)
			if err != nil || !reflect.DeepEqual(again, result) || provider.generateCalls != 1 || provider.restoreCalls != 1 {
				t.Fatal("exact terminal replay restored/re-exchanged or changed its original receipt", err)
			}
			recovered, err := owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
			if err != nil || !reflect.DeepEqual(recovered, result) {
				t.Fatal("terminal recovery changed original receipt", err)
			}
			var effects int
			var durableCiphertext bool
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*),coalesce(bool_and(finalized AND ciphertext=$1),true) FROM public.link_provider_effect`, []byte("synthetic-durable-provider-ciphertext")).Scan(&effects, &durableCiphertext); err != nil {
				t.Fatal(err)
			}
			wantEffects := 1
			if provider.refuse {
				wantEffects = 0
			}
			if effects != wantEffects || !durableCiphertext {
				t.Fatal("journal cleanup erased legitimate provider custody or committed refused effects")
			}
			replayed := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			if !reflect.DeepEqual(after, replayed) {
				t.Fatal("terminal replay changed persisted custody or receipt")
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2,preparation_ciphertext_generation=preparation_started_generation WHERE command_id=$1`, raw, []byte("synthetic-replacement-ciphertext")); err == nil {
				t.Fatal("schema permitted restoration of terminal preparation ciphertext")
			}
		})
	}
}

func TestAccountLinkPendingAndUnknownRetainPreparationAfterDeadline(t *testing.T) {
	for _, mode := range []string{"pending", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, owner, provider, audits, original, declaration := newAccountLinkErasureFixtureHistory(t, true, nil)
			provider.unknownRecovery = true
			prepared, err := owner.PrepareLink(ctx, original, declaration)
			intent, participants, ready := prepared.Intent()
			if err != nil || !ready {
				t.Fatal("prepare root link", err)
			}
			spec, _, _, _ := original.AccountLinkPreparationInput()
			before := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			installAccountLinkErasure(t, ctx, pool)
			if mode == "unknown" {
				audits.fail = true
				linked, executionErr := prepared.WithinLink(ctx, intent, participants)
				result, _ := linked.Receipt()
				if executionErr == nil || result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("failed terminal audit did not leave an unknown outcome", result.Outcome, executionErr)
				}
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			result, err := owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("deadline alone became evidence of noncommit", result.Outcome, err)
			}
			after := readAccountLinkErasureSnapshot(t, ctx, pool, spec.Binding.CommandID)
			// Recovery may acquire a fenced generation, but it must retain the
			// original start/output provenance and immutable prepared intent.
			before.generation = after.generation
			assertAccountLinkImmutableCustody(t, before, after)
			if after.state != "pending" || after.receipt != nil || !bytes.Equal(after.ciphertext, provider.wire) || after.ciphertextGeneration == nil || *after.ciphertextGeneration != "1" || provider.generateCalls != 1 || provider.restoreCalls != 1 {
				t.Fatal("unresolved root link released or replaced retained custody")
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw); err == nil {
				t.Fatal("schema permitted pending/unknown ciphertext erasure")
			}
		})
	}
}

func TestAccountLinkTerminalWithoutOptionalPreparationSchema(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		name := "success"
		if refuse {
			name = "refusal"
		}
		t.Run(name, func(t *testing.T) {
			ctx, _, owner, provider, _, _, _ := newAccountLinkErasureFixture(t, false)
			provider.refuse = refuse
			// This is the existing already-issued root command, not opt-in
			// preparation. Its SQL must not reference absent optional columns.
			spec, _, _ := provider.generated.AccountLinkCounterCommand()
			command, err := identity.NewAccountLinkCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			result, err := owner.Execute(ctx, command)
			want := identity.CommitOutcomeCommitted
			if refuse {
				want = identity.CommitOutcomeNotCommitted
			}
			if result.Outcome != want || !refuse && err != nil {
				t.Fatal("ordinary account link required optional preparation columns", result.Outcome, err)
			}
			again, err := owner.Execute(ctx, command)
			if err != nil || !reflect.DeepEqual(again, result) {
				t.Fatal("ordinary root terminal replay changed", err)
			}
		})
	}
}

func TestAccountLinkErasureLeavesOtherPreparationProfilesUnchanged(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, oauthRPPreparationErasureSQL, accountLinkPreparationSchemaSQL} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal(err)
		}
	}
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	for _, profile := range []int16{1, 2, 3, 4} {
		q, result := terminalCreation(t)
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		spec, _ := q.source.CreateUser()
		spec.Binding.CommandID = id
		command, err := identity.NewUserCreationCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		q, err = prepareClaim(command, keys.retained[keys.current])
		if err != nil {
			t.Fatal(err)
		}
		result.Binding = spec.Binding
		owner := [16]byte{1}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		d, err := lockCommandClaim(ctx, tx, q, keys)
		if err != nil {
			t.Fatal(err)
		}
		r, err := reservePreparationJournal(ctx, tx, q, d, owner, time.Minute, profile)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(id))
		if profile >= 3 {
			if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
		}
		if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
			t.Fatal(err)
		}
		ciphertext := []byte("synthetic-other-profile-ciphertext")
		if err := retainJournalPreparation(ctx, tx, q, r.journal, owner, ciphertext); err != nil {
			t.Fatal(err)
		}
		if err := terminalizeJournal(ctx, tx, q, r.journal, owner, result, "committed"); err != nil {
			t.Fatal("unrelated preparation could not terminalize", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var stored []byte
		var generation *string
		if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text FROM identity.commands WHERE command_id=$1`, raw).Scan(&stored, &generation); err != nil || !bytes.Equal(stored, ciphertext) || generation == nil || *generation != "1" {
			t.Fatal("account-link cleanup changed another profile's retained output", profile, err)
		}
	}
	const snapshot = `SELECT json_agg(j ORDER BY command_id)::text FROM identity.commands j`
	var before, after string
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	installAccountLinkErasure(t, ctx, pool)
	if err := pool.Raw().QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("forward erasure migration changed populated legacy rows", err)
	}
}

func TestAccountLinkErasurePreservesRPStartTerminalErasure(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, oauthRPPreparationErasureSQL, accountLinkPreparationSchemaSQL} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal(err)
		}
	}
	installAccountLinkErasure(t, ctx, pool)
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	for _, anonymous := range []bool{false, true} {
		for _, profile := range []int16{1, 2, 3, 4} {
			binding, _, _ := oauthRPPreparationFixture(t, anonymous)
			var err error
			binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := oauthRPInitiationOperation(anonymous)
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: featureCodecSpec().Fields})
			q, err := prepareClaim(command, keys.retained[keys.current])
			if err != nil {
				t.Fatal(err)
			}
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
			raw, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
			if profile >= 3 {
				if _, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration='\xa0'::bytea WHERE command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
				t.Fatal(err)
			}
			if err := retainJournalPreparation(ctx, tx, q, r.journal, owner, []byte("synthetic-encrypted-rp-custody")); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `UPDATE identity.commands SET command_plan='\xa0'::bytea WHERE command_id=$1`, raw); err != nil {
				t.Fatal(err)
			}
			result := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: op}}
			if err := terminalizeJournal(ctx, tx, q, r.journal, owner, result, "denied"); err != nil {
				t.Fatal("forward link erasure revoked RP-start allowance", profile, err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			s := readAccountLinkErasureSnapshot(t, ctx, pool, binding.CommandID)
			if s.state != "aborted" || s.ciphertext != nil || s.ciphertextGeneration != nil || s.started != "1" {
				t.Fatal("RP-start terminal custody changed", profile)
			}
			replay, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer replay.Rollback(ctx)
			d, err = lockCommandClaim(ctx, replay, q, keys)
			if err != nil {
				t.Fatal(err)
			}
			again, err := reservePreparationJournal(ctx, replay, q, d, [16]byte{2}, time.Minute, profile)
			if err != nil || again.generate || again.output != nil || again.journal.result == nil || !reflect.DeepEqual(*again.journal.result, result) {
				t.Fatal("RP-start terminal replay changed", profile, err)
			}
			if err := replay.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}
