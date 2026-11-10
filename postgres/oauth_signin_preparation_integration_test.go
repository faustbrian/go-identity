//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// These trusted participant fixtures prove reservation ordering in the real
// coordinator transaction, not provider authentication or a complete signin.
type signinPreparationPhase struct {
	oauthSigninAccountParticipant
	denyCommit bool
}

func (*signinPreparationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{oauthSigninAccountOperation()}
}
func (*signinPreparationPhase) ValidateFeaturePreparation(identity.Command, CommandPlan) error {
	return nil
}
func (*signinPreparationPhase) ValidateOAuthSigninConsumption(identity.Command, CapabilityPlan) error {
	return nil
}
func (p *signinPreparationPhase) AdmitFeaturePreparation(_ context.Context, w Work, _ identity.Command) error {
	_, _, _, err := w.FeatureScope(p)
	return err
}
func (p *signinPreparationPhase) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	if p.denyCommit {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *signinPreparationPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	consumed, err := w.OAuthSigninConsumption(p)
	spec, ok := command.Feature()
	if err != nil || !ok || consumed.Command != spec.Binding || consumed.Plan.Purpose != "identity.oauth.callback" || consumed.Generation != 2 {
		return identity.FeatureReceipt{}, invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.signin_session_effect(command_id) VALUES($1)`, string(spec.Binding.CommandID))
	return identity.FeatureReceipt{Operation: spec.Operation}, err
}
func (*signinPreparationPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}
func (*signinPreparationPhase) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, error) {
	return identity.Command{}, CommandPlan{}, invalidPreparation()
}

type signinPreparationCapability struct {
	capabilityExecutionProbe
	reserves, rebinds int
	denyFinalize      bool
}

type signinPreparationCounter struct{ commandCounterProbe }

func (*signinPreparationCounter) CheckCommandCounters(context.Context, CommandCounterAdmissionWork) error {
	return nil
}

func (p *signinPreparationCapability) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	p.reserves++
	_, err = w.Exec(ctx, `INSERT INTO public.signin_preparation_state(command_id,fingerprint,generation,state) VALUES($1,$2,$3::numeric,'reserved')`, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	return err
}
func (p *signinPreparationCapability) RebindCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration == 0 {
		return invalidWork()
	}
	p.rebinds++
	n, err := w.Exec(ctx, `UPDATE public.signin_preparation_state SET generation=$3::numeric WHERE command_id=$1 AND fingerprint=$2 AND generation=$4::numeric`, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10))
	if err != nil || n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *signinPreparationCapability) ApplyCapability(ctx context.Context, w CapabilityApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.signin_preparation_state SET state='applied' WHERE command_id=$1 AND fingerprint=$2 AND generation=$3::numeric AND state='reserved'`, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	if err != nil || n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *signinPreparationCapability) FinalizeCapability(ctx context.Context, w CapabilityFinalizeWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if p.denyFinalize {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, `UPDATE public.signin_preparation_state SET state='finalized' WHERE command_id=$1 AND fingerprint=$2 AND generation=$3::numeric AND state='applied'`, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	if err != nil || n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *signinPreparationCapability) ReleaseCapability(ctx context.Context, w CapabilityReleaseWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE public.signin_preparation_state SET state='released' WHERE command_id=$1 AND fingerprint=$2 AND generation=$3::numeric AND state='reserved'`, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	if err != nil || n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func TestOAuthSigninPreparationReservesStateBeforeGenerationAndRebindsOnce(t *testing.T) {
	for _, mode := range []string{"committed", "late-native-denial", "finalization-denial"} {
		t.Run(mode, func(t *testing.T) {
			testOAuthSigninPreparedExecution(t, mode)
		})
	}
}

func testOAuthSigninPreparedExecution(t *testing.T, mode string) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, `CREATE TABLE public.signin_preparation_state(command_id text PRIMARY KEY,fingerprint bytea NOT NULL,generation numeric NOT NULL,state text NOT NULL);
CREATE TABLE public.signin_session_effect(command_id text PRIMARY KEY);
CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal("preparation schema", err)
		}
	}
	_, plan := oauthSigninConsumptionPlanFixture(t)
	phase := &signinPreparationPhase{denyCommit: mode == "late-native-denial"}
	capability := &signinPreparationCapability{denyFinalize: mode == "finalization-denial"}
	auditOwner, lifecycleOwner := &recoveryAuditPhase{}, &recoveryLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditOwner, lifecycleOwner, phase, &signinPreparationCounter{}, capability})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	spec, command := signinAccountCommand(t, signinAccountFixture())
	plan.Contributors = registry.Descriptors()
	plan.Capability.ExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Second)
	plan.Audits[0].BindingDigest = securityAuditScopeDigest(spec.Binding, &spec.Operation, plan.SubjectType, featureAuditTargetID(spec.Binding, spec.Operation), audit.ActorService, "identity-feature-audit-binding-v1")
	q, admitted, native, err := c.prepareFeaturePreparation(command, plan)
	if err != nil {
		t.Fatal("original callback cannot prepare", err)
	}
	firstOwner := [16]byte{1}
	first, _, err := c.startFeaturePreparation(ctx, command, q, admitted, native, firstOwner, false)
	if err != nil || !first.generate || first.journal.generation != 1 {
		t.Fatal("original start failed", err)
	}
	var generation string
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM public.signin_preparation_state WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&generation); err != nil || generation != "1" || capability.reserves != 1 || capability.rebinds != 0 {
		t.Fatal("acknowledged generation began without original state reservation", err)
	}
	// The one-use state must already be durable before Generate can exchange a
	// provider code. Retain output, expire its owner and resume that same output.
	wire := []byte{1, 2, 3}
	if err := c.retainFeaturePreparation(ctx, q, first.journal, firstOwner, wire); err != nil {
		t.Fatal(err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	query, _ := queryInputs(spec.Binding)
	if result, err := c.recoverCommandReceipt(ctx, query); err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("metadata recovery treated unattached external exchange as rollback", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM public.signin_preparation_state WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&generation); err != nil || generation != "1" {
		t.Fatal("metadata recovery changed original-state custody", err)
	}
	secondOwner := [16]byte{2}
	resumed, _, err := c.startFeaturePreparation(ctx, command, q, admitted, native, secondOwner, false)
	if err != nil || resumed.generate || resumed.outputGeneration != 1 || resumed.journal.generation != 2 || capability.reserves != 1 || capability.rebinds != 1 {
		t.Fatal("retained preparation failed to transfer original reservation once", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT generation::text FROM public.signin_preparation_state WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&generation); err != nil || generation != "2" {
		t.Fatal("resumed owner lacks durable original-state custody", err)
	}
	generated, final, _, err := c.prepareRestoredFeature(spec.Binding, command, plan)
	if err != nil {
		t.Fatal("same original restored declaration", err)
	}
	reservation, err := c.attachFeaturePreparation(ctx, q, generated, final, resumed, secondOwner, wire)
	if err != nil || reservation.state == nil || capability.reserves != 1 || capability.rebinds != 1 {
		t.Fatal("attachment tried to reserve/rebind already-owned state again", err)
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		t.Fatal("attached original callback cannot begin", err)
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err := c.ApplyFeature(ctx, w, command)
	if err != nil {
		t.Fatal("actual callback dispatch did not provisionally consume state before native Apply", err)
	}
	result, err = c.Commit(w, result)
	wantState, wantEffects, wantLifecycle := "finalized", 1, 1
	if mode == "committed" {
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("selected callback did not finalize atomically", err)
		}
	} else {
		wantState, wantEffects, wantLifecycle = "released", 0, 0
		if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("late denial did not establish protected rollback", err)
		}
	}
	var state string
	var effects, audits, events int
	if err := pool.Raw().QueryRow(ctx, `SELECT s.state,(SELECT count(*) FROM public.signin_session_effect),(SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM public.identity_test_lifecycle) FROM public.signin_preparation_state s WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&state, &effects, &audits, &events); err != nil || state != wantState || effects != wantEffects || audits != 1 || events != wantLifecycle {
		t.Fatal("callback state/session/audit/lifecycle escaped atomic outcome", state, effects, audits, events, err)
	}
}
