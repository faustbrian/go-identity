//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

type proxyForwardPhase struct {
	signinPreparationPhase
	decl         CommandPlan
	generate     func(context.Context, uint64) ([]byte, error)
	refuseCommit bool
}

func (*proxyForwardPhase) Descriptor() ContributorDescriptor { return OAuthProxyForwardDescriptor() }
func (*proxyForwardPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{OAuthProxyForwardOperation()}
}
func (*proxyForwardPhase) ValidateOAuthProxyForward(command identity.Command, plan CapabilityPlan) error {
	s, ok := command.Feature()
	if !ok || !validOAuthProxyForwardBinding(s.Binding) || plan.Purpose != oauthProxyForwardPurpose {
		return invalidWork()
	}
	return nil
}
func (p *proxyForwardPhase) AdmitFeaturePreparation(_ context.Context, w Work, _ identity.Command) error {
	_, _, _, err := w.FeatureScope(p)
	return err
}
func (p *proxyForwardPhase) PrepareFeatureAdmission(ctx context.Context, _ identity.Command) (FeaturePreparationAdmission, error) {
	return proxyForwardAdmission{generate: p.generate}, ctx.Err()
}
func (p *proxyForwardPhase) RestoreFeatureAdmission(ctx context.Context, _ identity.Command, _ uint64, _ []byte) (FeaturePreparationAdmission, error) {
	return proxyForwardAdmission{generate: p.generate}, ctx.Err()
}
func (p *proxyForwardPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, _ uint64, output []byte) (identity.Command, CommandPlan, error) {
	if ctx.Err() != nil || !bytes.Equal(output, []byte{7, 9}) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	return command, p.decl, nil
}
func (p *proxyForwardPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	consumed, err := w.OAuthProxyForwardConsumption(p)
	s, ok := command.Feature()
	if err != nil || !ok || consumed.Command != s.Binding || consumed.Plan.Purpose != oauthProxyForwardPurpose || consumed.Generation == 0 {
		return identity.FeatureReceipt{}, invalidWork()
	}
	output, _, err := w.FeaturePreparationOutput(p)
	if err != nil || !bytes.Equal(output, []byte{7, 9}) {
		return identity.FeatureReceipt{}, invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.proxy_test_outcomes(command_id) VALUES($1)`, string(s.Binding.CommandID))
	return identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: 1, AfterVersion: 2}, err
}
func (p *proxyForwardPhase) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	if p.refuseCommit {
		return identity.ForbiddenError{}
	}
	return nil
}

type proxyForwardAdmission struct {
	generate func(context.Context, uint64) ([]byte, error)
}

func (proxyForwardAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a proxyForwardAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.generate(ctx, generation)
}

func TestOAuthProxyForwardKeepsOriginalStateAcrossExternalOutcomes(t *testing.T) {
	for _, mode := range []string{"committed", "exchange-unknown", "late-rollback"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, repo := newAccountAuthorityStore(t)
			for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, `CREATE TABLE public.signin_preparation_state(command_id text PRIMARY KEY,fingerprint bytea NOT NULL,generation numeric NOT NULL,state text NOT NULL);
CREATE TABLE public.proxy_test_outcomes(command_id text PRIMARY KEY);
CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`} {
				if _, err := pool.Raw().Exec(ctx, schema); err != nil {
					t.Fatal("proxy fixture schema", err)
				}
			}
			binding, plan := proxyForwardPlanFixture(t)
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: plan.Feature.Operation})
			if err != nil {
				t.Fatal("proxy command", err)
			}
			native := &proxyForwardPhase{refuseCommit: mode == "late-rollback"}
			capability := &signinPreparationCapability{}
			registry, err := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, native, capability})
			if err != nil {
				t.Fatal("proxy contributor registry", err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			plan.Capability.ExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Second)
			plan.Audits[0].BindingDigest = securityAuditScopeDigest(binding, &plan.Feature.Operation, plan.SubjectType, featureAuditTargetID(binding, plan.Feature.Operation), audit.ActorService, "identity-feature-audit-binding-v1")
			native.decl = plan
			var attempts atomic.Int32
			native.generate = func(ctx context.Context, generation uint64) ([]byte, error) {
				var state string
				if attempts.Add(1) != 1 || generation != 1 || pool.Raw().QueryRow(ctx, `SELECT state FROM public.signin_preparation_state WHERE command_id=$1`, string(binding.CommandID)).Scan(&state) != nil || state != "reserved" {
					t.Error("provider work entered before acknowledged original reservation or repeated")
					return nil, invalidPreparation()
				}
				if mode == "exchange-unknown" {
					return nil, identity.UnavailableError{}
				}
				return []byte{7, 9}, nil
			}
			if generic, err := c.PrepareCommandPlan(binding, command, plan); err == nil {
				if _, _, err := c.ReserveCommand(ctx, binding, command, generic); err == nil {
					t.Fatal("ordinary reservation can bypass exact proxy preparation")
				}
			}
			result, err := c.ExecutePreparedFeature(ctx, command, plan)
			wantOutcome, wantState, wantEffects := identity.CommitOutcomeCommitted, "finalized", 1
			if mode != "committed" {
				wantOutcome, wantState, wantEffects = identity.CommitOutcomeUnknown, "reserved", 0
			}
			if result.Outcome != wantOutcome || attempts.Load() != 1 || (mode == "committed") != (err == nil) {
				t.Fatalf("unexpected execution outcome: %v, attempts %d, error %v", result.Outcome, attempts.Load(), err)
			}
			if mode != "committed" {
				id, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				query, _ := queryInputs(binding)
				recovered, err := c.recoverCommandReceipt(ctx, query)
				if err != nil || recovered.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("historical recovery released possible provider effects", recovered.Outcome, err)
				}
			}
			if mode != "late-rollback" { // Retained output can rebind; never generate again.
				replay, _ := c.ExecutePreparedFeature(ctx, command, plan)
				if attempts.Load() != 1 || mode == "committed" && replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("replay exchanged the code again or lost its confirmed receipt", replay.Outcome)
				}
			}
			var state string
			var effects, audits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT s.state,(SELECT count(*) FROM public.proxy_test_outcomes),(SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM public.identity_test_lifecycle) FROM public.signin_preparation_state s WHERE command_id=$1`, string(binding.CommandID)).Scan(&state, &effects, &audits, &events); err != nil || state != wantState || effects != wantEffects || audits != wantEffects || events != wantEffects {
				t.Fatal("proxy effect, audit, and original state escaped the expected atomic outcome", state, effects, audits, events, err)
			}
		})
	}
}
