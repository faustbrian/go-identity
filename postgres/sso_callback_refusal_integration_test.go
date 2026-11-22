//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This trusted native fixture isolates the actual preparation cutover and
// transaction. It does not establish provider authentication or session safety.
type ssoCallbackRefusalPhase struct {
	*enterpriseSigninPreparation
	pool                                                       *database.Pool
	command                                                    identity.Command
	plan                                                       CommandPlan
	mode                                                       string
	prepareCalls, generateCalls, finalRestores, applyCalls     int
	oidcRestores, oauth2Restores, oidcCleanups, oauth2Cleanups int
}

func (p *ssoCallbackRefusalPhase) AdmitFeaturePreparation(_ context.Context, w Work, _ identity.Command) error {
	_, _, _, err := w.FeatureScope(p)
	return err
}

func (p *ssoCallbackRefusalPhase) PrepareFeatureAdmission(ctx context.Context, _ identity.Command) (FeaturePreparationAdmission, error) {
	p.prepareCalls++
	return ssoCallbackRefusalAdmission{p}, ctx.Err()
}

func (*ssoCallbackRefusalPhase) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error) {
	return nil, invalidPreparation()
}

type ssoCallbackRefusalAdmission struct{ phase *ssoCallbackRefusalPhase }

func (ssoCallbackRefusalAdmission) Check(ctx context.Context) error { return ctx.Err() }

func (a ssoCallbackRefusalAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	p := a.phase
	p.generateCalls++
	spec, _ := p.command.Feature()
	var state, reservedGeneration string
	if err := p.pool.Raw().QueryRow(ctx, `SELECT state,generation::text FROM public.signin_preparation_state WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&state, &reservedGeneration); err != nil || state != "reserved" || reservedGeneration != "1" || generation != 1 {
		return nil, invalidPreparation()
	}
	if p.mode == "generation-error" {
		return nil, identity.UnavailableError{}
	}
	return []byte("synthetic-sealed-enterprise-callback-output"), nil
}

func (p *ssoCallbackRefusalPhase) RestoreSSOOIDCPreparationRefusal(ctx context.Context, command identity.Command, generation uint64, wire []byte) (bool, error) {
	p.oidcRestores++
	if p.oauth2 {
		return false, invalidPreparation()
	}
	return p.restoreRefusal(ctx, command, generation, wire)
}

func (p *ssoCallbackRefusalPhase) RestoreSSOOAuth2PreparationRefusal(ctx context.Context, command identity.Command, generation uint64, wire []byte) (bool, error) {
	p.oauth2Restores++
	if !p.oauth2 {
		return false, invalidPreparation()
	}
	return p.restoreRefusal(ctx, command, generation, wire)
}

func (p *ssoCallbackRefusalPhase) restoreRefusal(ctx context.Context, command identity.Command, generation uint64, wire []byte) (bool, error) {
	spec, ok := command.Feature()
	original, _ := p.command.Feature()
	if ctx.Err() != nil || !ok || spec.Binding != original.Binding || spec.Operation != original.Operation || generation != 1 || !bytes.Equal(wire, []byte("synthetic-sealed-enterprise-callback-output")) || p.mode == "refusal-auth-error" {
		return false, invalidPreparation()
	}
	return p.mode != "success", nil
}

func (p *ssoCallbackRefusalPhase) CleanupSSOOIDCPreparationRefusal(ctx context.Context, w Work) error {
	p.oidcCleanups++
	if p.oauth2 {
		return invalidWork()
	}
	return p.cleanupRefusal(ctx, w)
}

func (p *ssoCallbackRefusalPhase) CleanupSSOOAuth2PreparationRefusal(ctx context.Context, w Work) error {
	p.oauth2Cleanups++
	if !p.oauth2 {
		return invalidWork()
	}
	return p.cleanupRefusal(ctx, w)
}

func (p *ssoCallbackRefusalPhase) cleanupRefusal(ctx context.Context, w Work) error {
	binding, _, _, err := w.FeatureScope(p)
	if err != nil {
		return err
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.sso_refusal_cleanup(command_id) VALUES($1)`, string(binding.CommandID)); err != nil {
		return err
	}
	if p.mode == "cleanup-error" {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *ssoCallbackRefusalPhase) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, error) {
	p.finalRestores++
	return p.command, p.plan, nil
}

func (p *ssoCallbackRefusalPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	consume := w.SSOOIDCSigninConsumption
	if p.oauth2 {
		consume = w.SSOOAuth2SigninConsumption
	}
	consumed, err := consume(p)
	spec, ok := command.Feature()
	if err != nil || !ok || consumed.Command != spec.Binding || consumed.Generation != 1 {
		return identity.FeatureReceipt{}, invalidWork()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.signin_session_effect(command_id) VALUES($1)`, string(spec.Binding.CommandID))
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 1, AfterVersion: 2}, err
}

func ssoCallbackRefusalFixture(t *testing.T, oauth2 bool, mode string) (context.Context, *Coordinator, *ssoCallbackRefusalPhase, *signinPreparationCapability) {
	t.Helper()
	ctx, pool, repo := newAccountAuthorityStore(t)
	for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, ssoOAuth2CallbackPreparationErasureSQL, `CREATE TABLE public.signin_preparation_state(command_id text PRIMARY KEY,fingerprint bytea NOT NULL,generation numeric NOT NULL,state text NOT NULL);
CREATE TABLE public.signin_session_effect(command_id text PRIMARY KEY);
CREATE TABLE public.sso_refusal_cleanup(command_id text PRIMARY KEY);
CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`} {
		if _, err := pool.Raw().Exec(ctx, schema); err != nil {
			t.Fatal("install callback refusal fixture", err)
		}
	}
	binding, plan := ssoOIDCSigninPlanFixture(t)
	if oauth2 {
		binding, plan = ssoOAuth2SigninPlanFixture(t)
	}
	_, source := signinAccountCommand(t, signinAccountFixture())
	cookie, _ := source.PreAuthCookie()
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: plan.Feature.Operation}, cookie)
	if err != nil {
		t.Fatal("construct original callback", err)
	}
	p := &ssoCallbackRefusalPhase{enterpriseSigninPreparation: &enterpriseSigninPreparation{signinPreparationPhase: &signinPreparationPhase{}, oauth2: oauth2}, pool: pool, command: command, mode: mode}
	capability := &signinPreparationCapability{}
	registry, err := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, p, capability})
	if err != nil {
		t.Fatal("register original callback owners", err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	plan.Contributors = registry.Descriptors()
	plan.Capability.ExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Second)
	plan.Audits[0].BindingDigest = securityAuditScopeDigest(binding, &plan.Feature.Operation, plan.SubjectType, featureAuditTargetID(binding, plan.Feature.Operation), audit.ActorService, "identity-feature-audit-binding-v1")
	p.plan = plan
	return ctx, c, p, capability
}

func TestSSOCallbackPreparationRefusal(t *testing.T) {
	for _, protocol := range []string{"oidc", "oauth2"} {
		for _, mode := range []string{"refused", "success", "generation-error", "refusal-auth-error", "cleanup-error", "lost-refusal-commit-ack"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				ctx, c, phase, capability := ssoCallbackRefusalFixture(t, protocol == "oauth2", mode)
				if mode == "lost-refusal-commit-ack" {
					c.preparationCommit = func(ctx context.Context, tx pgx.Tx) error {
						if err := tx.Commit(ctx); err != nil {
							return err
						}
						if phase.oidcCleanups+phase.oauth2Cleanups != 0 {
							return identity.UnavailableError{}
						}
						return nil
					}
				}
				result, err := c.ExecutePreparedFeature(ctx, phase.command, phase.plan)
				wantState, wantReservation := "pending", "reserved"
				wantAudit, wantCleanup, wantSession, wantLifecycle := 0, 0, 0, 0
				switch mode {
				case "refused":
					if !errors.As(err, new(identity.ForbiddenError)) || result.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("definitive refusal did not settle original preparation", result.Outcome, err)
					}
					wantState, wantReservation, wantAudit, wantCleanup = "aborted", "released", 1, 1
				case "success":
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("non-refusal output did not reach original Apply", result.Outcome, err)
					}
					wantState, wantReservation, wantAudit, wantSession, wantLifecycle = "committed", "finalized", 1, 1, 1
				default:
					if !errors.As(err, new(identity.UnknownCommitError)) || result.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("uncertain callback was misclassified as definitive", result.Outcome, err)
					}
					if mode == "lost-refusal-commit-ack" {
						wantState, wantReservation, wantAudit, wantCleanup = "aborted", "released", 1, 1
					}
				}
				spec, _ := phase.command.Feature()
				raw, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
				var state, reservation string
				var output, finalPlan, receipt []byte
				var audits, cleanups, sessions, lifecycle int
				if err := phase.pool.Raw().QueryRow(ctx, `SELECT state,preparation_ciphertext,command_plan,result,(SELECT state FROM public.signin_preparation_state WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM public.sso_refusal_cleanup),(SELECT count(*) FROM public.signin_session_effect),(SELECT count(*) FROM public.identity_test_lifecycle) FROM identity.commands WHERE command_id=$1`, raw, string(spec.Binding.CommandID)).Scan(&state, &output, &finalPlan, &receipt, &reservation, &audits, &cleanups, &sessions, &lifecycle); err != nil {
					t.Fatal("read original callback outcome", err)
				}
				if state != wantState || reservation != wantReservation || audits != wantAudit || cleanups != wantCleanup || sessions != wantSession || lifecycle != wantLifecycle || output != nil {
					t.Fatal("callback refusal escaped atomic custody", state, reservation, audits, cleanups, sessions, lifecycle)
				}
				if mode != "success" && finalPlan != nil || (state == "pending") != (receipt == nil) {
					t.Fatal("refusal attached execution or fabricated a receipt")
				}
				if protocol == "oauth2" && (phase.oidcRestores != 0 || phase.oidcCleanups != 0) || protocol == "oidc" && (phase.oauth2Restores != 0 || phase.oauth2Cleanups != 0) {
					t.Fatal("refusal crossed exact protocol ownership")
				}
				wantRestores := 1
				if mode == "generation-error" {
					wantRestores = 0
				}
				if phase.oidcRestores+phase.oauth2Restores != wantRestores || phase.finalRestores != wantSession || phase.applyCalls != wantSession || capability.reserves != 1 || capability.rebinds != 0 {
					t.Fatal("preparation bypassed refusal dispatch or repeated original state reservation")
				}
				replay, replayErr := c.ExecutePreparedFeature(ctx, phase.command, phase.plan)
				if state == "pending" {
					if replayErr != nil || replay.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("uncertain callback did not retain original pending custody", replay.Outcome, replayErr)
					}
				} else if state == "aborted" {
					// Legacy replay returns the persisted receipt, not the initial
					// invocation's transient ForbiddenError.
					want := featureOutcome(spec.Binding, &spec.Operation, identity.CommitOutcomeNotCommitted, 0)
					if replayErr != nil || !reflect.DeepEqual(replay, want) {
						t.Fatal("terminal refusal replay lost original denial", replay.Outcome, replayErr)
					}
				} else if replayErr != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("successful original callback replay changed", replay.Outcome, replayErr)
				}
				if phase.prepareCalls != 1 || phase.generateCalls != 1 || phase.oidcRestores+phase.oauth2Restores != wantRestores || phase.finalRestores != wantSession || phase.applyCalls != wantSession {
					t.Fatal("replay repeated admission, generation or native dispatch")
				}
			})
		}
	}
}
