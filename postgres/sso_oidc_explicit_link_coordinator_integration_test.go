//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// The trusted native seam supplies original callback admission, not provider
// authentication. Identity's actual writer and coordinator own link atomicity.
type explicitLinkCoordinatorPhase struct {
	enterpriseSigninAuthenticationPreparation
	repository         *Repository
	intent             SSOOIDCExplicitLinkIntent
	plan               CommandPlan
	withdrawActor      bool
	checkedCommit      bool
	withdrewActor      bool
	successAuditID     string
	provisionalAccount ProviderAccountAdmission
}

func (*explicitLinkCoordinatorPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{SSOOIDCExplicitLinkCallbackOperation()}
}

func (*explicitLinkCoordinatorPhase) ValidateSSOOIDCExplicitLinkConsumption(command identity.Command, plan CapabilityPlan) error {
	spec, ok := command.Feature()
	if !ok || !validSSOOIDCExplicitLinkBinding(spec.Binding) || plan.Purpose != ssoOIDCSigninPurpose {
		return invalidWork()
	}
	return nil
}

func (p *explicitLinkCoordinatorPhase) AdmitFeaturePreparation(_ context.Context, w Work, _ identity.Command) error {
	_, _, _, err := w.FeatureScope(p)
	return err
}

type explicitLinkCoordinatorAdmission struct{ signinPreparationAdmission }

func (explicitLinkCoordinatorAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if generation != 1 {
		return nil, invalidPreparation()
	}
	return []byte{1, 2, 3}, ctx.Err()
}

func (*explicitLinkCoordinatorPhase) PrepareFeatureAdmission(ctx context.Context, _ identity.Command) (FeaturePreparationAdmission, error) {
	return explicitLinkCoordinatorAdmission{}, ctx.Err()
}

func (p *explicitLinkCoordinatorPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	if generation != 1 || !bytes.Equal(wire, []byte{1, 2, 3}) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	return command, p.plan, ctx.Err()
}

func (p *explicitLinkCoordinatorPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	linked, err := p.repository.ApplySSOOIDCExplicitLink(ctx, w, p, command, p.intent)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.provisionalAccount = linked
	return identity.FeatureReceipt{Operation: SSOOIDCExplicitLinkCallbackOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *explicitLinkCoordinatorPhase) CheckFeatureCommit(ctx context.Context, w Work, command identity.Command) error {
	binding, feature, _, err := w.FeatureScope(p)
	spec, ok := command.Feature()
	if err != nil || !ok || binding != spec.Binding || feature.Operation != spec.Operation {
		return invalidWork()
	}
	p.checkedCommit = true
	rows, err := w.Query(ctx, `SELECT
 EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id='tenant-a' AND user_id='owner' AND account_id='enterprise-link' AND linked),
 u.version::text,u.credential_version::text,s.state,a.event_id,
 (SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)
 FROM identity.users u CROSS JOIN public.signin_preparation_state s
 JOIN public.identity_test_audits a ON a.command_id=s.command_id
 WHERE u.tenant_id='tenant-a' AND u.user_id='owner' AND s.command_id=$1`, string(binding.CommandID))
	if err != nil {
		return err
	}
	var linked bool
	var aggregate, epoch, state string
	var events int
	if !rows.Next() {
		rows.Close()
		return invalidWork()
	}
	err = rows.Scan(&linked, &aggregate, &epoch, &state, &p.successAuditID, &events)
	extra := rows.Next()
	rowsErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowsErr != nil || !linked || aggregate != "2" || epoch != "2" || state != "finalized" || p.successAuditID == "" || events != 1 {
		return invalidWork()
	}
	if p.withdrawActor {
		changed, err := w.Exec(ctx, `UPDATE identity.credential_references SET enabled=false
 WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='local-credential' AND enabled`)
		if err != nil {
			return err
		}
		if changed != 1 {
			return invalidWork()
		}
		p.withdrewActor = true
	}
	// A successful native return leaves the kernel's final authority check as
	// the only rejection point for the ordinary late credential withdrawal.
	return nil
}

func TestSSOOIDCExplicitLinkCoordinatorCommitsOrRollsBackLateActorWithdrawal(t *testing.T) {
	for _, withdrawActor := range []bool{false, true} {
		name := "committed"
		if withdrawActor {
			name = "late-actor-withdrawal"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool, repository := newAccountAuthorityStore(t)
			for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, ssoOIDCCallbackPreparationErasureSQL, `
CREATE TABLE public.signin_preparation_state(command_id text PRIMARY KEY,fingerprint bytea NOT NULL,generation numeric NOT NULL,state text NOT NULL);
CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
VALUES('tenant-a','owner','local-credential',1,'identity/password',1,true)`} {
				if _, err := pool.Raw().Exec(ctx, schema); err != nil {
					t.Fatal("explicit-link coordinator fixture", err)
				}
			}
			intent := enterpriseExplicitLinkIntent()
			intent.Change.Account.UserID, intent.Change.Method.Credential.UserID = "owner", "owner"
			intent.ActorCredential.Credential.UserID, intent.ActorCredential.Credential.Version = "owner", 1
			intent.ActorCredential.UserAuthorityVersion, intent.ActorCredential.IdentifierAuthorityVersion, intent.ActorCredential.CredentialAuthorityVersion = 1, 1, 1
			intent.Change.ExpectedUserVersion, intent.Change.ExpectedCredentialVersion = 1, 1
			intent.ValidUntil = time.Now().UTC().Truncate(time.Microsecond).Add(15 * time.Second)
			binding, plan := enterpriseExplicitLinkPlan(t)
			binding.ActorID, binding.UserID = "owner", "owner"
			plan.Capability.ExpiresAt = intent.ValidUntil.Add(time.Second).Truncate(time.Second)
			field, err := SSOOIDCExplicitLinkField(intent)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: binding, Operation: plan.Feature.Operation, Fields: []identity.FeatureField{field}},
				authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			phase := &explicitLinkCoordinatorPhase{
				enterpriseSigninAuthenticationPreparation: enterpriseSigninAuthenticationPreparation{&enterpriseSigninPreparation{signinPreparationPhase: &signinPreparationPhase{}}},
				repository: repository, intent: intent, withdrawActor: withdrawActor,
			}
			capability := &signinPreparationCapability{}
			registry, err := NewContributorRegistry([]Contributor{repository, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, phase, capability})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
				CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			plan.Audits[0].BindingDigest = securityAuditScopeDigest(binding, &plan.Feature.Operation, plan.SubjectType, featureAuditTargetID(binding, plan.Feature.Operation), audit.ActorHuman, "identity-feature-audit-binding-v1")
			phase.plan = plan
			prepared, err := coordinator.PrepareFeaturePreparationPlan(command, plan)
			if err != nil {
				t.Fatal("original explicit callback cannot prepare", err)
			}
			result, err := coordinator.ExecutePreparedFeature(ctx, command, prepared)
			if !phase.checkedCommit || phase.successAuditID == "" || phase.withdrewActor != withdrawActor {
				t.Fatal("callback did not reach the native final phase with provisional effects", err)
			}
			wantVersion, wantState, wantEffects := "2", "finalized", 1
			if withdrawActor {
				wantVersion, wantState, wantEffects = "1", "released", 0
				if !errors.As(err, new(identity.ForbiddenError)) || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("kernel final authority check failed to establish rollback", err)
				}
			} else if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("ordinary callback did not commit", err)
			}
			query := ProviderSigninAccountQuery{TenantID: binding.TenantID, Provider: intent.Change.Account.Provider, Issuer: intent.Change.Account.Issuer, Subject: intent.Change.Account.Subject}
			linked, lookupErr := repository.GetSSOOIDCSigninAccount(ctx, query)
			if withdrawActor {
				if !errors.As(lookupErr, new(identity.ForbiddenError)) {
					t.Fatal("rolled-back account became available for enterprise sign-in", lookupErr)
				}
			} else if lookupErr != nil || linked != phase.provisionalAccount || linked.Account != intent.Change.Account || linked.SocialLinkVersion != 2 || linked.Credential.Credential != intent.Change.Method.Credential || linked.Credential.CredentialAuthorityVersion != 2 {
				t.Fatal("committed account lost the exact existing-member successor", lookupErr)
			}
			var aggregate, epoch, state, auditID string
			var users, accounts, newCredentials, localCredentials, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,s.state,a.event_id,
 (SELECT count(*) FROM identity.users WHERE tenant_id='tenant-a'),
 (SELECT count(*) FROM identity.accounts),
 (SELECT count(*) FROM identity.credential_references WHERE credential_id='enterprise-credential'),
 (SELECT count(*) FROM identity.credential_references WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='local-credential' AND enabled),
 (SELECT count(*) FROM public.identity_test_lifecycle)
 FROM identity.users u CROSS JOIN public.signin_preparation_state s
 JOIN public.identity_test_audits a ON a.command_id=s.command_id
 WHERE u.tenant_id='tenant-a' AND u.user_id='owner' AND s.command_id=$1`, string(binding.CommandID)).Scan(
				&aggregate, &epoch, &state, &auditID, &users, &accounts, &newCredentials, &localCredentials, &events); err != nil {
				t.Fatal("durable explicit-link outcome", err)
			}
			if aggregate != wantVersion || epoch != wantVersion || state != wantState || users != 2 || accounts != wantEffects || newCredentials != wantEffects || localCredentials != 1 || events != wantEffects || capability.reserves != 1 || capability.rebinds != 0 {
				t.Fatal("link, epochs, original credential, one-use state or lifecycle escaped the atomic outcome")
			}
			if withdrawActor {
				if auditID == phase.successAuditID {
					t.Fatal("successful mutation audit survived denial")
				}
			} else if auditID != phase.successAuditID || auditID != result.AuditEventID {
				t.Fatal("committed receipt lost its successful mutation audit")
			}
		})
	}
}
