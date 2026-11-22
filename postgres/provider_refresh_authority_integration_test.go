//go:build integration

package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type providerRefreshAuthorityPhase struct {
	operation identity.FeatureOperation
	expected  ProviderAccountAdmission
	repeat    bool
}

func (*providerRefreshAuthorityPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.provider-refresh", Version: 1}
}

func (p *providerRefreshAuthorityPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation}
}

func (p *providerRefreshAuthorityPhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	spec, ok := c.Feature()
	if !ok || spec.Operation != p.operation || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != 7 || plan.Lifecycle.AfterVersion != 8 {
		return invalidPlan()
	}
	return nil
}

func (p *providerRefreshAuthorityPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	next, err := w.AdvanceProviderRefreshAuthority(ctx, p, c, p.expected)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if next != 4 {
		return identity.FeatureReceipt{}, fmt.Errorf("unexpected social-link successor: %d", next)
	}
	if p.repeat {
		second := p.expected
		second.SocialLinkVersion = next
		if _, err := w.AdvanceProviderRefreshAuthority(ctx, p, c, second); err == nil {
			return identity.FeatureReceipt{}, fmt.Errorf("one refresh command advanced twice")
		}
		// Ignoring the denied second write must still roll the first one back.
	}
	return identity.FeatureReceipt{Operation: p.operation, BeforeVersion: 7, AfterVersion: 8}, nil
}

func (*providerRefreshAuthorityPhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func TestProviderRefreshAuthorityAdvancesOnlyTheBoundCurrentLink(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
			t.Fatal("provider refresh authority fixture", err)
		}
	}
	exec(`CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
 CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
 INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version)
 VALUES('refresh','owner','active',101,11,13,17);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 VALUES('refresh','owner','provider-ref',3,'identity/oauth',7,true);
 WITH metadata AS (SELECT 'ordinary-oauth'::text AS provider,'https://issuer.example'::text AS issuer,'subject-one'::text AS subject)
 INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT 'refresh','owner','account',provider,issuer,subject,
 sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),5,3,true FROM metadata;
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 VALUES('refresh','owner','provider-ref','account')`)

	const refresh = "identity.account.refresh-token"
	for _, scenario := range []string{"commit", "audit-rollback", "wrong-operation", "wrong-account", "foreign-actor", "stale-account", "unlinked", "unbound-version", "second-bump"} {
		t.Run(scenario, func(t *testing.T) {
			exec(`UPDATE identity.accounts SET version=5,social_link_version=3,linked=true WHERE tenant_id='refresh'`)
			operation := identity.FeatureOperation{Owner: "identity/oauth", OperationID: refresh, SchemaID: "oauth-provider-refresh-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			expected := ProviderAccountAdmission{
				Account:           identity.Account{TenantID: "refresh", UserID: "owner", ID: "account", Provider: "ordinary-oauth", Issuer: "https://issuer.example", Subject: "subject-one", Version: 5},
				SocialLinkVersion: 3,
				Credential: CredentialAdmission{
					Credential:           identity.CredentialRef{TenantID: "refresh", UserID: "owner", ID: "provider-ref", Owner: "identity/oauth", Kind: identity.CredentialProvider, Version: 7},
					UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17,
				},
			}
			recordID, declaredSocialVersion := "account", uint64(3)
			switch scenario {
			case "wrong-operation":
				operation.OperationID = "identity.account.other-test"
			case "wrong-account":
				recordID = "other-account"
			case "stale-account":
				exec(`UPDATE identity.accounts SET version=6 WHERE tenant_id='refresh'`)
			case "unlinked":
				exec(`UPDATE identity.accounts SET linked=false WHERE tenant_id='refresh'`)
			case "unbound-version":
				declaredSocialVersion = 2
			}
			phase := &providerRefreshAuthorityPhase{operation: operation, expected: expected, repeat: scenario == "second-bump"}
			auditing := &recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: scenario == "audit-rollback"}}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, &recoveryLifecyclePhase{}, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			binding := identity.CommandBinding{CommandID: id, TenantID: "refresh", UserID: "owner", ActorID: "owner", ActorKind: authorization.SubjectUser, RecordID: recordID, OperationID: operation.OperationID, SchemaID: operation.SchemaID, SchemaVersion: 1, PolicyID: "refresh-policy", PolicyVersion: 1, CorrelationID: string(id)}
			if scenario == "foreign-actor" {
				binding.ActorID = "other-user"
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation, Fields: []identity.FeatureField{
				{Name: "provider-refresh.account-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 5}},
				{Name: "provider-refresh.social-link-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: declaredSocialVersion}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			audit, err := securityMutationAudit(ctx, binding, 7, 8, time.Now().UTC().Truncate(time.Microsecond), "committed", operation.OperationID, "account", recordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := FeatureAuditBindingDigest(binding, operation, "account", audit)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(binding, command, CommandPlan{
				Contributors: registry.Descriptors(), Feature: &FeatureRegistration{Contributor: phase.Descriptor(), Operation: operation}, SubjectType: "account",
				Lifecycle: &LifecyclePlan{EventType: "identity.account.provider-token-refreshed.v1", BeforeVersion: 7, AfterVersion: 8},
				Audits:    []AuditPlan{{EventType: operation.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}},
			})
			if err != nil {
				t.Fatal("prepare provider refresh authority", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, binding, command, plan)
			if err != nil {
				t.Fatal("reserve provider refresh authority", err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			result, commitErr := coordinator.Commit(work, result)
			if (result.Outcome == identity.CommitOutcomeCommitted) != (scenario == "commit") {
				t.Fatalf("unexpected outcome %v: apply=%v, commit=%v", result.Outcome, applyErr, commitErr)
			}
			wantSocial := "3"
			if scenario == "commit" {
				wantSocial = "4"
			}
			var social, credential, account string
			var enabled bool
			err = pool.Raw().QueryRow(ctx, `SELECT a.social_link_version::text,c.version::text,a.version::text,c.enabled FROM identity.accounts a JOIN identity.credential_references c USING(tenant_id,user_id) WHERE a.tenant_id='refresh'`).Scan(&social, &credential, &account, &enabled)
			wantAccount := "5"
			if scenario == "stale-account" {
				wantAccount = "6"
			}
			if err != nil || social != wantSocial || account != wantAccount || credential != "7" || !enabled {
				t.Fatalf("refresh authority changed unrelated state or missed the exact link: %v", err)
			}
		})
	}
}
