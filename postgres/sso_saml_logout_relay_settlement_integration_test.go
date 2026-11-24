//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Exercise the real coordinator transaction with the existing transactional
// capability fixture and a minimal native owner. Signature verification and
// the production provider/issuer composition are separate integration seams.
type samlLogoutRelaySettlementSQL struct {
	samlLogoutRelaySettlementProbe
	intent                   SSOSAMLLogoutRelaySettlementIntent
	mode                     string
	applied, checked, denied bool
}

func (p *samlLogoutRelaySettlementSQL) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	intent := p.intent
	if p.mode == "ignore-denied-scope" {
		intent.ResponseDigest[0]++
		p.denied = w.RequireSSOSAMLLogoutRelaySettlement(ctx, p, command, intent) != nil
	} else if err := w.RequireSSOSAMLLogoutRelaySettlement(ctx, p, command, intent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_saml_settled(issue_id,command_id) VALUES($1,$2)`, spec.Binding.RecordID, string(spec.Binding.CommandID))
	p.applied = err == nil
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 1, AfterVersion: 2}, err
}

func (p *samlLogoutRelaySettlementSQL) CheckFeatureCommit(ctx context.Context, w Work, command identity.Command) error {
	if p.mode == "reconstructed-final" {
		spec, _ := command.Feature()
		rebuilt, err := identity.NewFeatureCommand(spec)
		if err != nil {
			return err
		}
		command = rebuilt
	}
	if err := w.RequireSSOSAMLLogoutRelaySettlement(ctx, p, command, p.intent); err != nil {
		return err
	}
	p.checked = true
	if p.mode == "late-native-denial" {
		return identity.ForbiddenError{}
	}
	return nil
}

func TestSSOSAMLLogoutRelaySettlementPostgres(t *testing.T) {
	ctx, pool, repo := anonymousKernelDatabase(t)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric);
CREATE TABLE public.identity_test_saml_settled(issue_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "lost-commit-acknowledgement", "ignore-denied-scope", "finalize-denial", "reconstructed-final", "late-native-denial"} {
		t.Run(mode, func(t *testing.T) {
			newID := func() identity.CommandID {
				t.Helper()
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				return id
			}
			intent := SSOSAMLLogoutRelaySettlementIntent{IssueCommandID: newID(), LocalCommandID: newID(), OrganizationID: "organization", ProviderID: "provider", RequestDigest: [32]byte{1}, ResponseDigest: [32]byte{2}, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(time.Minute)}
			fields, err := SSOSAMLLogoutRelaySettlementFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			op := SSOSAMLLogoutRelaySettlementOperation()
			b := codecBinding()
			b.CommandID = newID()
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			b.ActorID, b.ActorKind, b.LinkMode = "installed-saml-service", authorization.SubjectServiceAccount, 0
			b.RecordID, b.CorrelationID = string(intent.IssueCommandID), string(intent.LocalCommandID)
			owner := &samlLogoutRelaySettlementSQL{samlLogoutRelaySettlementProbe: samlLogoutRelaySettlementProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}, intent: intent, mode: mode}
			capability := &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-denial"}
			registry, err := NewContributorRegistry([]Contributor{repo, &anonymousCreationAuditPhase{}, &recoveryLifecyclePhase{}, owner, capability})
			if err != nil {
				t.Fatal(err)
			}
			executionPool := pool
			var fault *registrationCommitFault
			if mode == "lost-commit-acknowledgement" {
				var name string
				if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
					t.Fatal(err)
				}
				fault = &registrationCommitFault{marker: []byte("public.identity_test_saml_settled(")}
				executionPool, err = database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database, c.ConnConfig.DialFunc = name, fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := executionPool.Close(bounded); err != nil {
						t.Error("owned fault pool cleanup", err)
					}
				})
			}
			config := CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
			c, err := NewCoordinator(executionPool, registry, config)
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, "sso_saml_logout_request"
			lifecycle := SSOSAMLLogoutRelaySettlementLifecycle()
			plan.Lifecycle = &lifecycle
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
			grant := issuanceTestPlan().Grants[0]
			grant.CapabilityID, grant.Purpose, grant.ExpiresAt = "logout-proof-"+mode, ssoSAMLLogoutRelaySettlePurpose, intent.ExpiresAt
			plan.Capability = &grant
			prepare := func(binding identity.CommandBinding) (identity.Command, CommandPlan) {
				t.Helper()
				command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields})
				seed, err := securityMutationAudit(ctx, binding, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, plan.SubjectType, binding.RecordID, "protected", true)
				if err != nil {
					t.Fatal(err)
				}
				plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(binding, op, plan.SubjectType, seed)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := c.PrepareCommandPlan(binding, command, plan)
				if err != nil {
					t.Fatal("prepare settlement", err)
				}
				return command, prepared
			}
			command, prepared := prepare(b)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), string(grant.Purpose), grant.CapabilityID, grant.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, command, prepared)
			if err != nil {
				t.Fatal("reserve original proof", err)
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("begin exact settlement", err)
			}
			defer func() { _, _ = c.Abort(w, identity.UnavailableError{}) }()
			staged, applyErr := c.ApplyFeature(ctx, w, command)
			var result identity.CommandResult
			if applyErr == nil {
				result, err = c.Commit(w, staged)
			} else {
				result, err = c.Abort(w, applyErr)
			}
			success := mode == "commit" || fault != nil
			if fault != nil {
				if err == nil || result.Outcome != identity.CommitOutcomeUnknown || result.AuditEventID != "" || result.Feature == nil ||
					*result.Feature != (identity.FeatureReceipt{Operation: op}) || !fault.hit.Load() {
					t.Fatal("lost commit acknowledgement exposed a receipt or did not exercise uncertainty", result.Outcome, err)
				}
				c, err = NewCoordinator(pool, registry, config)
				if err != nil {
					t.Fatal(err)
				}
			} else if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.AfterVersion != 2) {
				t.Fatal("original response did not settle", err, result.Outcome)
			}
			if !success && (err == nil || result.Outcome == identity.CommitOutcomeCommitted) {
				t.Fatal("denied settlement committed", result.Outcome)
			}
			if owner.denied != (mode == "ignore-denied-scope") || owner.applied != (mode != "ignore-denied-scope") || owner.checked != (success || mode == "late-native-denial") {
				t.Fatal("wrong provisional Apply or final-check path", owner.applied, owner.checked, err)
			}
			if success {
				replayed, receipt, err := c.ReserveCommand(ctx, b, command, prepared)
				if err != nil || replayed.state != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || *receipt.Feature != (identity.FeatureReceipt{Operation: op, BeforeVersion: 1, AfterVersion: 2}) {
					t.Fatal("exact replay did not return the original terminal receipt", err)
				}
				foreign := b
				foreign.CommandID = newID()
				foreignCommand, foreignPlan := prepare(foreign)
				if second, receipt, err := c.ReserveCommand(ctx, foreign, foreignCommand, foreignPlan); err == nil || second.state != nil || receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("another command acquired consumed proof")
				}
			}
			var state string
			var effects, audits, lifecycleEvents int
			err = pool.Raw().QueryRow(ctx, `SELECT state,
(SELECT count(*) FROM public.identity_test_saml_settled WHERE issue_id=$2),
(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),
(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)
FROM identity.capability_recovery_fixture WHERE capability_id=$1`, grant.CapabilityID, b.RecordID, string(b.CommandID)).Scan(&state, &effects, &audits, &lifecycleEvents)
			if err != nil {
				t.Fatal(err)
			}
			if success && (state != "finalized" || effects != 1 || audits != 1 || lifecycleEvents != 1) ||
				!success && (state == "finalized" || state == "consuming" || effects != 0 || audits != 0 || lifecycleEvents != 0) {
				t.Fatalf("non-atomic settlement: proof=%s effect=%d audit=%d lifecycle=%d", state, effects, audits, lifecycleEvents)
			}
		})
	}
}
