//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

const sourceFenceTestOperation = "identity.apikey.source-authority-test"

// This test-only registered Work consumer performs no credential verification,
// key mutation or principal issuance. Its source was genuinely authenticated by
// authenticatedSourceBinding; production SourceAuthority owns all current facts.
type sourceFenceConsumer struct {
	service  *apikeypg.Service
	observed apikey.SourceAuthorityObservation
	command  identity.Command
	fail     bool
	invoked  bool
	scope    identity.CommandBinding
	scopeErr error
	fenceErr error
}

func (*sourceFenceConsumer) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
}
func (*sourceFenceConsumer) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/apikey", OperationID: sourceFenceTestOperation, SchemaID: "source-authority-test-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}}
}
func (p *sourceFenceConsumer) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.command || plan.Feature == nil || plan.Feature.Operation != p.FeatureOperations()[0] || plan.SubjectType != "api_key_source" {
		return identity.InvalidInputError{Field: "source_test_command"}
	}
	return nil
}
func (p *sourceFenceConsumer) ApplyFeature(ctx context.Context, work kernel.Work, _ identity.Command) (identity.FeatureReceipt, error) {
	p.invoked = true
	p.scope, _, _, p.scopeErr = work.FeatureScope(p)
	p.fenceErr = p.service.RequireSourceAuthority(ctx, work, p, p.observed)
	if p.fenceErr != nil {
		return identity.FeatureReceipt{}, p.fenceErr
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0]}, nil
}
func (p *sourceFenceConsumer) CheckFeatureCommit(ctx context.Context, work kernel.Work, _ identity.Command) error {
	return p.service.RequireSourceAuthority(ctx, work, p, p.observed)
}
func (*sourceFenceConsumer) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

type sourceFencePolicy struct{ binding apikey.SourceAuthorityBinding }

func (p sourceFencePolicy) Evaluate(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	owner := p.binding.Owner.Spec()
	outcome := authorization.Deny
	if request.Action == sourceFenceTestOperation && request.Tenant == authorization.TenantID(owner.TenantID) && request.Subject.Kind == authorization.SubjectAPIKey && request.Subject.ID == authorization.SubjectID(p.binding.KeyID) && request.Resource.Type == "identity.user" && request.Resource.ID == authorization.ResourceID(owner.UserID) {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome}, nil
}

// Scope probes admit the test operation regardless of principal so only the
// actual source fence, not outer admission policy, can reject a mismatched Work.
type sourceFenceScopeProbePolicy struct{}

func (sourceFenceScopeProbePolicy) Evaluate(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	outcome := authorization.Deny
	if request.Action == sourceFenceTestOperation {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome}, nil
}

func prepareSourceFence(t *testing.T, f nativeConsumerFixture, service *apikeypg.Service, observed apikey.SourceAuthorityObservation, fail bool) (*kernel.Coordinator, kernel.Work, identity.Command) {
	t.Helper()
	owner := observed.Binding.Owner.Spec()
	scope := identity.CommandBinding{TenantID: owner.TenantID, UserID: owner.UserID, ActorKind: authorization.SubjectAPIKey, ActorID: identity.ActorID(observed.Binding.KeyID)}
	coordinator, work, command, _ := prepareSourceFenceScope(t, f, service, observed, fail, scope, sourceFencePolicy{observed.Binding})
	return coordinator, work, command
}

func prepareSourceFenceScope(t *testing.T, f nativeConsumerFixture, service *apikeypg.Service, observed apikey.SourceAuthorityObservation, fail bool, scope identity.CommandBinding, evaluator authorization.Evaluator) (*kernel.Coordinator, kernel.Work, identity.Command, *sourceFenceConsumer) {
	t.Helper()
	participant := &sourceFenceConsumer{service: service, observed: observed, fail: fail}
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: f.config.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle, participant})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "source-work-test", Revision: 9, Evaluator: evaluator})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	config := f.config.Coordinator
	query, admission := *config.QueryPolicy, *config.AdmissionPolicy
	query.Authorization, admission.Authorization = policy, policy
	config.QueryPolicy, config.AdmissionPolicy = &query, &admission
	coordinator, err := kernel.NewCoordinator(f.pool, registry, config)
	if err != nil {
		t.Fatal(err)
	}
	op := participant.FeatureOperations()[0]
	id := commandID(t)
	binding := identity.CommandBinding{CommandID: id, TenantID: scope.TenantID, UserID: scope.UserID, ActorKind: scope.ActorKind, ActorID: scope.ActorID, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: f.config.PolicyID, PolicyVersion: f.config.PolicyVersion, CorrelationID: string(id)}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{{Name: "source.key", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(observed.Binding.KeyID)}}, {Name: "source.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: observed.Binding.AuthorityVersion}}, {Name: "source.deadline", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: observed.ValidUntil}}}})
	if err != nil {
		t.Fatal(err)
	}
	participant.command = command
	const event = "identity.api_key.source_observe"
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	actorKind := audit.ActorService
	if binding.ActorKind == authorization.SubjectUser {
		actorKind = audit.ActorHuman
	}
	seed, err := builder.Build(audit.RecordInput{
		OccurredAt: time.Now().UTC(), Action: event, Outcome: audit.OutcomeDenied, ReasonCode: "not_authorized",
		Actor:      audit.ActorInput{Kind: actorKind, ID: string(binding.ActorID)},
		Subject:    audit.SubjectInput{Type: "api_key_source", ID: string(binding.UserID)},
		Context:    audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID, CausationID: string(id)},
		Policy:     audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: strconv.FormatUint(binding.PolicyVersion, 10)},
		Changes:    audit.ChangeSetInput{NoChange: true},
		Attributes: map[string]string{"command.id": string(id), "aggregate.type": "api_key_source", "aggregate.id": string(binding.UserID), "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, op, "api_key_source", seed)
	if err != nil {
		t.Fatal(err)
	}
	plan := kernel.CommandPlan{
		Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: participant.Descriptor(), Operation: op}, SubjectType: "api_key_source",
		Lifecycle: &kernel.LifecyclePlan{EventType: "api_key.source_observed.v1"},
		Audits:    []kernel.AuditPlan{{EventType: event, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}},
	}
	plan, err = coordinator.PrepareCommandPlan(binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	reservation, _, err := coordinator.ReserveCommand(f.ctx, binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	work, err := coordinator.Begin(f.ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = coordinator.Abort(work, identity.UnavailableError{}) })
	return coordinator, work, command, participant
}

func TestNativeSourceAuthorityRejectsMismatchedRealWorkScope(t *testing.T) {
	f := setupNativeConsumer(t)
	service, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	binding := authenticatedSourceBinding(t, f, service)
	owner := binding.Owner.Spec()
	for _, mode := range []string{"human-actor", "basic-client-actor", "different-key-actor", "foreign-tenant", "foreign-user"} {
		t.Run(mode, func(t *testing.T) {
			observed, err := service.ObserveSourceAuthority(f.ctx, binding)
			if err != nil {
				t.Fatal(err)
			}
			scope := identity.CommandBinding{TenantID: owner.TenantID, UserID: owner.UserID, ActorKind: authorization.SubjectAPIKey, ActorID: identity.ActorID(binding.KeyID)}
			switch mode {
			case "human-actor":
				scope.ActorKind, scope.ActorID = authorization.SubjectUser, identity.ActorID(owner.UserID)
			case "basic-client-actor":
				scope.ActorKind, scope.ActorID = authorization.SubjectServiceAccount, "native-basic-client"
			case "different-key-actor":
				scope.ActorID = "another-api-key"
			case "foreign-tenant":
				scope.TenantID = "another-tenant"
			case "foreign-user":
				scope.UserID = "another-user"
			}
			coordinator, work, command, participant := prepareSourceFenceScope(t, f, service, observed, false, scope, sourceFenceScopeProbePolicy{})
			result, applyErr := coordinator.ApplyFeature(f.ctx, work, command)
			actual := participant.scope
			if !participant.invoked || participant.scopeErr != nil || actual.TenantID != scope.TenantID || actual.UserID != scope.UserID || actual.ActorKind != scope.ActorKind || actual.ActorID != scope.ActorID {
				t.Fatal("real participant invocation did not retain the intentionally mismatched scope", participant.scopeErr)
			}
			var forbidden identity.ForbiddenError
			if !errors.As(participant.fenceErr, &forbidden) || !errors.As(applyErr, &forbidden) || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("actual source fence accepted another actor/owner or failed before its scope guard", mode, applyErr)
			}
		})
	}
}

func TestNativeSourceAuthorityExistingWorkAndFinalDeadline(t *testing.T) {
	f := setupNativeConsumer(t)
	service, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	binding := authenticatedSourceBinding(t, f, service)
	for _, mode := range []string{"current", "rollback", "final-deadline", "lock-deadline"} {
		t.Run(mode, func(t *testing.T) {
			observed, err := service.ObserveSourceAuthority(f.ctx, binding)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "final-deadline" || mode == "lock-deadline" {
				observed.ValidUntil = time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
			}
			coordinator, work, command := prepareSourceFence(t, f, service, observed, mode == "rollback")
			if mode == "lock-deadline" {
				requireSourceLockDeadline(t, f, coordinator, work, command, observed)
				return
			}
			result, applyErr := coordinator.ApplyFeature(f.ctx, work, command)
			if mode == "rollback" {
				if applyErr == nil {
					t.Fatal("required native consumer failure was ignored")
				}
				return
			}
			if applyErr != nil {
				t.Fatal("exact API-key actor could not use existing Work fence", applyErr)
			}
			if mode == "final-deadline" {
				timer := time.NewTimer(time.Until(observed.ValidUntil) + 10*time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-f.ctx.Done():
					t.Fatal(f.ctx.Err())
				}
			}
			committed, commitErr := coordinator.Commit(work, result)
			if mode == "current" {
				if commitErr != nil || committed.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("current source fence prevented known commit", commitErr)
				}
			} else if commitErr == nil || committed.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("post-Apply expiry survived final current-source check", commitErr)
			}
		})
	}
	current, err := service.ObserveSourceAuthority(f.ctx, binding)
	if err != nil || current.Record.AuthorityVersion != binding.AuthorityVersion || current.Record.RootVersion != binding.RootVersion {
		t.Fatal("source fence changed or stranded the original key", err)
	}
	if err := service.RequireSourceAuthority(f.ctx, kernel.Work{}, nil, current); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("source fence accepted absent native participant", err)
	}
}

func requireSourceLockDeadline(t *testing.T, f nativeConsumerFixture, coordinator *kernel.Coordinator, work kernel.Work, command identity.Command, observed apikey.SourceAuthorityObservation) {
	t.Helper()
	locker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackSourceProbe(locker)
	if _, err := locker.Exec(f.ctx, `SELECT configuration_id FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2 FOR UPDATE`, baselineTenant, observed.Binding.ConfigurationAuthority.ConfigurationID); err != nil {
		t.Fatal(err)
	}
	type completion struct {
		result identity.CommandResult
		err    error
	}
	done := make(chan completion, 1)
	received := false
	go func() {
		result, err := coordinator.ApplyFeature(f.ctx, work, command)
		done <- completion{result, err}
	}()
	defer func() {
		rollbackSourceProbe(locker)
		if !received {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("source fence worker did not join after lock cleanup")
			}
		}
	}()
	// Verify a real PostgreSQL lock wait, not merely a delayed goroutine.
	blocked := false
	for deadline := time.Now().Add(750 * time.Millisecond); time.Now().Before(deadline); {
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT authority_version::text,configuration_digest,enabled FROM identity_api_keys.configurations%')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case result := <-done:
			received = true
			t.Fatal("source fence completed before the actual blocking lock released", result.err)
		case <-time.After(5 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		}
	}
	if !blocked {
		t.Fatal("source fence did not reach its real configuration lock wait")
	}
	timer := time.NewTimer(time.Until(observed.ValidUntil) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	if err := locker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-done:
		received = true
		if out.err == nil || out.result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("configuration lock wait renewed original source validity", out.err)
		}
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
}

func rollbackSourceProbe(tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(cleanup)
}

func TestNativeSourceAuthorityWithdrawnEpochs(t *testing.T) {
	for _, mode := range []string{"directory", "user", "policy", "configuration", "unrelated-key", "permissions"} {
		t.Run(mode, func(t *testing.T) {
			f := setupNativeConsumer(t)
			service, err := apikeypg.NewService(f.pool, f.config)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
				t.Fatal(err)
			}
			binding := authenticatedSourceBinding(t, f, service)
			observed, err := service.ObserveSourceAuthority(f.ctx, binding)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "directory":
				// Negative infrastructure probes only withdraw genuine primary
				// authority. They create/restore no identity and prove no admin API.
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id=$1`, baselineTenant)
			case "user":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, baselineTenant, string(f.user))
			case "configuration":
				_, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=false,authority_version=authority_version+1 WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, binding.ConfigurationAuthority.ConfigurationID)
			case "policy":
				f.deniedGrant.Store(true)
				writer, beginErr := f.pool.Raw().Begin(f.ctx)
				if beginErr != nil {
					t.Fatal(beginErr)
				}
				defer rollbackSourceProbe(writer)
				scope := authority.AuthorityScope{TenantID: baselineTenant, PolicyNamespace: f.config.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(f.user)}
				_, err = authority.AdvanceAuthority(f.ctx, writer, scope, observed.AuthorizationVersion, time.Second)
				if err == nil {
					err = writer.Commit(f.ctx)
				}
			case "unrelated-key":
				other := metadataIssue(t, f, service, f.caller, "unrelated-source-key")
				key, _ := identity.NewIdempotencyKey([]byte("unrelated-original-revoke"))
				_, err = service.Revoke(f.ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: key, KeyID: other.ID, ExpectedVersion: other.Version, Network: "192.0.2.1"})
			case "permissions":
				key, _ := identity.NewIdempotencyKey([]byte("source-original-permission-narrowing"))
				_, err = service.Update(f.ctx, apikey.UpdateRequest{Authentication: f.caller, IdempotencyKey: key, KeyID: binding.KeyID, ExpectedVersion: observed.Record.Version, Name: observed.Record.Name, Permissions: []string{"invoice.read"}, Network: "192.0.2.1"})
			}
			if err != nil {
				t.Fatal("real source authority withdrawal failed", err)
			}
			coordinator, work, command := prepareSourceFence(t, f, service, observed, false)
			result, err := coordinator.ApplyFeature(f.ctx, work, command)
			if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("old observation survived actual current-owner withdrawal", mode, err)
			}
			fresh, freshErr := service.ObserveSourceAuthority(f.ctx, binding)
			switch mode {
			case "unrelated-key":
				if freshErr != nil || fresh.ConfigurationAuthority.Version <= observed.ConfigurationAuthority.Version || fresh.Record.AuthorityVersion != binding.AuthorityVersion {
					t.Fatal("another key's aggregate mutation revoked this independent root", freshErr)
				}
			case "policy":
				if freshErr != nil || len(fresh.Grant) != 1 || fresh.Grant[0] != "invoice.read" || fresh.AuthorizationVersion <= observed.AuthorizationVersion {
					t.Fatal("fresh policy observation retained withdrawn permissions", freshErr)
				}
			default:
				if freshErr == nil || fresh.Record.ID != "" || len(fresh.Grant) != 0 {
					t.Fatal("withdrawn source disclosed current authority", mode, freshErr)
				}
			}
		})
	}
}
