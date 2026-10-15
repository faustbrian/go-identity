//go:build integration

package passwordintegration_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Original native password comparison, signed-record issuance and primary
// verification are real. This first assertion is preparation only; atomic
// protected consumption is exercised by the companion coordinator cases.
func testNativeEmailPrimary(t *testing.T, ctx context.Context, pool *database.Pool, config passworddb.ReauthenticationConfig, verification passworddb.ReauthenticationRequest) {
	t.Helper()
	config.Targets = append(config.Targets, passworddb.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.email.change-request", Audience: "email-management"})
	source, err := passworddb.NewReauthenticationService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	verification.Target = config.Targets[len(config.Targets)-1]
	issued, err := source.Verify(ctx, verification)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real email-bound password proof", err)
	}
	primary, err := passworddb.NewEmailPrimarySource(source, passworddb.EmailPrimaryConfig{Action: "identity.email.change-request", Audience: "email-management", MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal("email primary composition", err)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request := passworddb.EmailPrimaryRequest{TenantID: verification.TenantID, CommandID: commandID, AddressID: "managed-email", Session: verification.Session, Proof: issued.Proof, Caller: verification.Caller}
	admission, err := primary.Prepare(ctx, request)
	if err != nil {
		t.Fatal("original email admission", err)
	}
	original, err := admission.Original()
	bindings, bindingErr := original.Bindings()
	deadline, deadlineErr := admission.Deadline()
	if err != nil || bindingErr != nil || deadlineErr != nil || bindings.SessionID != "reauth-session" || !deadline.Equal(issued.Proof.Proof.IssuedAt.Add(2*time.Minute)) {
		t.Fatal("email admission changed original session or freshness")
	}
	wrong := request
	wrong.Proof.Action = "identity.password.change"
	if _, err := primary.Prepare(ctx, wrong); err == nil {
		t.Fatal("foreign action became email authority")
	}
	wrong = request
	wrong.Proof.SessionVersion++
	if _, err := primary.Prepare(ctx, wrong); err == nil {
		t.Fatal("foreign session version became email authority")
	}
	wrong = request
	wrong.Caller.Request.Subject.ID = "another-user"
	if _, err := primary.Prepare(ctx, wrong); err == nil {
		t.Fatal("foreign actor became email authority")
	}
	connection, err := pgx.ParseConfig(pool.Raw().Config().ConnString())
	if err != nil {
		t.Fatal("native migration connection", err)
	}
	db := stdlib.OpenDB(*connection)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := backend.ForNamespace("identity_password")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(passworddb.EmailReauthenticationMigrationSource{}, owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("additive email proof history", err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("email proof history retry", err)
	}
	testEmailPrimaryAtomicConsumption(t, ctx, pool, config, primary, request)
}

// This native participant proves the kernel's real pending-email attachment,
// not a complete delivery/confirmation service. Original proof, current-primary,
// directory, coordinator, audit and outbox owners are real. A failure after all
// writes must roll back the proof and directory effects together.
type emailPrimaryFixturePhase struct {
	admission passworddb.EmailPrimaryAdmission
	command   identity.Command
	rollback  bool
	record    audit.Record
	domain    *kernel.EmailAttachmentDomain
	intent    kernel.EmailAttachmentIntent
}

func (*emailPrimaryFixturePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (p *emailPrimaryFixturePhase) FeatureOperations() []identity.FeatureOperation {
	spec, _ := p.command.Feature()
	return []identity.FeatureOperation{spec.Operation}
}
func (p *emailPrimaryFixturePhase) EmailAttachment(identity.Command) (kernel.EmailAttachmentIntent, *kernel.EmailAttachmentDomain, error) {
	return p.intent, p.domain, nil
}
func (p *emailPrimaryFixturePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.command || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.SubjectType != "identifier" || plan.Capability != nil || plan.OTP != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.attached.v1" || len(plan.Audits) != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *emailPrimaryFixturePhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.admission.Consume(ctx, work, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := command.Feature()
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 0, AfterVersion: 1}, nil
}
func (p *emailPrimaryFixturePhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if p.rollback {
		return identity.ForbiddenError{}
	}
	return p.admission.Check(ctx, work, p, command)
}
func (*emailPrimaryFixturePhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func testEmailPrimaryAtomicConsumption(t *testing.T, ctx context.Context, pool *database.Pool, config passworddb.ReauthenticationConfig, primary *passworddb.EmailPrimarySource, request passworddb.EmailPrimaryRequest) {
	t.Helper()
	history, err := (kernel.IdentifierMutationMigrationSource{Base: kernel.MigrationSource{}, Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'previous-email','email','previous@example.test','Previous@example.test',true,true,5,2,7,clock_timestamp())`, string(request.TenantID), string(request.Caller.Request.Subject.ID)); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, rollback bool, mutate func(*kernel.EmailAttachmentIntent)) (identity.CommandResult, error) {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		request.CommandID = id
		admission, err := primary.Prepare(ctx, request)
		if err != nil {
			return identity.CommandResult{Outcome: identity.CommitOutcomeNotCommitted}, err
		}
		op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-request", SchemaID: "identity.email.change-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		binding := identity.CommandBinding{CommandID: id, TenantID: request.TenantID, UserID: identity.UserID(request.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "email-management", PolicyVersion: 9, RecordID: string(request.AddressID), CorrelationID: string(id)}
		intent := kernel.EmailAttachmentIntent{Change: identity.IdentifierChange{TenantID: binding.TenantID, UserID: binding.UserID, ID: request.AddressID, Action: identity.IdentifierAttach, Kind: identity.IdentifierEmail, CanonicalValue: "managed@example.test", DisplayValue: "Managed@example.test", ExpectedUserVersion: 9, ExpectedAuthorityVersion: 4}, ComparisonProfile: "email-v1"}
		intent.Previous = kernel.ManagedEmailPrevious{ID: "previous-email", CanonicalAddress: "previous@example.test", IdentifierVersion: 5, VerificationVersion: 7, Primary: true}
		if mutate != nil {
			mutate(&intent)
		}
		fields, err := kernel.EmailAttachmentFields(intent)
		if err != nil {
			t.Fatal(err)
		}
		command, err := admission.Command(binding, fields)
		if err != nil {
			t.Fatal("native command construction", err)
		}
		phase := &emailPrimaryFixturePhase{admission: admission, command: command, rollback: rollback}
		domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		phase.domain, err = kernel.NewEmailAttachmentDomain(domain, kernel.EmailAttachmentDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {7}}})
		phase.intent = intent
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
		registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle, phase})
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := kernel.NewCoordinator(pool, registry, config.Coordinator)
		if err != nil {
			t.Fatal(err)
		}
		builder, err := audit.NewBuilder(audit.BuilderConfig{})
		if err != nil {
			t.Fatal(err)
		}
		phase.record, err = builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: binding.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "identifier", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "9"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "identifier", "aggregate.id": binding.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := kernel.FeatureAuditBindingDigest(binding, op, "identifier", phase.record)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := coordinator.PrepareCommandPlan(binding, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "identifier", Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "identifier.attached.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: binding.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native plan", err)
		}
		reservation, result, err := coordinator.ReserveCommand(ctx, binding, command, plan)
		if err != nil {
			return result, err
		}
		work, err := coordinator.Begin(ctx, reservation)
		if err != nil {
			return result, err
		}
		defer coordinator.Abort(work, identity.UnavailableError{})
		result, err = coordinator.ApplyFeature(ctx, work, command)
		if err != nil {
			return coordinator.Abort(work, err)
		}
		result, err = coordinator.Commit(work, result)
		return result, err
	}
	assertState := func(t *testing.T, used bool, count int) {
		t.Helper()
		var consumed bool
		var effects int
		if err := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL,(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$2 AND user_id=$3 AND identifier_id=$4 AND canonical_value='managed@example.test' AND display_value='Managed@example.test' AND NOT verified AND NOT is_primary AND version=1 AND verification_version=1 AND verification_state=1 AND verified_at IS NULL) FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(request.Proof.Proof.ID), string(request.TenantID), string(request.Caller.Request.Subject.ID), string(request.AddressID)).Scan(&consumed, &effects); err != nil || consumed != used || effects != count {
			t.Fatal("proof/effect atomicity", err)
		}
		var userVersion, identifierVersion string
		if err := pool.Raw().QueryRow(ctx, `SELECT version::text,identifier_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(request.Caller.Request.Subject.ID)).Scan(&userVersion, &identifierVersion); err != nil {
			t.Fatal(err)
		}
		if count == 0 && (userVersion != "9" || identifierVersion != "4") || count == 1 && (userVersion != "10" || identifierVersion != "5") {
			t.Fatal("kernel attachment did not preserve exact predecessor/successor epochs")
		}
		var original bool
		if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='previous-email' AND canonical_value='previous@example.test' AND display_value='Previous@example.test' AND verified AND is_primary AND version=5 AND verification_version=7)`, string(request.TenantID), string(request.Caller.Request.Subject.ID)).Scan(&original); err != nil || !original {
			t.Fatal("pending attachment changed the original verified primary", err)
		}
	}
	for name, mutate := range map[string]func(*kernel.EmailAttachmentIntent){
		"stale-user":                 func(i *kernel.EmailAttachmentIntent) { i.Change.ExpectedUserVersion = 10 },
		"stale-identifier-authority": func(i *kernel.EmailAttachmentIntent) { i.Change.ExpectedAuthorityVersion = 5 },
		"occupied-canonical-address": func(i *kernel.EmailAttachmentIntent) { i.Change.CanonicalValue = "previous@example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			result, err := run(t, false, mutate)
			if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("invalid directory predecessor committed", err)
			}
			assertState(t, false, 0)
		})
	}
	result, err := run(t, true, nil)
	if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("protected failure did not roll back", err)
	}
	assertState(t, false, 0)
	result, err = run(t, false, nil)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("protected commit", err)
	}
	assertState(t, true, 1)
	key, err := base64.RawURLEncoding.Strict().DecodeString(string(result.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var audits int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1`, key).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("required native audit", err)
	}
	result, err = run(t, false, nil)
	if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("used original proof committed a second effect", err)
	}
	assertState(t, true, 1)
}
