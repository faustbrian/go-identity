package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func (p *rpStartPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.input == nil {
		return identity.InvalidInputError{Field: "oauth_start_owner"}
	}
	spec, ok := command.Feature()
	expected, counters, err := p.command()
	want, valid := expected.Feature()
	if err != nil || !ok || !valid || spec.Binding != p.input.binding() || spec.Operation != rpLinkStartOperation() || !sameRPFields(spec.Fields, want.Fields) {
		return identity.InvalidInputError{Field: "oauth_start_command"}
	}
	bearer, hasBearer := command.SessionToken()
	original, err := p.originalSession()
	if !hasBearer || err != nil || !p.service.possesses(spec.Binding.TenantID, bearer, p.request.CSRFToken, original) {
		return identity.ForbiddenError{}
	}
	if plan.Feature != nil && (*plan.Feature != p.registration() || plan.CommandCounters == nil || *plan.CommandCounters != counters || plan.SubjectType != "oauth_transaction" || plan.Lifecycle == nil || *plan.Lifecycle != rpStartLifecycle()) {
		return identity.InvalidInputError{Field: "oauth_start_plan"}
	}
	return nil
}

func (p *rpStartPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.Capability != nil {
		return identity.InvalidInputError{Field: "oauth_start_preparation"}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func rpStartLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}
}

func (p *rpStartPhase) declaration(ctx context.Context, command identity.Command, counter kernel.CommandCounterPlan, registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	spec, ok := command.Feature()
	if !ok || p.input == nil || registry == nil {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "oauth_start_declaration"}
	}
	auditing, err := rpStartAudit(ctx, spec.Binding, p.input.Started, p.service.config().AuditRetentionPolicyVersion)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	owners := registry.Descriptors()
	if len(owners) != 6 || owners[5] != p.service.issuer.Descriptor() {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "oauth_start_declaration"}
	}
	feature, lifecycle := p.registration(), rpStartLifecycle()
	return kernel.CommandPlan{Contributors: owners[:5], Feature: &feature, SubjectType: "oauth_transaction", CommandCounters: &counter, Audits: []kernel.AuditPlan{auditing}, Lifecycle: &lifecycle}, nil
}

func rpStartAudit(ctx context.Context, b identity.CommandBinding, now time.Time, retention uint64) (kernel.AuditPlan, error) {
	return rpTransactionAudit(ctx, b, rpLinkStartOperation(), 0, 1, now, retention)
}

func rpTransactionAudit(ctx context.Context, b identity.CommandBinding, op identity.FeatureOperation, before, after uint64, now time.Time, retention uint64) (kernel.AuditPlan, error) {
	// SECURITY_EVENTS.md reserves catalog actions independently of command IDs.
	// These self-service RP operations use its standard retention classification.
	var action string
	switch op {
	case rpLinkStartOperation():
		action = "identity.oauth.start_authorization"
	case rpDenialOperation():
		action = "identity.oauth.handle_callback"
	default:
		return kernel.AuditPlan{}, identity.InvalidInputError{Field: "oauth_transaction_audit"}
	}
	// This ID is a declaration seed only, never persisted. The coordinator owns
	// actual event IDs, primary time, success/denial and atomic audit persistence.
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "oauth-declaration", nil }})
	if err != nil || retention == 0 {
		return kernel.AuditPlan{}, identity.InvalidInputError{Field: "oauth_start_audit"}
	}
	record, err := builder.Build(audit.RecordInput{Action: action, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "oauth_transaction", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "standard", "aggregate.type": "oauth_transaction", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(after, 10)}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "oauth_transaction", record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}, nil
}

func (p *rpStartPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command, false)
}

func (p *rpStartPhase) check(ctx context.Context, w kernel.Work, command identity.Command, applying bool) error {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || feature != p.registration() || lifecycle != rpStartLifecycle() || p.input == nil || b != p.input.binding() || p.ValidateFeatureCommand(command, kernel.CommandPlan{}) != nil {
		return identity.ForbiddenError{}
	}
	if applying {
		if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
			return err
		}
	}
	original, err := p.originalSession()
	if err != nil {
		return err
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.config().Session.Profile, original, b)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config().Session.Repository, original); err != nil {
		return err
	}
	if _, err := mfapg.RequireOAuthLinkStartFactors(ctx, w, p, command, p.input.FactorVersion); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || now.Before(p.input.Started) || !now.Before(p.input.ValidUntil) {
		return identity.ForbiddenError{}
	}
	lifetime, err := original.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *rpStartPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command, false)
}

func (p *rpStartPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.check(ctx, w, command, true); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	output, issued, _, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.persist(ctx, w, output); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.issuer.Stage(ctx, w, issued); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: rpLinkStartOperation(), AfterVersion: 1}, nil
}

func (p *rpStartPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || b.ValidateFor(rpLinkStartOperation()) != nil {
		return kernel.RecoveryUnknown, identity.InvalidInputError{Field: "oauth_start_recovery"}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT user_id,operation,transaction_id FROM `+rpQuotedSchema(p.service.config().Schema)+`.transactions WHERE tenant_id=$1 AND origin_command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var user, operation, transaction string
	if rows.Scan(&user, &operation, &transaction) != nil || rows.Next() || rows.Err() != nil || user != string(b.UserID) || operation != b.OperationID || transaction != b.RecordID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
