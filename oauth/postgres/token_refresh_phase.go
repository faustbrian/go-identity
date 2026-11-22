package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

var _ kernel.RequestKeyPreparationContributor = (*providerRefreshPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*providerRefreshPhase)(nil)

const refreshAuditEvent = "identity.oauth.refresh_grant"
const refreshLifecycleEvent = "social_provider.token_grant_changed.v1"
const refreshSubjectType = "account"

func (p *providerRefreshPhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: refreshLifecycleEvent,
		BeforeVersion: p.input.GrantVersion, AfterVersion: p.input.GrantVersion + 1}
}

func (p *providerRefreshPhase) declaration(ctx context.Context, counters kernel.CommandCounterPlan, owners []kernel.ContributorDescriptor) (kernel.CommandPlan, error) {
	b, feature, lifecycle := p.input.binding(), providerRefreshRegistration(), p.lifecycle()
	auditing, err := providerRefreshAudit(ctx, b, p.input.Started, lifecycle, p.service.link.config().AuditRetentionPolicyVersion)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: owners, Feature: &feature, SubjectType: refreshSubjectType,
		CommandCounters: &counters, Audits: []kernel.AuditPlan{auditing}, Lifecycle: &lifecycle}, nil
}

func providerRefreshAudit(ctx context.Context, b identity.CommandBinding, at time.Time, transition kernel.LifecyclePlan, retention uint64) (kernel.AuditPlan, error) {
	invalid := identity.InvalidInputError{Field: "oauth_refresh_audit"}
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "oauth-refresh-declaration", nil }})
	if err != nil || retention == 0 {
		return kernel.AuditPlan{}, invalid
	}
	record, err := builder.Build(audit.RecordInput{
		Action: refreshAuditEvent, OccurredAt: at, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: refreshSubjectType, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID),
			"retention.class": "standard", "aggregate.type": refreshSubjectType, "aggregate.id": b.RecordID,
			"aggregate.before_version": strconv.FormatUint(transition.BeforeVersion, 10),
			"aggregate.after_version":  strconv.FormatUint(transition.AfterVersion, 10)},
	})
	if err != nil {
		return kernel.AuditPlan{}, invalid
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{
		"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version",
	}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, providerRefreshOperation(), refreshSubjectType, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: refreshAuditEvent, SchemaVersion: 1, BindingDigest: digest,
		RetentionClass: "standard", RetentionPolicyVersion: retention, RequiredRecordCount: 1,
		MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}, nil
}

func (p *providerRefreshPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p.input == nil || command != p.command {
		return identity.ForbiddenError{}
	}
	if plan.Feature != nil && (*plan.Feature != providerRefreshRegistration() || plan.SubjectType != refreshSubjectType ||
		plan.CommandCounters == nil || p.plan.CommandCounters == nil || *plan.CommandCounters != *p.plan.CommandCounters ||
		plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle()) {
		return identity.InvalidInputError{Field: "oauth_refresh_plan"}
	}
	return nil
}

func (p *providerRefreshPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if plan.Feature == nil || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil {
		return identity.InvalidInputError{Field: "oauth_refresh_preparation"}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *providerRefreshPhase) requireCurrentSession(ctx context.Context, w kernel.Work) error {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || p.input == nil || b != p.input.binding() || feature != providerRefreshRegistration() || lifecycle != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	original, err := p.input.originalSession()
	if err != nil {
		return err
	}
	cfg := p.service.link.config()
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(cfg.Session.Profile, original, b)
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
	if err := sessionpg.RequireSession(ctx, w, cfg.Session.Repository, original); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || !p.input.validAt(now) {
		return identity.ForbiddenError{}
	}
	lifetime, err := original.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *providerRefreshPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return err
	}
	if err := p.requireCurrentSession(ctx, w); err != nil {
		return err
	}
	_, err := w.RequireActiveProviderAccount(ctx, p, p.input.account())
	return err
}

type providerRefreshAdmission struct{ phase *providerRefreshPhase }

func (a providerRefreshAdmission) Check(ctx context.Context) error {
	if ctx == nil || a.phase == nil || a.phase.input == nil || !a.phase.input.validAt(time.Now().UTC()) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (a providerRefreshAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	p, link := a.phase, a.phase.service.link
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	original, err := link.providerRefreshGrant(ctx, p.input.binding())
	if err != nil {
		return nil, err
	}
	defer clear(original.Ciphertext)
	if !p.input.matchesGrant(original) {
		return nil, identity.ConflictError{}
	}
	// Network IO is outside SQL. The retained deadline applies to the
	// configured provider request even if the earlier SQL checks were fast.
	ctx, cancel := context.WithDeadline(ctx, p.input.ValidUntil)
	defer cancel()
	return link.generateProviderRefreshOutput(ctx, p.input.binding(), original, p.service.providers[p.input.Account.Provider], generation)
}

func (p *providerRefreshPhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	a := providerRefreshAdmission{phase: p}
	return a, a.Check(ctx)
}

func (*providerRefreshPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *providerRefreshPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	a := providerRefreshAdmission{phase: p}
	return a, a.Check(ctx)
}

func (p *providerRefreshPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	output, err := p.service.link.decodeProviderRefreshOutput(ctx, p.input.binding(), p.input.GrantDigest, generation, wire)
	if output.Successor != nil {
		clear(output.Successor.Ciphertext)
	}
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	return command, p.plan, nil
}

func (p *providerRefreshPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.AdmitFeaturePreparation(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	b, schema := p.input.binding(), p.service.link.config().Schema
	rows, err := w.Query(ctx, providerRefreshVaultReadSQL(schema), string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !rows.Next() {
		rows.Close()
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	original, err := scanProviderRefreshVault(rows, b.TenantID, b.UserID, p.input.Account.ID)
	multiple := rows.Next()
	rows.Close()
	defer clear(original.Ciphertext)
	if err != nil || multiple || rows.Err() != nil || !p.input.matchesGrant(original) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	output, err := p.service.link.openProviderRefreshOutput(ctx, b, original, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if output.Successor != nil {
		defer clear(output.Successor.Ciphertext)
	}
	linkVersion, err := w.AdvanceProviderRefreshAuthority(ctx, p, command, p.input.account())
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var expires time.Time
	if output.Rejected {
		err = retireRejectedProviderRefreshVault(ctx, w.Exec, schema, original, linkVersion)
	} else {
		expires = output.Successor.AccessExpiresAt
		err = compareAndSetProviderRefreshVault(ctx, w.Exec, schema, original, *output.Successor)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.persistReceipt(ctx, w, output.Rejected, expires); err != nil {
		return identity.FeatureReceipt{}, err
	}
	lifecycle := p.lifecycle()
	return identity.FeatureReceipt{Operation: providerRefreshOperation(),
		BeforeVersion: lifecycle.BeforeVersion, AfterVersion: lifecycle.AfterVersion}, nil
}

func (p *providerRefreshPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return err
	}
	return p.requireCurrentSession(ctx, w)
}
