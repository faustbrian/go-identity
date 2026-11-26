package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const oneTapSubject = "preauth_transaction"

func oneTapLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.preauth-issued.v1", AfterVersion: 1}
}

func (p *oneTapStartPhase) plan(ctx context.Context, issuance *kernel.CapabilityIssuancePlan) (kernel.CommandPlan, error) {
	if p.input == nil || p.registry == nil {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	b := identity.CommandBinding(p.input.Binding)
	auditing, err := oneTapStartAudit(ctx, b, p.input.ObservedAt, p.service.config().AuditRetentionPolicyVersion)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	contributors := p.registry.Descriptors()
	if len(contributors) != 5 || contributors[4] != p.service.issuer.Descriptor() {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	if issuance == nil {
		contributors = contributors[:4]
	}
	feature, lifecycle := p.registration(), oneTapLifecycle()
	return kernel.CommandPlan{Contributors: contributors, Feature: &feature, SubjectType: oneTapSubject,
		Audits: []kernel.AuditPlan{auditing}, Lifecycle: &lifecycle, CapabilityIssuance: issuance}, nil
}

func oneTapStartAudit(ctx context.Context, b identity.CommandBinding, now time.Time, retention uint64) (kernel.AuditPlan, error) {
	const action = "identity.session.preauth-issue"
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "onetap-declaration", nil }})
	if err != nil || retention == 0 {
		return kernel.AuditPlan{}, identity.ForbiddenError{}
	}
	attrs := map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "standard",
		"aggregate.type": oneTapSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"}
	record, err := builder.Build(audit.RecordInput{Action: action, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: oneTapSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true}, Attributes: attrs})
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
	digest, err := kernel.FeatureAuditBindingDigest(b, kernel.OneTapStartOperation(), oneTapSubject, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}, nil
}

func (p *oneTapStartPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	expected, err := p.command(nil)
	actual, ok := command.Feature()
	want, _ := expected.Feature()
	if err != nil || !ok || actual.Binding != want.Binding || actual.Operation != want.Operation {
		return identity.ForbiddenError{}
	}
	fields := actual.Fields
	prepared := len(fields) == 2 && fields[1].Name == "preauth.commitment" && fields[1].Value.Kind == identity.FeatureBytes && len(fields[1].Value.Bytes) == sha256.Size
	if prepared {
		fields = fields[:1]
	}
	if !sameRPFields(fields, want.Fields) {
		return identity.ForbiddenError{}
	}
	if plan.Feature != nil && (*plan.Feature != p.registration() || (plan.CapabilityIssuance != nil) != prepared ||
		plan.SubjectType != oneTapSubject || plan.Lifecycle == nil || *plan.Lifecycle != oneTapLifecycle()) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapStartPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	spec, ok := command.Feature()
	if !ok || len(spec.Fields) != 1 || plan.CapabilityIssuance != nil || plan.Capability != nil || plan.Delivery != nil || plan.CommandCounters != nil {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *oneTapStartPhase) check(ctx context.Context, w kernel.Work, command identity.Command) error {
	b, registration, lifecycle, err := w.FeatureScope(p)
	if err != nil || p.input == nil || b != identity.CommandBinding(p.input.Binding) || registration != p.registration() || lifecycle != oneTapLifecycle() || p.ValidateFeatureCommand(command, kernel.CommandPlan{}) != nil {
		return identity.ForbiddenError{}
	}
	c := p.service.config()
	authority := kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{TenantID: b.TenantID, GlobalAuthorityID: c.GlobalAuthorityID},
		GlobalVersion: p.input.GlobalVersion, TenantVersion: p.input.TenantVersion}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, authority); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.input.ObservedAt) || !now.Before(p.input.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapStartPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command)
}

func (p *oneTapStartPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command)
}

// ApplyFeature stages only the one original session flow and encrypted callback
// proof bound to this Work. The staged capability and audit/lifecycle owners
// still decide their own durable effects before the coordinator commits.
func (p *oneTapStartPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.check(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	out, record, grant, _, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	c := p.service.config()
	if err := sessionpg.StageOneTapStartPreAuth(ctx, w, p, command, c.Session, record, p.service.selected); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.issuer.Stage(ctx, w, grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.stageCallbackGrant(ctx, w, out); err != nil {
		return identity.FeatureReceipt{}, err
	}
	generated, owns := p.generated.Command()
	if owns && p.generation == generation {
		original, _ := generated.Record.ProviderBindings()
		stored, _ := record.ProviderBindings()
		p.applied = original == stored
	}
	return identity.FeatureReceipt{Operation: kernel.OneTapStartOperation(), AfterVersion: 1}, nil
}

func (p *oneTapStartPhase) riskInputs() (risk.Context, risk.Subject) {
	b := identity.CommandBinding(p.input.Binding)
	c := p.service.config()
	key := c.IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-oauth-onetap-provider-risk-v1\x00"))
	// No browser identifier or generated flow participates in this stable
	// provider-specific dimension; those would make repeated starts unlinked.
	frame, _ := json.Marshal([]string{c.ConfigurationID, string(c.TenantID), p.service.selected.ProviderID, p.service.selected.ClientID})
	_, _ = mac.Write(frame)
	clear(frame)
	return risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)},
		risk.Subject{Network: p.request.Network, Device: p.request.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
}

type oneTapStartAdmission struct {
	owner *oneTapStartPhase
	risk  risk.AuthenticationAdmission
}

func (a *oneTapStartAdmission) Check(ctx context.Context) error {
	now := a.owner.service.config().Issuance.Clock.Now().UTC()
	if now.Before(a.owner.input.ObservedAt) || !now.Before(a.owner.input.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return a.risk.CheckAt(ctx, now)
}

func (a *oneTapStartAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.owner.generateOutput(ctx, generation, a.risk)
}

func (p *oneTapStartPhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	b := identity.CommandBinding(p.input.Binding)
	scope, subject := p.riskInputs()
	result, err := p.service.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject,
		Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous},
			Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	admission, err := p.service.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, err
	}
	a := &oneTapStartAdmission{owner: p, risk: admission}
	return a, a.Check(ctx)
}

func (*oneTapStartPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *oneTapStartPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	out, _, _, _, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return nil, err
	}
	scope, subject := p.riskInputs()
	admission, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(out.Admission), scope, subject)
	if err != nil {
		return nil, err
	}
	a := &oneTapStartAdmission{owner: p, risk: admission}
	return a, a.Check(ctx)
}

func (p *oneTapStartPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	_, record, _, issuance, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	command, err = p.command(&record)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(ctx, &issuance)
	return command, plan, err
}
