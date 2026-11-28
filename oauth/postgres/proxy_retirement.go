package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProxyRetirementAuthority borrows the authoritative audit reader and pins
// the provider operator identity. Keep this trusted operator composition out
// of callback handlers. It owns no pool or background work.
type ProxyRetirementAuthority struct {
	reader   *auditpg.Store
	operator identity.ActorID
}

// NewProxyRetirementAuthority selects a separately authorized audit reader.
// It does not query PostgreSQL or grant the callback role audit-read access.
func NewProxyRetirementAuthority(reader *auditpg.Store, operator identity.ActorID) (*ProxyRetirementAuthority, error) {
	if reader == nil || !rpDirectoryID(string(operator)) {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_retirement_authority"}
	}
	return &ProxyRetirementAuthority{reader: reader, operator: operator}, nil
}

// ProxyOriginRetirementRequest identifies one original local custody row and
// the retained provider disable that withdrew its authority. Reuse the same
// CommandID and unchanged inputs when recovering an ambiguous result.
type ProxyOriginRetirementRequest struct {
	CommandID, OriginCommandID identity.CommandID
	FlowID                     identity.PreAuthTransactionID
	Disable                    ProviderAuthorityChange
}

// RetireDisabledProviderOrigin retires one unused production grant and erases
// its local bearer custody. An original settled outcome is not changed, and
// uncertain provider exchange is not classified. The receipt is local only.
func (s *ProxyForwardService) RetireDisabledProviderOrigin(ctx context.Context, authority *ProxyRetirementAuthority, r ProxyOriginRetirementRequest) (identity.CommandResult, error) {
	if s == nil || s.pool == nil || s.providerAuthority == nil {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	c := s.config
	p := proxyRetirementPhase{kind: kernel.OAuthProxyRetireProduction, schema: c.Schema, production: c.ProductionDeployment,
		envelopes: s.envelopes, request: r}
	return p.execute(ctx, authority, s.pool, s.directory, c.Coordinator, c.Actor, c.PolicyID, c.PolicyVersion, c.AuditRetention)
}

// RetireDisabledProviderOrigin retires the exact bound preview callback grant
// and erases its proof without creating or revoking a session. The preview
// transaction never writes to the production database.
func (s *ProxyPreviewService) RetireDisabledProviderOrigin(ctx context.Context, authority *ProxyRetirementAuthority, r ProxyOriginRetirementRequest) (identity.CommandResult, error) {
	if s == nil || s.signin == nil || s.signin.start == nil || s.authority == nil || r.Disable.Key.TenantID != s.config.TenantID {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	start := s.signin.start
	c := start.config
	if c.Coordinator.AdmissionPolicy == nil {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	p := proxyRetirementPhase{kind: kernel.OAuthProxyRetirePreview, schema: c.Schema, production: s.config.ProductionDeployment,
		preview: s.config.Target.Deployment, envelopes: start.envelopes, request: r}
	return p.execute(ctx, authority, start.pool, start.directory, c.Coordinator, s.config.ActorID, c.PolicyID,
		c.Coordinator.AdmissionPolicy.PolicyVersion, c.AuditRetentionPolicyVersion)
}

type proxyRetirementPhase struct {
	kind                        kernel.OAuthProxyRetirementKind
	schema, production, preview string
	envelopes                   *envelope.Service
	request                     ProxyOriginRetirementRequest
	command                     identity.Command
}

func (*proxyRetirementPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.OAuthProxyOriginRetirementDescriptor()
}

func (*proxyRetirementPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.OAuthProxyOriginRetirementOperation()}
}

func (p *proxyRetirementPhase) execute(ctx context.Context, authority *ProxyRetirementAuthority, pool *database.Pool, directory *kernel.Repository,
	config kernel.CoordinatorConfig, actor identity.ActorID, policy string, policyVersion, retention uint64) (identity.CommandResult, error) {
	if ctx == nil || authority == nil || authority.reader == nil {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, config.MaximumDuration)
	defer cancel()
	r := p.request
	op := kernel.OAuthProxyOriginRetirementOperation()
	binding := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.Disable.Key.TenantID, ActorID: actor,
		ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: string(r.FlowID), RecordID: string(r.FlowID),
		CorrelationID: string(r.OriginCommandID), OperationID: op.OperationID, SchemaID: op.SchemaID,
		SchemaVersion: op.SchemaVersion, PolicyID: policy, PolicyVersion: policyVersion}
	command, err := kernel.NewOAuthProxyOriginRetirementCommand(binding, p.kind, r.Disable.CommandID, r.Disable.Next.Version)
	if err != nil {
		return identity.CommandResult{}, err
	}
	// Authenticate the immutable source before opening local Work. Preview
	// must not hold local locks while it reads the production audit primary.
	if err := readProxyProviderDisable(ctx, authority.reader, authority.operator, r.Disable); err != nil {
		return identity.CommandResult{}, err
	}
	p.command = command
	auditPlan, err := proxyRetirementAudit(binding, retention)
	if err != nil {
		return identity.CommandResult{}, err
	}
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return identity.CommandResult{}, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return identity.CommandResult{}, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, auditing, lifecycle, p})
	if err != nil {
		return identity.CommandResult{}, err
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, config)
	if err != nil {
		return identity.CommandResult{}, err
	}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	effect := kernel.OAuthProxyOriginRetirementLifecycle()
	plan, err := coordinator.PrepareCommandPlan(binding, command, kernel.CommandPlan{Contributors: registry.Descriptors(),
		Feature: &feature, SubjectType: proxyRetirementSubject, Audits: []kernel.AuditPlan{auditPlan}, Lifecycle: &effect})
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, binding, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	applied, err := coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return coordinator.Abort(work, err)
	}
	return coordinator.Commit(work, applied)
}

func (p *proxyRetirementPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p.command == (identity.Command{}) || command != p.command || plan.Feature == nil ||
		*plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: kernel.OAuthProxyOriginRetirementOperation()}) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyRetirementPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	scope, err := w.OAuthProxyOriginRetirementScope(ctx, p, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if scope.SourceCommandID != p.request.Disable.CommandID || scope.SourceVersion != p.request.Disable.Next.Version {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	mutation, err := p.authenticateCustody(ctx, w, scope)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(mutation.binding)
	grant, err := w.OAuthProxyOriginRetirementGrant(ctx, p, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Callback settlement locks the capability before its custody row. Match
	// that order; the final compare-and-set rechecks the authenticated original.
	if err := capabilitypg.RetireOAuthProxyOriginGrant(ctx, w, p, command, grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mutation.erase(ctx, w, scope); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: kernel.OAuthProxyOriginRetirementOperation(), AfterVersion: 1}, nil
}

func (*proxyRetirementPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil // The local command journal owns settlement.
}

const proxyRetirementSubject = "oauth_proxy_retirement"

func proxyRetirementAudit(b identity.CommandBinding, retention uint64) (kernel.AuditPlan, error) {
	const event = "identity.oauth.proxy_custody.retire"
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: event, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: proxyRetirementSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": proxyRetirementSubject, "aggregate.id": b.RecordID,
			"aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, kernel.OAuthProxyOriginRetirementOperation(), proxyRetirementSubject, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: event, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
		RetentionPolicyVersion: retention, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}, nil
}
