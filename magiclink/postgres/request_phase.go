package magiclinkpostgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/magiclink"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Every public invocation has a distinct native participant; no request state
// is stored in a shared registry or retained beyond the coordinator's Work.
type requestPhase struct {
	service              *RequestService
	request              magiclink.RequestRequest
	canonical            string
	flow                 session.PreAuthTransaction
	subject              risk.Subject
	original             identity.Command
	coordinator          *kernel.Coordinator
	registry             *kernel.ContributorRegistry
	selected             requestSelection
	execution            *requestExecution
	prospectiveAvailable bool
}
type requestSelection struct {
	recipient              kernel.RecipientRecord
	prospective            *kernel.MagicLinkRegistrationIntent
	global, tenant, factor uint64
	issued, expires        time.Time
}

// A suppressed directory result can carry prospective creation, but is never
// itself existing-recipient authority. Only explicit prospective intent issues.
func (s requestSelection) delivers() bool {
	return s.prospective != nil || !s.recipient.Suppressed
}

type requestExecution struct {
	selected   requestSelection
	admission  risk.AuthenticationAdmission
	issuance   issuerpg.PreparedIssuance
	delivery   deliverypg.PreparedDelivery
	generation uint64
	digest     [32]byte
}

func (*requestPhase) Descriptor() kernel.ContributorDescriptor { return descriptor() }
func (*requestPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{requestOperation()}
}
func (*requestPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: descriptor(), Operation: requestOperation()}
}

func (p *requestPhase) plan(at time.Time, final bool) (kernel.CommandPlan, error) {
	spec, ok := p.original.Feature()
	if !ok || p.coordinator == nil || p.registry == nil {
		return kernel.CommandPlan{}, invalid()
	}
	contributors := p.registry.Descriptors()[:4]
	if final && p.execution != nil && p.execution.selected.delivers() {
		contributors = p.registry.Descriptors()
	}
	plan, err := requestAuditDeclaration(spec.Binding, contributors, at)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.MagicLinkRequestAcceptance = p.request.Intent == magiclink.SignupIfAllowed
	if final && p.execution.selected.delivers() {
		issue, e := p.execution.issuance.Plan()
		if e != nil {
			return kernel.CommandPlan{}, e
		}
		message, e := p.execution.delivery.Plan()
		if e != nil {
			return kernel.CommandPlan{}, e
		}
		plan.CapabilityIssuance = &issue
		plan.Delivery = &message
	}
	if final {
		return p.coordinator.PrepareCommandPlan(spec.Binding, p.original, plan)
	}
	return p.coordinator.PrepareFeaturePreparationPlan(p.original, plan)
}

func (p *requestPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || plan.MagicLinkRequestAcceptance != (p.request.Intent == magiclink.SignupIfAllowed) {
		return invalid()
	}
	if p == nil || p.service == nil || c != p.original || c == (identity.Command{}) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "user" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "magic-link.requested.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 || plan.Capability != nil || plan.OTP != nil {
		return invalid()
	}
	return nil
}
func (p *requestPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *requestPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original {
		return invalid()
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil || f != p.registration() {
		return invalid()
	}
	q := kernel.RecipientQuery{TenantID: b.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: p.canonical, Eligibility: kernel.RecipientVerified}
	r := p.selected.recipient
	if r.Validate() != nil || r.Query != q {
		return invalid()
	}
	if r.Suppressed {
		if p.request.Intent != magiclink.SignupIfAllowed {
			return sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow)
		}
		if p.service.registration == nil {
			return invalid()
		}
		p.prospectiveAvailable, err = p.service.registration.AdmitProspectiveMailbox(ctx, w, p, c, p.canonical)
		if err != nil {
			return err
		}
		if !p.prospectiveAvailable {
			return sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow)
		}
	}
	if !r.Suppressed {
		factor, err := p.requestFactors(ctx, w, c, r.User.ID, 0)
		var forbidden identity.ForbiddenError
		if errors.As(err, &forbidden) {
			p.selected.recipient = kernel.RecipientRecord{Query: q, Suppressed: true}
			return sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow)
		}
		if err != nil {
			return err
		}
		p.selected.factor = factor.Version()
	}
	// Match consumption's factor-before-browser lock order. Never acquire a
	// second pool connection while this Work owns either authority lock.
	if err = sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	now = now.UTC().Truncate(time.Second)
	flow, _ := p.flow.Bindings()
	expires := now.Add(p.service.config().Lifetime)
	if flow.Binding.ExpiresAt.Before(expires) {
		expires = flow.Binding.ExpiresAt.UTC().Truncate(time.Second)
	}
	if !expires.After(now) {
		return identity.ForbiddenError{}
	}
	p.selected.issued, p.selected.expires = now, expires
	return nil
}

// Remote/counted risk evaluation is outside Work. The durable generation
// owner retains its original signed facts; retries never restart their clocks.
func (p *requestPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original {
		return nil, invalid()
	}
	spec, _ := c.Feature()
	b := spec.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	evaluation, err := p.service.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	a, err := p.service.custody.Prepare(ctx, evaluation, scope, p.subject)
	if err != nil {
		return nil, err
	}
	d, err := p.service.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config().GlobalAuthorityID, TenantID: b.TenantID})
	if err != nil {
		return nil, err
	}
	if !d.Enabled {
		return nil, identity.ForbiddenError{}
	}
	p.selected.global, p.selected.tenant = d.GlobalVersion, d.TenantVersion
	admission := &requestAdmission{owner: p, admission: a}
	return admission, admission.Check(ctx)
}

type requestAdmission struct {
	owner     *requestPhase
	admission risk.AuthenticationAdmission
}

func (a *requestAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return invalid()
	}
	return a.admission.CheckAt(ctx, time.Now().UTC())
}
func (a *requestAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.owner
	if p.selected.recipient.Validate() != nil {
		return nil, invalid()
	}
	var artifacts requestArtifacts
	var err error
	if p.prospectiveAvailable {
		if err := p.prepareProspective(ctx, generation); err != nil {
			return nil, err
		}
	}
	if p.selected.delivers() {
		artifacts, err = p.generateDelivery(ctx, generation, a.admission)
		if err != nil {
			return nil, err
		}
		defer clear(artifacts.issuanceWire)
		defer clear(artifacts.deliveryWire)
	}
	return p.sealOutput(ctx, generation, p.selected, a.admission, artifacts)
}
func (*requestPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalid()
}
func (p *requestPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &requestAdmission{owner: p, admission: p.execution.admission}
	return a, a.Check(ctx)
}
func (p *requestPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, invalid()
	}
	e, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.execution = e
	at := e.selected.issued
	if at.IsZero() {
		at = time.Now().UTC()
	}
	plan, err := p.plan(at, true)
	return c, plan, err
}

func (p *requestPhase) checkCurrent(ctx context.Context, w kernel.Work, c identity.Command) (bool, error) {
	if p.execution == nil || c != p.original {
		return false, invalid()
	}
	e := p.execution
	spec, _ := c.Feature()
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config().GlobalAuthorityID, TenantID: spec.Binding.TenantID}, GlobalVersion: e.selected.global, TenantVersion: e.selected.tenant}); err != nil {
		return false, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return false, err
	}
	if err = e.admission.CheckAt(ctx, now); err != nil {
		return false, err
	}
	if err = p.service.admitFlow(p.request, p.flow, now); err != nil {
		return false, err
	}
	if e.selected.prospective != nil {
		if p.service.registration == nil || !now.Before(e.selected.expires) {
			return false, identity.ForbiddenError{}
		}
		available, err := p.service.registration.SelectProspectiveRecipient(ctx, w, p, c, *e.selected.prospective)
		if err != nil {
			return false, err
		}
		if err := sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow); err != nil {
			return false, err
		}
		return available, nil
	}
	if e.selected.recipient.Suppressed {
		return false, sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow)
	}
	if !now.Before(e.selected.expires) {
		return false, identity.ForbiddenError{}
	}
	if err = w.RequireMagicLinkRecipient(ctx, p, e.selected.recipient); err != nil {
		return false, err
	}
	_, err = p.requestFactors(ctx, w, c, e.selected.recipient.User.ID, e.selected.factor)
	if err != nil {
		return false, err
	}
	return true, sessionpg.RequirePreAuth(ctx, w, p.service.config().Session, p.flow)
}

func (p *requestPhase) requestFactors(ctx context.Context, w kernel.Work, c identity.Command, user identity.UserID, version uint64) (mfa.FactorAuthority, error) {
	if p.service.config().MFAContinuation {
		return mfapg.ReadMagicLinkRequestFactors(ctx, w, p, c, user, version)
	}
	return mfapg.RequireMagicLinkFactors(ctx, w, p, c, user, version)
}
func (p *requestPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.execution == nil {
		return identity.FeatureReceipt{}, invalid()
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if digest != p.execution.digest || generation != p.execution.generation {
		return identity.FeatureReceipt{}, invalid()
	}
	// Serialize resends and consumption before acquiring authority/browser rows.
	// Suppressed requests must never invalidate an existing recipient's link.
	if p.execution.selected.delivers() {
		payload, e := p.payload(p.execution.selected)
		if e != nil {
			return identity.FeatureReceipt{}, e
		}
		scope, e := issuerpg.MagicLinkScopeFromPayload(payload)
		if e != nil {
			return identity.FeatureReceipt{}, e
		}
		if e = issuerpg.LockMagicLinkSupersession(ctx, w, p, scope); e != nil {
			return identity.FeatureReceipt{}, e
		}
	}
	selected, err := p.checkCurrent(ctx, w, c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if selected {
		if err = p.service.issuer.Stage(ctx, w, p.execution.issuance); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err = p.service.config().Delivery.Owner.Stage(ctx, w, p.execution.delivery); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: requestOperation()}, nil
}
func (p *requestPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || c != p.original {
		return invalid()
	}
	b, f, _, err := w.FeatureScope(p)
	spec, ok := c.Feature()
	if err != nil || !ok || b != spec.Binding || f != p.registration() {
		return invalid()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.execution.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if err = p.service.admitFlow(p.request, p.flow, now); err != nil {
		return err
	}
	if p.execution.selected.delivers() && !now.Before(p.execution.selected.expires) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *requestPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(p)
	if ctx == nil || err != nil || f != p.registration() || b.UserID != "" || b.AnonymousFlowID == "" || l.EventType != "magic-link.requested.v1" || l.BeforeVersion != 0 || l.AfterVersion != 0 {
		return kernel.RecoveryUnknown, invalid()
	}
	// This owner stages no independent record. Every real effect participant
	// must independently prove its own absence in the same recovery scope.
	return kernel.RecoveryNotCommitted, nil
}

func requestAuditDeclaration(b identity.CommandBinding, contributors []kernel.ContributorDescriptor, at time.Time) (kernel.CommandPlan, error) {
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at.UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "user", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, requestOperation(), "user", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: contributors, Feature: &kernel.FeatureRegistration{Contributor: descriptor(), Operation: requestOperation()}, SubjectType: "user", Lifecycle: &kernel.LifecyclePlan{EventType: "magic-link.requested.v1", BeforeVersion: 0, AfterVersion: 0}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}, nil
}

var _ kernel.FeatureAdmissionPreparationContributor = (*requestPhase)(nil)
var _ kernel.FeatureCommitContributor = (*requestPhase)(nil)
