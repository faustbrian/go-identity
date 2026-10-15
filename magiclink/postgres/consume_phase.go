package magiclinkpostgres

import (
	"context"
	"crypto/sha256"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// One synchronous public invocation owns this participant and ephemeral bearer.
// Retained output has only original risk custody and tokenless session fields.
type consumePhase struct {
	service                 *ConsumeService
	request                 magiclink.ConsumeRequest
	original, command       identity.Command
	flow                    session.PreAuthTransaction
	grant                   capability.Grant
	origin                  identity.CommandID
	selected                requestSelection
	signup                  *kernel.MagicLinkRegistrationIntent
	createdRecipient        *kernel.RecipientRecord
	proof                   kernel.CapabilityPlan
	subject                 risk.Subject
	coordinator             *kernel.Coordinator
	registry                *kernel.ContributorRegistry
	issuer                  *session.SessionIssuer
	prepared                session.PreparedIssuance
	execution               *consumeExecution
	authenticatedAt         time.Time
	policyVersion           uint64
	receipt                 identity.CommandResult
	deliverable             bool
	mfaRequired             bool
	generatedChallengeProof capability.Proof
}

type consumeExecution struct {
	record     session.Session
	admission  risk.AuthenticationAdmission
	generation uint64
	digest     [32]byte
	challenge  *consumeMFAExecution
}

func (*consumePhase) Descriptor() kernel.ContributorDescriptor { return descriptor() }
func (*consumePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{consumeOperation()}
}
func (*consumePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: descriptor(), Operation: consumeOperation()}
}

func (p *consumePhase) plan(command identity.Command, at time.Time) (kernel.CommandPlan, error) {
	f, ok := p.original.Feature()
	if !ok || p.coordinator == nil || p.registry == nil {
		return kernel.CommandPlan{}, invalid()
	}
	b := f.Binding
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	subject := "authentication_attempt"
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at.UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, consumeOperation(), subject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	proof := p.proof
	contributors := p.registry.Descriptors()
	if p.service.config.MFA != nil {
		contributors = contributors[:len(contributors)-1]
	}
	plan := kernel.CommandPlan{Contributors: contributors, Feature: &kernel.FeatureRegistration{Contributor: descriptor(), Operation: consumeOperation()}, SubjectType: subject, Capability: &proof, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if p.mfaRequired {
		plan.Lifecycle.EventType = "mfa.challenge.created.v1"
		plan.MFAContinuation = &kernel.MFAContinuationPlan{UserID: p.selected.recipient.User.ID, PolicyVersion: b.PolicyVersion, FactorVersion: p.selected.factor}
		if command != p.original {
			if p.execution == nil || p.execution.challenge == nil {
				return kernel.CommandPlan{}, invalid()
			}
			plan.MFAContinuation, err = p.execution.challenge.plan()
			if err != nil {
				return kernel.CommandPlan{}, err
			}
			issue, err := p.execution.challenge.issuance.Plan()
			if err != nil {
				return kernel.CommandPlan{}, err
			}
			plan.CapabilityIssuance = &issue
			plan.Contributors = p.registry.Descriptors()
		}
	}
	if p.signup != nil {
		digest, e := kernel.MagicLinkRegistrationDigest(*p.signup)
		if e != nil {
			return kernel.CommandPlan{}, e
		}
		plan.MagicLinkRegistration = &kernel.MagicLinkRegistrationPlan{UserID: p.signup.Creation.Binding.UserID, IdentifierID: string(p.signup.Identifier.ID), CreationDigest: digest, EmailPossessionPolicyVersion: p.signup.EmailPossessionPolicyVersion, CreationEventIndex: 1}
	}
	if command == p.original {
		return p.coordinator.PrepareFeaturePreparationPlan(command, plan)
	}
	return p.coordinator.PrepareCommandPlan(b, command, plan)
}

func (p *consumePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p != nil && p.mfaRequired {
		return p.validateMFAFeature(c, plan)
	}
	if p == nil || p.service == nil || (c != p.original && c != p.command) || c == (identity.Command{}) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "authentication_attempt" || plan.Capability == nil || *plan.Capability != p.proof || plan.CommandCounters != nil || plan.RiskEvidence != nil || plan.OTP != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "session.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 {
		return invalid()
	}
	if p.signup == nil {
		if plan.MagicLinkRegistration != nil {
			return invalid()
		}
	} else {
		digest, err := kernel.MagicLinkRegistrationDigest(*p.signup)
		expected := kernel.MagicLinkRegistrationPlan{UserID: p.signup.Creation.Binding.UserID, IdentifierID: string(p.signup.Identifier.ID), CreationDigest: digest, EmailPossessionPolicyVersion: p.signup.EmailPossessionPolicyVersion, CreationEventIndex: 1}
		if err != nil || plan.MagicLinkRegistration == nil || *plan.MagicLinkRegistration != expected {
			return invalid()
		}
	}
	return p.ValidateMagicLinkConsumption(c, *plan.Capability)
}
func (p *consumePhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original {
		return invalid()
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (p *consumePhase) ValidateMagicLinkConsumption(c identity.Command, proof kernel.CapabilityPlan) error {
	if p == nil || p.service == nil || proof != p.proof || (c != p.original && c != p.command) {
		return invalid()
	}
	if c == p.original {
		return nil
	}
	if p.mfaRequired {
		return nil
	}
	record, err := sessionpg.MagicLinkSigninSession(c)
	if err != nil || p.execution == nil {
		return invalid()
	}
	meta, err := record.MagicLinkAuthentication().Bindings()
	user, identifier, iv, vv := p.sessionIdentity()
	s, specErr := record.Bindings()
	f, _ := c.Feature()
	if err != nil || specErr != nil || meta.CommandID != f.Binding.CommandID || meta.RequestCommandID != p.origin || meta.CapabilityID != p.proof.CapabilityID || meta.IdentifierID != identifier || meta.IdentifierVersion != iv || meta.VerificationVersion != vv || !meta.ValidUntil.Equal(p.proof.ExpiresAt) || s.TenantID != p.request.TenantID || s.UserID != user {
		return invalid()
	}
	fields, err := sessionpg.MagicLinkSigninSessionFields(record)
	expected, e := sessionpg.MagicLinkSigninSessionFields(p.execution.record)
	if err != nil || e != nil || !sameFields(fields, expected) {
		return invalid()
	}
	return nil
}

func (p *consumePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original {
		return invalid()
	}
	if p.signup != nil {
		if err := sessionpg.RequirePreAuth(ctx, w, p.service.request.config().Session, p.flow); err != nil {
			return err
		}
		now, err := w.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		if err = p.checkProspectiveScope(now); err != nil {
			return err
		}
		p.authenticatedAt = now
		return nil
	}
	if p.mfaRequired {
		if err := mfapg.RequireMagicLinkTOTPChallenge(ctx, w, p, c, p.selected.recipient.User.ID, p.selected.factor); err != nil {
			return err
		}
	} else if _, err := mfapg.RequireMagicLinkFactors(ctx, w, p, c, p.selected.recipient.User.ID, p.selected.factor); err != nil {
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.selected.recipient); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.service.request.config().Session, p.flow); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if _, err = p.service.request.validateConsumptionScope(p.request, p.flow, p.grant, p.origin, p.selected.recipient, now); err != nil {
		return err
	}
	if err = p.service.request.admitFlow(p.flowInput(), p.flow, now); err != nil {
		return err
	}
	p.authenticatedAt = now
	return nil
}

func (p *consumePhase) flowInput() magiclink.RequestRequest {
	return magiclink.RequestRequest{TenantID: p.request.TenantID, PreAuthID: p.request.PreAuthID, Cookie: p.request.Cookie, Origin: p.request.Origin, Callback: p.request.Callback}
}

func (p *consumePhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original || p.authenticatedAt.IsZero() {
		return nil, invalid()
	}
	f, _ := c.Feature()
	b := f.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	evaluated, err := p.service.request.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	a, err := p.service.request.custody.Prepare(ctx, evaluated, scope, p.subject)
	if err != nil {
		return nil, err
	}
	d, err := p.service.request.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.request.config().GlobalAuthorityID, TenantID: b.TenantID})
	if err != nil || !d.Enabled {
		return nil, identity.ForbiddenError{}
	}
	p.policyVersion = 1
	if p.signup == nil {
		policy, e := p.service.policy.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(p.selected.recipient.User.ID), PolicyNamespace: p.service.config.PolicyNamespace})
		if e != nil {
			return nil, e
		}
		p.policyVersion = policy.Version
	}
	p.selected.global, p.selected.tenant = d.GlobalVersion, d.TenantVersion
	admission := &consumeAdmission{owner: p, admission: a}
	return admission, admission.Check(ctx)
}

type consumeAdmission struct {
	owner     *consumePhase
	admission risk.AuthenticationAdmission
}

func (a *consumeAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return invalid()
	}
	if err := a.admission.CheckAt(ctx, time.Now().UTC()); err != nil {
		return err
	}
	if !time.Now().UTC().Before(a.owner.proof.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (a *consumeAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.owner
	if p.mfaRequired {
		return a.generateMFA(ctx, generation)
	}
	if generation == 0 || p.prepared != (session.PreparedIssuance{}) {
		return nil, invalid()
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	authority, err := p.authority(string(id), string(family))
	if err != nil {
		return nil, err
	}
	f, _ := p.original.Feature()
	flow, _ := p.flow.Bindings()
	user, identifier, iv, vv := p.sessionIdentity()
	meta, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: f.Binding.CommandID, RequestCommandID: p.origin, CapabilityID: p.proof.CapabilityID, IdentifierID: identifier, IdentifierVersion: iv, VerificationVersion: vv, AuthenticatedAt: p.authenticatedAt, ValidUntil: p.proof.ExpiresAt})
	if err != nil {
		return nil, err
	}
	p.prepared, err = p.issuer.PrepareMagicLink(f.Binding, session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: f.Binding.TenantID, UserID: user, Audience: p.service.request.config().Issuer.Audience, Version: 1, FamilyVersion: 1, Remember: flow.Binding.Intent.Remember, Authority: authority, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}, IssuedAt: p.authenticatedAt, LastActivityAt: p.authenticatedAt}, meta)
	if err != nil {
		return nil, err
	}
	record, ok := p.prepared.Session()
	if !ok {
		return nil, invalid()
	}
	fields, err := sessionpg.MagicLinkSigninSessionFields(record)
	if err != nil {
		return nil, err
	}
	return p.sealConsumeOutput(ctx, generation, fields, a.admission)
}

func (p *consumePhase) authority(id, family string) (session.AuthoritySnapshot, error) {
	r := p.selected.recipient
	user, _, _, _ := p.sessionIdentity()
	uver, iver, cver := r.UserAuthorityVersion, r.IdentifierAuthorityVersion, r.CredentialAuthorityVersion
	if p.signup != nil {
		uver, iver, cver = 1, 1, 1
	}
	q := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.request.config().GlobalAuthorityID, TenantID: p.request.TenantID}
	keys, err := kernel.KernelAuthorityKeys(q, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	skeys, err := sessionpg.SessionAuthorityKeys(q.TenantID, user, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	policy := authoritypg.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), SubjectID: authorization.SubjectID(user), PolicyNamespace: p.service.config.PolicyNamespace}
	key, err := policy.Key()
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	bind := func(k string, v uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: v}
	}
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(keys.Global, p.selected.global), Tenant: bind(keys.Tenant, p.selected.tenant), User: bind(keys.User, uver), Identifier: bind(keys.Identifier, iver), Credential: bind(keys.Credential, cver), SessionFamily: bind(skeys.Family, 1), Session: bind(skeys.Session, 1), Authorization: bind(key, p.policyVersion)})
}

func (*consumePhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalid()
}
func (p *consumePhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &consumeAdmission{owner: p, admission: p.execution.admission}
	return a, a.Check(ctx)
}
func (p *consumePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, invalid()
	}
	e, command, err := p.restoreConsumeOutput(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.execution, p.command = e, command
	if p.mfaRequired {
		s, err := e.challenge.continuation.Bindings()
		if err != nil {
			return identity.Command{}, kernel.CommandPlan{}, err
		}
		plan, err := p.plan(command, s.IssuedAt)
		return command, plan, err
	}
	s, _ := e.record.Bindings()
	plan, err := p.plan(command, s.IssuedAt)
	return command, plan, err
}

func (p *consumePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.execution == nil || c != p.command || c == p.original {
		return identity.FeatureReceipt{}, invalid()
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
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
	scope, err := issuerpg.MagicLinkScopeFromPayload(p.grant.Payload())
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = issuerpg.LockMagicLinkSupersession(ctx, w, p, scope); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.signup != nil {
		if err = p.applySignup(ctx, w, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.mfaRequired {
		return p.applyMFA(ctx, w, c)
	}
	if err = p.checkCurrent(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	recipient := p.selected.recipient
	if p.signup != nil {
		recipient = *p.createdRecipient
	}
	return p.service.effect.Apply(ctx, w, p, c, recipient, p.flow)
}

func (p *consumePhase) checkCurrent(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || c != p.command {
		return invalid()
	}
	user, _, _, _ := p.sessionIdentity()
	factor := p.selected.factor
	if p.signup != nil {
		factor = 1
	}
	if _, err := mfapg.RequireMagicLinkFactors(ctx, w, p, c, user, factor); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.execution.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if p.signup != nil {
		if err = p.checkProspectiveScope(now); err != nil {
			return err
		}
	} else if _, err = p.service.request.validateConsumptionScope(p.request, p.flow, p.grant, p.origin, p.selected.recipient, now); err != nil {
		return err
	}
	if err = p.service.request.admitFlow(p.flowInput(), p.flow, now); err != nil {
		return err
	}
	record, err := sessionpg.MagicLinkSigninSession(c)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	life, err := record.Lifetime(now)
	if err != nil || now.Before(s.IssuedAt) || !life.Fresh {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *consumePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mfaRequired {
		return p.checkMFA(ctx, w, c)
	}
	return p.checkCurrent(ctx, w, c)
}
func (p *consumePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	_, _, life, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if life.EventType == "mfa.challenge.created.v1" {
		return mfapg.RecoverMagicLinkChallenge(ctx, w, p)
	}
	return p.service.effect.Recover(ctx, w, p)
}

// ExecuteIssue can lend only the actual new receipt from this exact invocation.
// It performs no transaction or recovery and cannot turn retained output into
// new delivery permission. SessionIssuer repeats exact mapping/time/receipt
// checks before releasing its private original bearer and CSRF token.
func (p *consumePhase) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || !p.deliverable || p.execution == nil {
		return session.IssueExecution{}, invalid()
	}
	c, record, ok := r.MagicLinkCommand()
	if !ok || c != p.command || p.receipt.Outcome != identity.CommitOutcomeCommitted || p.receipt.Validate() != nil {
		return session.IssueExecution{}, invalid()
	}
	fields, err := sessionpg.MagicLinkSigninSessionFields(record)
	expected, e := sessionpg.MagicLinkSigninSessionFields(p.execution.record)
	if err != nil || e != nil || !sameFields(fields, expected) {
		return session.IssueExecution{}, invalid()
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: p.execution.record}, nil
}
func (*consumePhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, invalid()
}

var _ kernel.MagicLinkConsumptionContributor = (*consumePhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*consumePhase)(nil)
