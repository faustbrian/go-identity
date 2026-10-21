package anonymouspostgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func (p *deletionPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.command == (identity.Command{}) || command != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "anonymous" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "anonymous.deleted.v1", BeforeVersion: 1, AfterVersion: 2}) || plan.CommandCounters == nil || *plan.CommandCounters != kernel.CommandCounterPlan(p.input.Counters) || len(plan.Audits) != 1 || plan.Audits[0].EventType != "identity.anonymous.delete" || !plan.Audits[0].Required || plan.OTP != nil || plan.Capability != nil || plan.Delivery != nil || plan.SignupAcceptance {
		return anonymous.ErrInvalidInput
	}
	return p.service.risk.ValidateCommandCounters(command, kernel.CommandCounterPlan(p.input.Counters))
}

func (p *deletionPhase) plan() (kernel.CommandPlan, error) {
	b := p.input.Command.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.input.PreparedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "anonymous", "aggregate.id": string(b.UserID), "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, deletionOperation(), "anonymous", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	counters := kernel.CommandCounterPlan(p.input.Counters)
	return p.coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: p.registry.Descriptors(), SubjectType: "anonymous", Feature: &registration, Lifecycle: &kernel.LifecyclePlan{EventType: "anonymous.deleted.v1", BeforeVersion: 1, AfterVersion: 2}, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: p.service.config().RetentionPolicyVersion, RetentionClass: "protected", BindingDigest: digest}}})
}

func (p *deletionPhase) checkShared(ctx context.Context, w kernel.Work) error {
	s, err := p.source.Bindings()
	if err != nil {
		return anonymous.ErrInvalidInput
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return anonymous.ErrInvalidInput
	}
	c := p.service.config()
	expected := p.input.Kernel.intent().Snapshot.Authority
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.Profile.GlobalAuthorityID, TenantID: s.TenantID}
	keys, err := kernel.KernelAuthorityKeys(query, s.UserID)
	if err != nil {
		return err
	}
	sessionKeys, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return err
	}
	scope := policy.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: c.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}
	key, err := scope.Key()
	if err != nil {
		return err
	}
	if a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User != (session.AuthorityBinding{ScopeKey: keys.User, Version: expected.UserAuthorityVersion}) || a.Identifier != (session.AuthorityBinding{ScopeKey: keys.Identifier, Version: expected.IdentifierAuthorityVersion}) || a.Credential != (session.AuthorityBinding{ScopeKey: keys.Credential, Version: expected.CredentialAuthorityVersion}) || a.Session != (session.AuthorityBinding{ScopeKey: sessionKeys.Session, Version: s.Version}) || a.SessionFamily != (session.AuthorityBinding{ScopeKey: sessionKeys.Family, Version: s.FamilyVersion}) || a.Authorization.ScopeKey != key || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, kernel.UserAuthorizationAdmission{Scope: scope, Version: a.Authorization.Version}); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	local := c.Validation.Clock.Now()
	if !readInstant(local) || !now.Before(p.input.Until) || !local.Before(p.input.Until) || now.Before(p.input.PreparedAt) || local.Before(p.input.PreparedAt) || p.input.Until.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *deletionPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, anonymous.ErrInvalidInput
	}
	if err := p.checkShared(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config().Sessions, p.source); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := p.service.domain.Apply(ctx, w, p, c, p.input.Kernel.intent()); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.repository.StageDisposal(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return p.service.effect.Apply(ctx, w, p, c, p.source)
}

func (p *deletionPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return anonymous.ErrInvalidInput
	}
	if err := p.checkShared(ctx, w); err != nil {
		return err
	}
	if err := p.service.domain.Check(ctx, w, p, c, p.input.Kernel.intent()); err != nil {
		return err
	}
	if err := p.service.repository.RequireDisposal(ctx, w, p, c); err != nil {
		return err
	}
	return p.service.effect.Check(ctx, w, p, c, p.source, p.input.Until)
}

func (p *deletionPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	a, err := p.service.repository.RecoverDisposal(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := p.service.effect.Recover(ctx, w, p, p.source)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if a != b {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return a, nil
}
