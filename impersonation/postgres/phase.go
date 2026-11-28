package impersonationpostgres

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const grantSubject = "impersonation"

// An invocation is immutable once returned by Prepare. Recovery registers a
// fresh phase with no session, plaintext or prepared command to restore.
type approvalPhase struct {
	service  *Service
	binding  identity.CommandBinding
	actor    authenticatedActor
	original originalRequest
	target   identity.User
	observed grantRecord
	payload  []byte
	reason   impersonation.Reason
	command  identity.Command
	counters kernel.CommandCounterPlan
	audit    kernel.AuditPlan
}

var _ kernel.FeatureCommitContributor = (*approvalPhase)(nil)

func (*approvalPhase) Descriptor() kernel.ContributorDescriptor { return approvalDescriptor }

func (*approvalPhase) FeatureOperations() []identity.FeatureOperation {
	request, _ := approvalOperation(requestAction)
	approve, _ := approvalOperation(approveAction)
	return []identity.FeatureOperation{request, approve}
}

func grantLifecycle(action string) kernel.LifecyclePlan {
	if action == requestAction {
		return kernel.LifecyclePlan{EventType: "impersonation.requested.v1", AfterVersion: 1}
	}
	return kernel.LifecyclePlan{EventType: "impersonation.approved.v1", BeforeVersion: 1, AfterVersion: 2}
}

func (s *Service) prepare(ctx context.Context, p *approvalPhase, network string) (PreparedCommand, error) {
	b := p.binding
	op, ok := approvalOperation(b.OperationID)
	if !ok || b.ValidateFor(op) != nil {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	fields, err := sessionpg.OriginalSessionFields(p.actor.observed.Session)
	if err != nil {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	digest := p.original.request.Digest()
	fields = append(fields,
		identity.FeatureField{Name: "impersonation.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}},
		identity.FeatureField{Name: "impersonation.target-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.target.Version}},
		identity.FeatureField{Name: "impersonation.requester-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.original.request.Actor().User())}},
		identity.FeatureField{Name: "impersonation.requester-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.original.requesterUserVersion}},
		identity.FeatureField{Name: "impersonation.requester-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.config.Session.Profile.PolicyNamespace}},
		identity.FeatureField{Name: "impersonation.requester-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.original.requesterAuthorityVersion}},
	)
	if b.OperationID == approveAction {
		reason := p.reason.Digest()
		fields = append(fields,
			identity.FeatureField{Name: "impersonation.approval-reason", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: reason[:]}},
			identity.FeatureField{Name: "impersonation.grant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.observed.version}},
			identity.FeatureField{Name: "impersonation.grant-expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.observed.expiresAt}},
		)
	}
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, p.actor.input.Bearer)
	if err != nil {
		return PreparedCommand{}, err
	}
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		if ctx.Err() != nil {
			return PreparedCommand{}, ctx.Err()
		}
		return PreparedCommand{}, identity.UnavailableError{}
	}
	at = at.UTC()
	if err := p.actor.requireFresh(at); err != nil {
		return PreparedCommand{}, err
	}
	if b.OperationID == approveAction && !at.Before(p.observed.expiresAt) {
		return PreparedCommand{}, impersonation.ErrExpired
	}
	command, counters, err := s.config.Risk.PrepareCommandCounters(command, risk.Subject{Actor: string(b.ActorID), Resource: b.RecordID, Network: network}, at)
	if err != nil {
		return PreparedCommand{}, err
	}
	p.command, p.counters = command, counters
	lifecycle := grantLifecycle(b.OperationID)
	p.audit, err = grantAudit(b, op, lifecycle, at)
	if err != nil {
		return PreparedCommand{}, err
	}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return PreparedCommand{}, err
	}
	registration := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{
		Contributors: registry.Descriptors(), Feature: &registration, SubjectType: grantSubject,
		Lifecycle: &lifecycle, Audits: []kernel.AuditPlan{p.audit}, CommandCounters: &counters,
	})
	if err != nil {
		return PreparedCommand{}, err
	}
	return PreparedCommand{state: &preparedState{phase: p, owner: s, coordinator: coordinator, plan: plan}}, nil
}

func grantAudit(b identity.CommandBinding, op identity.FeatureOperation, transition kernel.LifecyclePlan, at time.Time) (kernel.AuditPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{
		OccurredAt: at, Action: b.OperationID, Outcome: audit.OutcomeSucceeded,
		Actor:   audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)},
		Subject: audit.SubjectInput{Type: grantSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{
			"command.id": string(b.CommandID), "aggregate.type": grantSubject, "aggregate.id": b.RecordID,
			"aggregate.before_version": strconv.FormatUint(transition.BeforeVersion, 10),
			"aggregate.after_version":  strconv.FormatUint(transition.AfterVersion, 10), "retention.class": "protected",
		},
	})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, grantSubject, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
		RetentionPolicyVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}, nil
}

func (p *approvalPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	op, ok := approvalOperation(p.binding.OperationID)
	if !ok || command == (identity.Command{}) || command != p.command || plan.Feature == nil ||
		*plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}) ||
		plan.SubjectType != grantSubject || plan.Lifecycle == nil || *plan.Lifecycle != grantLifecycle(p.binding.OperationID) ||
		plan.CommandCounters == nil || *plan.CommandCounters != p.counters || len(plan.Audits) != 1 || plan.Audits[0] != p.audit ||
		plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.OTP != nil || plan.RiskEvidence != nil ||
		plan.CaptchaEvidence != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *approvalPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var locked grantRecord
	b := p.binding
	if b.OperationID == approveAction {
		var err error
		locked, err = lockGrant(ctx, w, b.TenantID, impersonation.GrantID(b.RecordID))
		if err != nil {
			return identity.FeatureReceipt{}, p.storageError(err)
		}
		if !sameGrant(locked, p.observed) {
			return identity.FeatureReceipt{}, identity.ConflictError{CommandID: b.CommandID}
		}
	}
	at, err := p.checkCurrent(ctx, w, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	id := impersonation.GrantID(b.RecordID)
	if b.OperationID == requestAction {
		grant, err := impersonation.NewPendingGrant(id, p.original.request, at)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		err = insertPendingGrant(ctx, w, grantRecord{tenant: b.TenantID, id: id, requester: identity.UserID(b.ActorID), target: b.UserID,
			digest: p.original.request.Digest(), payload: p.payload, requestedAt: grant.RequestedAt(), expiresAt: grant.ExpiresAt(), version: grant.Version()})
		if err != nil {
			return identity.FeatureReceipt{}, p.storageError(err)
		}
	} else {
		grant, err := impersonation.NewPendingGrant(id, p.original.request, locked.requestedAt)
		if err != nil || !locked.expiresAt.Equal(grant.ExpiresAt()) {
			return identity.FeatureReceipt{}, identity.UnavailableError{}
		}
		reviewer, err := impersonation.NewActor(b.TenantID, identity.UserID(b.ActorID))
		if err != nil {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
		_, decision, err := impersonation.Approve(grant, impersonation.ApprovalInput{GrantID: id, ExpectedVersion: locked.version,
			Request: p.original.request, Approver: reviewer, Reason: p.reason, At: at})
		if err != nil {
			return identity.FeatureReceipt{}, p.storageError(err)
		}
		err = saveApproval(ctx, w, locked, approvalRecord{commandID: b.CommandID, approver: identity.UserID(b.ActorID), payload: p.payload, decidedAt: decision.At()})
		if err != nil {
			return identity.FeatureReceipt{}, p.storageError(err)
		}
	}
	op, _ := approvalOperation(b.OperationID)
	l := grantLifecycle(b.OperationID)
	return identity.FeatureReceipt{Operation: op, BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}

func sameGrant(a, b grantRecord) bool {
	return a.tenant == b.tenant && a.id == b.id && a.requester == b.requester && a.target == b.target && a.version == b.version &&
		a.digest == b.digest && a.requestedAt.Equal(b.requestedAt) && a.expiresAt.Equal(b.expiresAt) && bytes.Equal(a.payload, b.payload)
}

func (p *approvalPhase) storageError(err error) error {
	if errors.Is(err, impersonation.ErrConflict) || errors.Is(err, impersonation.ErrExpired) {
		return identity.ConflictError{CommandID: p.binding.CommandID}
	}
	return err
}

func (p *approvalPhase) checkCurrent(ctx context.Context, w kernel.Work, command identity.Command) (time.Time, error) {
	b, registration, l, err := w.FeatureScope(p)
	op, _ := approvalOperation(p.binding.OperationID)
	if err != nil || b != p.binding || command != p.command || registration != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}) || l != grantLifecycle(b.OperationID) {
		return time.Time{}, identity.ForbiddenError{}
	}
	if err := w.RequireActiveTargetUser(ctx, p, p.target); err != nil {
		return time.Time{}, err
	}
	c := p.service.config
	if err := p.actor.checkWork(ctx, w, p, c.Session, c.CSRFKey, b); err != nil {
		return time.Time{}, err
	}
	if b.OperationID == approveAction {
		requester := identity.User{ID: p.observed.requester, TenantID: b.TenantID, Status: identity.StatusActive, Version: p.original.requesterUserVersion}
		policy := kernel.UserAuthorizationAdmission{Scope: authority.AuthorityScope{
			TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(requester.ID), PolicyNamespace: c.Session.Profile.PolicyNamespace,
		}, Version: p.original.requesterAuthorityVersion}
		if err := w.RequireActiveImpersonationRequester(ctx, p, command, requester, policy); err != nil {
			return time.Time{}, err
		}
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	at = at.UTC()
	if b.OperationID == approveAction && !at.Before(p.observed.expiresAt) {
		return time.Time{}, identity.ConflictError{CommandID: b.CommandID}
	}
	// Resolve expiry against the latest in-transaction primary time after the
	// target, actor, original requester and native record locks are held.
	if err := p.actor.requireFresh(at); err != nil {
		return time.Time{}, err
	}
	return at, nil
}

func (p *approvalPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	_, err := p.checkCurrent(ctx, w, c)
	return err
}

func (p *approvalPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, registration, l, err := w.FeatureScope(p)
	op, selected := approvalOperation(b.OperationID)
	if err != nil || !selected || registration != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}) || l != grantLifecycle(b.OperationID) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return recoverGrantEffect(ctx, w, b)
}
