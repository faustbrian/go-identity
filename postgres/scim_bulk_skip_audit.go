package postgres

import (
	"context"
	"crypto/sha256"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// SCIMBulkSkippedChild identifies one admitted child changed to skipped in
// the original failure transaction. Ordinal is its zero-based request order.
type SCIMBulkSkippedChild struct {
	CommandID identity.CommandID
	Ordinal   uint16
}

// SCIMBulkSkipAudit is a coordinator-built protected event. The audit owner
// binds it to the skipped child at event index zero, not to the command that
// triggered cutoff. These records are separate from that command's frozen plan.
type SCIMBulkSkipAudit struct {
	Child                  SCIMBulkSkippedChild
	Record                 audit.Record
	RetentionPolicyVersion uint64
	BindingDigest          [32]byte
}

// SCIMBulkSkipAuditContributor appends only coordinator-built cutoff events
// with StagedSCIMBulkSkipAudits inside the same terminal Work. It must fail
// if any append cannot be acknowledged and must not retain Work.
type SCIMBulkSkipAuditContributor interface {
	AuditContributor
	PersistSCIMBulkSkipAudits(context.Context, Work) error
}

type scimBulkSkipPhase struct {
	written bool
	owner   SCIMBulkSkipAuditContributor
	records []SCIMBulkSkipAudit
}

// PersistSCIMBulkChildSkipAudits appends the complete nonempty skip set via the
// registered audit owner. It conveys no commit result. It is valid only once
// in the exact failure callback, after native storage has changed these children
// from admitted to skipped in this Work. Children must be strictly ordered by
// ordinal and cannot include the parent or triggering command. The caller must
// recheck current source authority after this bounded append.
func (w Work) PersistSCIMBulkChildSkipAudits(ctx context.Context, owner SCIMBulkChildFailureContributor, children []SCIMBulkSkippedChild) error {
	binding, _, _, err := w.FeatureScope(owner)
	if err != nil || ctx == nil || ctx.Err() != nil || w.state.scimBulkSkip == nil {
		return invalidWork()
	}
	phase := w.state.scimBulkSkip
	// The protocol admits at most 1,000 operations; one is the failed trigger.
	if len(children) == 0 || len(children) > 999 || phase.written {
		return w.fail(ctx, invalidAudit())
	}
	seen := make(map[identity.CommandID]struct{}, len(children))
	for i, child := range children {
		_, err := identity.ParseCommandID(string(child.CommandID))
		if err != nil || child.CommandID == binding.CommandID || string(child.CommandID) == binding.CorrelationID ||
			child.Ordinal >= 1000 || i > 0 && children[i-1].Ordinal >= child.Ordinal {
			return w.fail(ctx, invalidAudit())
		}
		if _, duplicate := seen[child.CommandID]; duplicate {
			return w.fail(ctx, invalidAudit())
		}
		seen[child.CommandID] = struct{}{}
	}
	phase.written = true
	// The audit owner may read staged events but cannot impersonate the native
	// contributor or exercise native feature-scoped authority while appending.
	w.state.featureInvocation = nil
	defer func() { w.state.featureInvocation = owner }()
	if err := persistSCIMBulkSkips(ctx, w, phase, children); err != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	return w.usable()
}

// StagedSCIMBulkSkipAudits returns an owned copy only during the exact
// registered audit contributor's non-retainable cutoff persistence call.
func (w Work) StagedSCIMBulkSkipAudits(owner SCIMBulkSkipAuditContributor) ([]SCIMBulkSkipAudit, error) {
	if w.usable() != nil || w.state.scimBulkSkip == nil {
		return nil, invalidWork()
	}
	phase := w.state.scimBulkSkip
	if phase.owner == nil || !sameParticipant(phase.owner, owner) || len(phase.records) == 0 {
		return nil, invalidWork()
	}
	return slices.Clone(phase.records), nil
}

func persistSCIMBulkSkips(ctx context.Context, w Work, phase *scimBulkSkipPhase, children []SCIMBulkSkippedChild) error {
	plan := w.state.execution.reservation.plan
	trigger := plan.audits[0]
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "audit/postgres" {
			phase.owner, _ = entry.contributor.(SCIMBulkSkipAuditContributor)
			break
		}
	}
	if phase.owner == nil || trigger.RetentionClass != "protected" || w.usable() != nil {
		return invalidAudit()
	}
	defer func() {
		phase.owner = nil
		phase.records = nil
	}()
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	phase.records, err = makeSCIMBulkSkipAudits(ctx, w.state.binding, w.state.feature.Operation, trigger, children, now)
	if err != nil {
		return err
	}
	if err := phase.owner.PersistSCIMBulkSkipAudits(ctx, w); err != nil {
		return err
	}
	if w.state.rows != nil {
		return invalidWork()
	}
	return w.usable()
}

func makeSCIMBulkSkipAudits(ctx context.Context, binding identity.CommandBinding, operation identity.FeatureOperation, trigger AuditPlan, children []SCIMBulkSkippedChild, now time.Time) ([]SCIMBulkSkipAudit, error) {
	const action = "identity.scim.bulk_skip_child"
	const kind = "scim_bulk_child"
	builder, err := audit.NewBuilder(audit.BuilderConfig{Limits: securityAuditLimits(), IDGenerator: func() (string, error) {
		id, err := identity.NewSubjectID()
		return string(id), err
	}})
	if err != nil {
		return nil, invalidAudit()
	}
	allowed := []string{"identity.profile", "command.id", "retention.class", "scim.bulk.operation_order"}
	redactor, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: allowed})
	if err != nil {
		return nil, invalidAudit()
	}
	original := commandSafeFields(binding, &operation)
	records := make([]SCIMBulkSkipAudit, 0, len(children))
	for _, child := range children {
		record, err := builder.Build(audit.RecordInput{
			OccurredAt: now, Action: action, Outcome: audit.OutcomeDenied, ReasonCode: "identity.scim.fail_on_errors_cutoff",
			Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: kind, ID: string(child.CommandID)},
			Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID, CausationID: string(binding.CommandID)},
			Policy:  audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: strconv.FormatUint(binding.PolicyVersion, 10)},
			Changes: audit.ChangeSetInput{NoChange: true},
			Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(child.CommandID), "retention.class": "protected",
				"scim.bulk.operation_order": strconv.FormatUint(uint64(child.Ordinal), 10)},
		})
		if err != nil {
			return nil, invalidAudit()
		}
		record, err = redactor.Redact(ctx, record)
		if err != nil || !record.RedactionApplied() {
			return nil, invalidAudit()
		}
		// The triggering command remains the authority and causation. The
		// skipped child's identity has only an audit binding, not a journal lease.
		digest := sha256.Sum256(cborMap(map[string][]byte{"domain": cborText("identity-scim-bulk-skip-v1"), "command": original,
			"child": cborText(string(child.CommandID)), "ordinal": cborUint(uint64(child.Ordinal))}))
		records = append(records, SCIMBulkSkipAudit{Child: child, Record: record, RetentionPolicyVersion: trigger.RetentionPolicyVersion, BindingDigest: digest})
	}
	return records, nil
}
