package postgres

import (
	"bytes"
	"context"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// FeatureExecutionContributor is the complete native non-one-time feature
// participant. Registration remains immutable; only the coordinator invokes
// ApplyFeature and recovery. ValidateFeatureCommand is a pure bounded local
// operation, validating every native field, declared security action, subject
// kind and transition before reservation. No request-generated callbacks, IO,
// mutation of the supplied plan, hooks or private transactions are permitted.
// ApplyFeature receives the sole generation-bound Work, performs current
// authority/optimistic checks and its owned mutation, and returns a provisional
// primary-record receipt. It must not stage audit/lifecycle, close or retain Work,
// mutate kernel-owned tables, perform network IO, or return secret material.
// The coordinator stages the declared effects and establishes durability.
// Methods must support concurrent calls with independent serial-use handles.
// Risk execution additionally requires its exact typed current-check/finalize
// owner. Capability/OTP profiles remain rejected until their typed phases exist.
type FeatureExecutionContributor interface {
	FeatureContributor
	RecoveryContributor
	ValidateFeatureCommand(identity.Command, CommandPlan) error
	ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error)
}

// Keep both pre-transaction and open-Work validation inside the same redaction
// boundary. Validation has no authority to preserve callback diagnostics.
func validateFeatureCommand(phase FeatureExecutionContributor, command identity.Command, plan CommandPlan) (err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err := phase.ValidateFeatureCommand(command, plan); err != nil {
		return err
	}
	if plan.Feature != nil && credentialCompromiseOperation(plan.Feature.Operation) {
		p, ok := phase.(CredentialCompromiseContributor)
		if !ok {
			return invalidCredentialCompromise()
		}
		_, err := compromiseCommand(p, command, plan)
		return err
	}
	return nil
}

func (r *ContributorRegistry) admitFeaturePlan(b identity.CommandBinding, fingerprint [32]byte, p CommandPlan) (*admittedKernelPlan, error) {
	digest, err := FeaturePlanDigest(b, fingerprint, p)
	if err != nil || digest != p.Digest || p.SubjectType == "" {
		return nil, invalidPlan()
	}
	feature, err := r.selectFeatureOperation(*p.Feature)
	if err != nil {
		return nil, invalidPlan()
	}
	if _, ok := feature.contributor.(FeatureExecutionContributor); !ok {
		return nil, invalidPlan()
	}
	target, actorKind := string(b.UserID), audit.ActorService
	if b.RecordID != "" {
		target = b.RecordID
	}
	if b.ActorKind == authorization.SubjectUser {
		actorKind = audit.ActorHuman
	}
	if !auditSafeID(target) {
		return nil, invalidPlan()
	}
	expected := securityAuditScopeDigest(b, &p.Feature.Operation, p.SubjectType, target, actorKind, "identity-feature-audit-binding-v1")
	for _, a := range p.Audits {
		if a.BindingDigest != expected {
			return nil, invalidPlan()
		}
	}
	entries, err := r.selectContributors(p.Contributors)
	if err != nil {
		return nil, invalidPlan()
	}
	if validateDeliveryContributor(b, p.Delivery, entries) != nil {
		return nil, invalidPlan()
	}
	if credentialCompromiseOperation(p.Feature.Operation) {
		if _, ok := feature.contributor.(CredentialCompromiseContributor); !ok {
			return nil, invalidPlan()
		}
		for _, entry := range entries {
			if entry.descriptor.Owner == "identity/postgres" {
				if _, ok := entry.contributor.(*Repository); !ok {
					return nil, invalidPlan()
				}
			}
			if entry.descriptor.Owner == "outbox/postgres" {
				if _, ok := entry.contributor.(CredentialCompromiseLifecycleContributor); !ok {
					return nil, invalidPlan()
				}
			}
		}
	}
	for _, entry := range entries {
		if _, ok := entry.contributor.(RecoveryContributor); !ok {
			return nil, invalidPlan()
		}
		switch entry.descriptor.Owner {
		case "audit/postgres":
			if _, ok := entry.contributor.(AuditContributor); !ok {
				return nil, invalidPlan()
			}
		case "outbox/postgres":
			if _, ok := entry.contributor.(LifecycleContributor); !ok {
				return nil, invalidPlan()
			}
		case "identity/risk/postgres":
			// The same store also owns ordinary evidence issuance as the native
			// feature participant. Only a declared consuming role needs reservation.
			if p.RiskEvidence != nil {
				if _, ok := riskReservationParticipant(entry.contributor); !ok {
					return nil, invalidPlan()
				}
			}
			if p.CommandCounters != nil {
				if _, ok := commandCounterParticipant(entry.contributor); !ok {
					return nil, invalidPlan()
				}
			}
		}
	}
	f, l := *p.Feature, *p.Lifecycle
	var risk *RiskEvidencePlan
	if p.RiskEvidence != nil {
		copy := *p.RiskEvidence
		risk = &copy
	}
	var counters *CommandCounterPlan
	if p.CommandCounters != nil {
		copy := *p.CommandCounters
		counters = &copy
	}
	return &admittedKernelPlan{registry: r.state, binding: b, digest: digest, contributors: entries, audits: append([]AuditPlan(nil), p.Audits...), lifecycle: &l, risk: risk, counters: counters, fingerprint: fingerprint, feature: &f, subjectType: p.SubjectType, delivery: cloneDeliveryPlan(p.Delivery)}, nil
}

// ApplyFeature invokes only the frozen exact native adapter once through Work.
// Input must equal the admitted command's complete keyed intent. It prebuilds
// bounded failure evidence from primary time before mutation, validates the
// native provisional receipt, and stages every declared security/lifecycle slot.
// This is a trusted adapter composition seam, not an authentication endpoint.
// No bearer is generated/revealed. A returned receipt is provisional until
// Commit succeeds; the caller must always defer Abort. Errors poison Work;
// contributor diagnostics/panics are redacted. No local retry is performed.
func (c *Coordinator) ApplyFeature(ctx context.Context, w Work, command identity.Command) (result identity.CommandResult, err error) {
	if ctx == nil || !c.owns(w) || w.state.feature == nil {
		return result, invalidWork()
	}
	if err = w.usable(); err != nil {
		return result, err
	}
	if w.state.featureAttempted || w.state.creation != nil || w.state.profile != nil || w.state.update != nil {
		return result, w.fail(ctx, identity.ConflictError{})
	}
	q, e := prepareClaim(command, c.keys.retained[c.keys.current])
	if e != nil || !bytes.Equal(q.canonical, w.state.execution.reservation.request.canonical) {
		return result, w.fail(ctx, identity.ConflictError{})
	}
	p := w.state.execution.reservation.plan
	entry, e := c.registry.selectFeatureOperation(*p.feature)
	if e != nil {
		return result, w.fail(ctx, invalidPlan())
	}
	phase, ok := entry.contributor.(FeatureExecutionContributor)
	if !ok {
		return result, w.fail(ctx, invalidPlan())
	}
	if e = validateFeatureCommand(phase, command, p.snapshot()); e != nil {
		return result, w.fail(ctx, invalidPlan())
	}
	w.state.featureAttempted = true
	defer func() {
		if recover() != nil {
			result = identity.CommandResult{}
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	now, e := w.DatabaseTime(ctx)
	if e != nil {
		return result, e
	}
	w.state.execution.featureAbortAudits = make(map[string][]audit.Record, 5)
	for _, class := range []string{"denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		records, e := featureMutationAudits(ctx, p, now, class)
		if e != nil {
			return result, w.fail(ctx, e)
		}
		w.state.execution.featureAbortAudits[class] = records
	}
	if e = c.checkCommandCounters(ctx, w, command); e != nil {
		return result, e
	}
	if p.counters != nil {
		// Command is opaque immutable owned input, retained only by this Work
		// for the final current check; it never enters a durable plan or receipt.
		w.state.counterCommand = &command
	}
	if e = c.runRiskExecution(ctx, w, command, false); e != nil {
		return result, e
	}
	if p.risk != nil {
		w.state.riskCommand = &command
	}
	if credentialCompromiseOperation(p.feature.Operation) {
		if e := prepareCredentialCompromise(ctx, w, command); e != nil {
			return result, e
		}
	}
	receipt, e := invokeFeature(phase, ctx, w, command)
	if e != nil {
		_, _, _, safe := abortClassification(e)
		return result, w.fail(ctx, safe)
	}
	if e = w.usable(); e != nil {
		return result, e
	}
	if w.state.rows != nil || receipt.Operation != p.feature.Operation || receipt.BeforeVersion != p.lifecycle.BeforeVersion || receipt.AfterVersion != p.lifecycle.AfterVersion {
		return result, w.fail(ctx, identity.InvalidInputError{Field: "feature_receipt"})
	}
	if w.state.credentialIntent != nil {
		if e := applyCredentialCompromise(ctx, w); e != nil {
			return result, e
		}
	}
	success, e := featureMutationAudits(ctx, p, now, "committed")
	if e != nil {
		return result, w.fail(ctx, e)
	}
	for i, record := range success {
		if e = w.StageAudit(p.audits[i].EventIndex, record); e != nil {
			return result, e
		}
	}
	if e = w.StageLifecycle(p.lifecycle.EventIndex, now); e != nil {
		return result, e
	}
	result = identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: success[0].ID(), Feature: &receipt}
	if result.Validate() != nil {
		return identity.CommandResult{}, w.fail(ctx, identity.InvalidInputError{Field: "feature_receipt"})
	}
	stored := receipt
	w.state.featureReceipt = &stored
	return result, nil
}

// Restrict self-verification to the exact synchronous native phase. Clear it
// even when the contributor panics; usable Work must not revive the invocation.
func invokeFeature(p FeatureExecutionContributor, ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	w.state.featureInvocation = p
	defer func() { w.state.featureInvocation = nil }()
	return p.ApplyFeature(ctx, w, command)
}

func featureMutationAudits(ctx context.Context, p *admittedKernelPlan, now time.Time, class string) ([]audit.Record, error) {
	records := make([]audit.Record, len(p.audits))
	target := string(p.binding.UserID)
	if p.binding.RecordID != "" {
		target = p.binding.RecordID
	}
	for i, a := range p.audits {
		record, err := securityMutationAudit(ctx, p.binding, p.lifecycle.BeforeVersion, p.lifecycle.AfterVersion, now, class, a.EventType, p.subjectType, target, a.RetentionClass, true)
		if err != nil {
			return nil, err
		}
		records[i] = record
	}
	return records, nil
}

func featureOutcome(b identity.CommandBinding, f *identity.FeatureOperation, outcome identity.CommitOutcome, retry time.Duration) identity.CommandResult {
	r := identity.CommandResult{Binding: b, Outcome: outcome, RetryAfter: retry}
	if f != nil {
		r.Feature = &identity.FeatureReceipt{Operation: *f}
	}
	return r
}
