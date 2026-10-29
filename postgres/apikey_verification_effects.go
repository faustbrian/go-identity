package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// APIKeyVerificationOutcome selects the result of an actual native comparison
// inside the original Work. PermissionsChanged means that Work also persisted
// the declared key's non-expanding grant and checked version successor. It does
// not imply successful authentication: denied use of a removed permission can
// commit the narrowing and its own successful update audit atomically.
// Unknown keys may select neither authentication nor a permission mutation.
type APIKeyVerificationOutcome struct {
	Authenticated      bool
	PermissionsChanged bool
}

// APIKeyVerificationContributor owns credential comparison, current authority
// and an optional strict permission reduction inside the original Work. Only
// the exact closed API-key verification plan selects this phase. Generic
// mutation contributors cannot supply its disposition. The returned receipt
// remains record-free; authentication and permission mutation are independent.
// CheckFeatureCommit must fence the original credential, current owner/policy
// and original freshness after required effects, without renewing authority.
// Implementations follow FeatureExecutionContributor's ownership, cancellation,
// concurrency, redaction and no-network rules. A denial is a nil-error false
// authentication result; errors roll back the entire attempt, including Narrow.
type APIKeyVerificationContributor interface {
	FeatureCommitContributor
	ApplyAPIKeyVerification(context.Context, Work, identity.Command) (identity.FeatureReceipt, APIKeyVerificationOutcome, error)
}

type apiKeyVerificationEffects struct {
	audits    []audit.Record
	lifecycle *LifecyclePlan
}

func buildAPIKeyVerificationEffects(ctx context.Context, p *admittedKernelPlan, outcome APIKeyVerificationOutcome, now time.Time) (apiKeyVerificationEffects, error) {
	if !validAPIKeyVerificationOutcome(p, outcome) {
		return apiKeyVerificationEffects{}, invalidPlan()
	}
	target := featureAuditTargetID(p.binding, p.feature.Operation)
	class := "denied"
	if outcome.Authenticated {
		class = "committed"
	}
	// The authentication attempt never claims a credential version transition.
	// The independently selected update slot owns that transition, even when
	// the current request cannot use the resulting narrower credential.
	authentication, err := securityMutationAuditCausation(ctx, p.binding, 0, 0, now, class, p.audits[0].EventType, p.subjectType, target, "protected", true, string(p.binding.CommandID))
	if err != nil {
		return apiKeyVerificationEffects{}, err
	}
	effects := apiKeyVerificationEffects{audits: []audit.Record{authentication}}
	if !outcome.PermissionsChanged {
		return effects, nil
	}
	before := p.apiKeyVerification.KeyVersion
	// SECURITY_EVENTS requires distinct causal predecessors for composed,
	// non-synonymous actions. Authentication is caused by the original command;
	// the separately selected reduction receives its own opaque canonical ID.
	causation, err := identity.NewSubjectID()
	if err != nil || string(causation) == string(p.binding.CommandID) {
		return apiKeyVerificationEffects{}, invalidAudit()
	}
	update, err := securityMutationAuditCausation(ctx, p.binding, before, before+1, now, "committed", p.audits[1].EventType, p.subjectType, target, "protected", true, string(causation))
	if err != nil {
		return apiKeyVerificationEffects{}, err
	}
	effects.audits = append(effects.audits, update)
	effects.lifecycle = &LifecyclePlan{EventType: "api_key.permissions_changed.v1", BeforeVersion: before, AfterVersion: before + 1}
	return effects, nil
}

func validAPIKeyVerificationOutcome(p *admittedKernelPlan, outcome APIKeyVerificationOutcome) bool {
	return p != nil && validAPIKeyVerificationPlan(p.binding, p.snapshot()) && (p.feature.Operation != apiKeyVerificationOperation(true) || !outcome.Authenticated && !outcome.PermissionsChanged)
}

func selectAPIKeyVerificationAudits(w Work, count int) error {
	p := w.state.execution.reservation.plan
	a := w.state.audits
	if p.apiKeyVerification == nil || a == nil || count < 1 || count > len(p.audits) || count > 2 || a.bytes != 0 || len(a.ids) != 0 {
		return invalidAudit()
	}
	for _, staged := range a.staged {
		if staged {
			return invalidAudit()
		}
	}
	// The immutable retained plan declares the closed maximum. Only the
	// coordinator selects which slots actually exist for this native outcome.
	// Rolled-back attempts select authentication alone, never a fictional update.
	a.plans, a.records, a.staged = a.plans[:count], a.records[:count], a.staged[:count]
	return nil
}

func stageAPIKeyVerificationEffects(ctx context.Context, w Work, now time.Time) ([]audit.Record, error) {
	if w.state.apiKeyVerification == nil {
		return nil, invalidWork()
	}
	p := w.state.execution.reservation.plan
	effects, err := buildAPIKeyVerificationEffects(ctx, p, *w.state.apiKeyVerification, now)
	if err != nil {
		return nil, err
	}
	if err := selectAPIKeyVerificationAudits(w, len(effects.audits)); err != nil {
		return nil, err
	}
	for i, record := range effects.audits {
		if err := w.StageAudit(p.audits[i].EventIndex, record); err != nil {
			return nil, err
		}
	}
	if effects.lifecycle != nil {
		if err := w.StageLifecycle(p.lifecycle.EventIndex, now); err != nil {
			return nil, err
		}
	}
	return effects.audits, nil
}

func validateAPIKeyVerificationAudits(w Work) error {
	if err := completeAudits(w); err != nil {
		return err
	}
	p, outcome := w.state.execution.reservation.plan, w.state.apiKeyVerification
	if outcome == nil || !validAPIKeyVerificationOutcome(p, *outcome) {
		return invalidAudit()
	}
	count := 1
	if outcome.PermissionsChanged {
		count++
	}
	a := w.state.audits
	if len(a.plans) != count || len(a.records) != count || len(a.staged) != count {
		return invalidAudit()
	}
	target := featureAuditTargetID(p.binding, p.feature.Operation)
	for i, record := range a.records {
		before, after := uint64(0), uint64(0)
		succeeded := outcome.Authenticated
		if i == 1 {
			before, after, succeeded = p.apiKeyVerification.KeyVersion, p.apiKeyVerification.KeyVersion+1, true
		}
		expected, reason := audit.OutcomeDenied, "not_authorized"
		changes := record.Changes().NoChange()
		if succeeded {
			expected, reason, changes = audit.OutcomeSucceeded, "completed", record.Changes().Redacted()
		}
		attrs := record.Attributes()
		causation := record.Context().CausationID()
		_, causeErr := identity.ParseSubjectID(causation)
		if causeErr != nil || (i == 0) != (causation == string(p.binding.CommandID)) || a.plans[i] != p.audits[i] || record.Action() != p.audits[i].EventType || record.Outcome() != expected || record.ReasonCode() != reason || !changes || record.Subject().Type() != p.subjectType || record.Subject().ID() != target || attrs["aggregate.before_version"] != strconv.FormatUint(before, 10) || attrs["aggregate.after_version"] != strconv.FormatUint(after, 10) {
			return invalidAudit()
		}
	}
	return nil
}

func apiKeyVerificationLifecyclePlan(w Work) (LifecyclePlan, error) {
	p, outcome := w.state.execution.reservation.plan, w.state.apiKeyVerification
	if outcome == nil || !outcome.PermissionsChanged || !validAPIKeyVerificationOutcome(p, *outcome) {
		return LifecyclePlan{}, invalidLifecycle()
	}
	plan := *p.lifecycle
	plan.BeforeVersion, plan.AfterVersion = p.apiKeyVerification.KeyVersion, p.apiKeyVerification.KeyVersion+1
	return plan, nil
}
