package postgres

import (
	"context"
	"math"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// AccountUnlinkAudits constructs the exact two audit declarations for typed
// self-unlink. The original account version is part of the event, not a new
// clock or eligibility assertion. No audit is written in this call.
func AccountUnlinkAudits(ctx context.Context, original identity.Command, retention uint64) ([]AuditPlan, error) {
	s, _, ok := original.AccountUnlinkPreparationInput()
	if ctx == nil || !ok || retention == 0 || !accountUnlinkBinding(s.Binding) {
		return nil, invalidAudit()
	}
	b := s.Binding
	record, err := securityMutationAuditCausation(ctx, b, s.Change.ExpectedAccountVersion, s.Change.ExpectedAccountVersion+1, s.Counters.PreparedAt, "committed", b.OperationID, "account", b.RecordID, "standard", false, string(b.CommandID))
	if err != nil {
		return nil, err
	}
	digest, err := AuditBindingDigest(b, record)
	if err != nil {
		return nil, err
	}
	return oauthAccountUnlinkAuditPlans(AuditPlan{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}), nil
}

// SECURITY_EVENTS requires both the authoritative account change and the
// OAuth owner's unlink action. Derive the exact second slot from the kernel
// declaration; arbitrary events cannot be appended by an unlink contributor.
func oauthAccountUnlinkAuditPlans(base AuditPlan) []AuditPlan {
	orchestration := base
	orchestration.EventType = "identity.oauth.unlink_account"
	orchestration.EventIndex++
	return []AuditPlan{base, orchestration}
}

func validateOAuthAccountUnlinkAudits(binding identity.CommandBinding, plans []AuditPlan) error {
	if !accountUnlinkBinding(binding) || len(plans) != 2 {
		return invalidAudit()
	}
	base := plans[0]
	if base.EventIndex == math.MaxUint16 || validateKernelAuditPlans(binding, plans[:1]) != nil {
		return invalidAudit()
	}
	expected := oauthAccountUnlinkAuditPlans(base)
	if plans[1] != expected[1] {
		return invalidAudit()
	}
	return nil
}

func accountUnlinkMutationAudits(ctx context.Context, p *admittedKernelPlan, now time.Time, class string) ([]audit.Record, error) {
	if p == nil || p.accountUnlink == nil || p.lifecycle == nil || validateOAuthAccountUnlinkAudits(p.binding, p.audits) != nil {
		return nil, invalidAudit()
	}
	b := p.binding
	orchestration, err := securityMutationAuditCausation(ctx, b, p.lifecycle.BeforeVersion, p.lifecycle.AfterVersion, now, class, p.audits[1].EventType, "account", b.RecordID, "standard", false, string(b.CommandID))
	if err != nil {
		return nil, err
	}
	kernel, err := securityMutationAuditCausation(ctx, b, p.lifecycle.BeforeVersion, p.lifecycle.AfterVersion, now, class, p.audits[0].EventType, "account", b.RecordID, "standard", false, orchestration.ID())
	if err != nil {
		return nil, err
	}
	return []audit.Record{kernel, orchestration}, nil
}
