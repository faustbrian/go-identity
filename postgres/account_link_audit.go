package postgres

import (
	"context"
	"math"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// The v2 RP plan has a closed, derivable audit set. It preserves the installed
// v1 kernel declaration bytes rather than introducing a generic extra-event
// bag. SECURITY_EVENTS.md requires both OAuth orchestration actions as well as
// the authoritative account mutation, with distinct causation and one outcome.
func oauthAccountLinkAuditPlans(base AuditPlan) []AuditPlan {
	plans := []AuditPlan{base}
	for i, action := range []string{"identity.oauth.handle_callback", "identity.oauth.link_account"} {
		p := base
		// audit/postgres reserves explicit RetentionClass for feature plans.
		// Kernel declarations inherit its empty sentinel; records below still
		// carry the required standard self-service retention class.
		p.EventType, p.EventIndex = action, base.EventIndex+uint16(i+1)
		plans = append(plans, p)
	}
	return plans
}

func validateOAuthAccountLinkAudits(binding identity.CommandBinding, plans []AuditPlan) error {
	if !accountLinkBinding(binding) || len(plans) != 3 {
		return invalidAudit()
	}
	base := plans[0]
	if base.EventIndex > math.MaxUint16-2 || validateKernelAuditPlans(binding, plans[:1]) != nil {
		return invalidAudit()
	}
	expected := oauthAccountLinkAuditPlans(base)
	for i := range plans {
		if plans[i] != expected[i] {
			return invalidAudit()
		}
	}
	return nil
}

func accountLinkMutationAudits(ctx context.Context, p *admittedKernelPlan, now time.Time, class string) ([]audit.Record, error) {
	if p == nil || p.lifecycle == nil {
		return nil, invalidAudit()
	}
	before := p.lifecycle.BeforeVersion
	if len(p.audits) == 1 {
		record, err := kernelMutationAudit(ctx, p.binding, before, now, class)
		return []audit.Record{record}, err
	}
	if p.accountLinkState == nil || validateOAuthAccountLinkAudits(p.binding, p.audits) != nil {
		return nil, invalidAudit()
	}
	b := p.binding
	callback, err := securityMutationAuditCausation(ctx, b, before, p.lifecycle.AfterVersion, now, class, p.audits[1].EventType, "account", b.RecordID, "standard", false, string(b.CommandID))
	if err != nil {
		return nil, err
	}
	link, err := securityMutationAuditCausation(ctx, b, before, p.lifecycle.AfterVersion, now, class, p.audits[2].EventType, "account", b.RecordID, "standard", false, callback.ID())
	if err != nil {
		return nil, err
	}
	kernel, err := securityMutationAuditCausation(ctx, b, before, p.lifecycle.AfterVersion, now, class, p.audits[0].EventType, "account", b.RecordID, "standard", false, link.ID())
	if err != nil {
		return nil, err
	}
	return []audit.Record{kernel, callback, link}, nil
}
