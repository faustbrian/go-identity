package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestAccountUnlinkPlanRequiresBothSecurityActions(t *testing.T) {
	binding, plan := unlinkPlanFixture(t)
	additional := plan.Audits[0]
	additional.EventType = "identity.oauth.unlink_account"
	additional.EventIndex++
	plan.Audits = []AuditPlan{plan.Audits[0], additional}
	for _, preparation := range []bool{false, true} {
		candidate := plan
		if preparation {
			candidate.Capability = nil
		}
		wire, err := encodeKernelPlan(binding, [32]byte{8}, candidate)
		if err != nil {
			t.Fatal("closed unlink cannot declare both mandatory audit actions", preparation, err)
		}
		decoded, err := decodeKernelPlan(binding, [32]byte{8}, wire)
		if err != nil || !reflect.DeepEqual(decoded.Audits, candidate.Audits) {
			t.Fatal("original unlink history lost a required audit action", err)
		}
		for _, mutate := range []func([]AuditPlan) []AuditPlan{
			func(p []AuditPlan) []AuditPlan { return p[:1] },
			func(p []AuditPlan) []AuditPlan { p[1].EventType = "identity.oauth.link_account"; return p },
			func(p []AuditPlan) []AuditPlan { p[1].EventIndex = p[0].EventIndex; return p },
			func(p []AuditPlan) []AuditPlan { p[1].RetentionClass = "protected"; return p },
			func(p []AuditPlan) []AuditPlan { p[1].BindingDigest[0] ^= 1; return p },
		} {
			invalid := candidate
			invalid.Audits = mutate(append([]AuditPlan(nil), candidate.Audits...))
			if _, err := encodeKernelPlan(binding, [32]byte{8}, invalid); err == nil {
				t.Fatal("missing, substituted or rebound unlink action admitted")
			}
		}
	}
}

func TestAccountUnlinkAuditRecordsShareOutcomeWithoutLosingCausation(t *testing.T) {
	c, command, declaration := unlinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountUnlinkCounterCommand()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, declaration)
	if err != nil {
		t.Fatal(err)
	}
	_, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []string{"committed", "denied", "conflict", "dependency-failure"} {
		records, err := accountUnlinkMutationAudits(context.Background(), admitted, time.Unix(1000, 0).UTC(), class)
		if err != nil || len(records) != 2 {
			t.Fatal("required unlink audit group missing", class, err)
		}
		if records[0].Action() != "identity.account.unlink" || records[1].Action() != "identity.oauth.unlink_account" || records[0].ID() == records[1].ID() || records[0].Context().CausationID() != records[1].ID() || records[1].Context().CausationID() != string(spec.Binding.CommandID) {
			t.Fatal("unlink audit action or original causal chain changed", class)
		}
		for i, record := range records {
			digest, err := AuditBindingDigest(spec.Binding, record)
			if err != nil || digest != admitted.audits[i].BindingDigest || record.Outcome() != records[0].Outcome() || record.ReasonCode() != records[0].ReasonCode() || record.Changes().NoChange() != (class != "committed") {
				t.Fatal("unlink audit group changed binding or outcome", class, err)
			}
		}
	}
	if _, err := accountUnlinkMutationAudits(context.Background(), nil, time.Unix(1000, 0), "committed"); err == nil {
		t.Fatal("absent unlink owner minted audit evidence")
	}
	foreign := *admitted
	foreign.accountUnlink = nil
	if _, err := accountUnlinkMutationAudits(context.Background(), &foreign, time.Unix(1000, 0), "committed"); err == nil {
		t.Fatal("foreign domain owner minted unlink audit evidence")
	}
}
