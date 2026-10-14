package postgres

import "testing"

func TestStagedAuditsAreCompleteOwnedSnapshots(t *testing.T) {
	w, r, p := auditFixture(t)
	if entries, e := w.StagedAudits(); e == nil || entries != nil {
		t.Fatal("undeclared audit exposed")
	}
	if e := bindAuditPlans(w, []AuditPlan{p}); e != nil {
		t.Fatal(e)
	}
	if entries, e := w.StagedAudits(); e == nil || entries != nil {
		t.Fatal("incomplete audit exposed")
	}
	if e := w.StageAudit(p.EventIndex, r); e != nil {
		t.Fatal(e)
	}
	entries, e := w.StagedAudits()
	if e != nil || len(entries) != 1 || entries[0].Plan != p || entries[0].Record.ID() != r.ID() {
		t.Fatal("complete audit changed", e)
	}
	entries[0].Plan.EventType = "identity.user.delete"
	entries[0].Record = r // Record is immutable; the slice itself must be owned.
	again, e := w.StagedAudits()
	if e != nil || again[0].Plan != p {
		t.Fatal("snapshot mutation changed Work")
	}
	invalidateWork(w)
	if entries, e = w.StagedAudits(); e == nil || entries != nil {
		t.Fatal("closed Work exposed audit")
	}
	if entries, e = (Work{}).StagedAudits(); e == nil || entries != nil {
		t.Fatal("zero Work exposed audit")
	}
}

func TestKernelAdmissionRequiresDurableAuditPhase(t *testing.T) {
	w, _, ap := auditFixture(t)
	domain := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	auditing := ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
	r, _ := NewContributorRegistry([]Contributor{&registryContributor{domain}, &registryContributor{auditing}})
	p := CommandPlan{Contributors: []ContributorDescriptor{domain, auditing}, Audits: []AuditPlan{ap}}
	fp := [32]byte{1}
	p.Digest, _ = KernelPlanDigest(w.state.binding, fp, p)
	if admitted, e := r.admitKernelPlan(w.state.binding, fp, p); e == nil || admitted != nil {
		t.Fatal("descriptor-only audit participant admitted without durable phase")
	}
}
