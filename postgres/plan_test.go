package postgres

import (
	"testing"
)

func TestKernelPlanOwnsSelectionAndAudits(t *testing.T) {
	w, record, ap := auditFixture(t)
	domain := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	auditing := ContributorDescriptor{Owner: "audit/postgres", ContractID: "audit.records", Version: 1}
	registry, err := NewContributorRegistry([]Contributor{&registryContributor{domain}, &registryContributor{auditing}})
	if err != nil {
		t.Fatal(err)
	}
	p := CommandPlan{Contributors: []ContributorDescriptor{domain, auditing}, Audits: []AuditPlan{ap}}
	fingerprint := [32]byte{1}
	p.Digest, err = KernelPlanDigest(w.state.binding, fingerprint, p)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := registry.admitKernelPlan(w.state.binding, fingerprint, p)
	if err != nil {
		t.Fatal(err)
	}
	original := p.Digest
	w.state.registry = registry.state
	p.Contributors[0] = ContributorDescriptor{}
	p.Audits[0].EventType = "identity.user.delete"
	p.Digest = [32]byte{}
	if admitted.digest != original || admitted.contributors[0].descriptor != domain || admitted.audits[0].EventType != record.Action() {
		t.Fatal("caller mutation changed admitted plan")
	}
	if err := admitted.bindWork(w); err != nil {
		t.Fatal(err)
	}
	if err := w.StageAudit(ap.EventIndex, record); err != nil {
		t.Fatal(err)
	}
	if err := completeAudits(w); err != nil {
		t.Fatal(err)
	}
	other, _ := NewContributorRegistry([]Contributor{&registryContributor{domain}, &registryContributor{auditing}})
	if err := admitted.belongsTo(other); err == nil {
		t.Fatal("foreign registry accepted")
	}
	if err := admitted.belongsTo(registry); err != nil {
		t.Fatal(err)
	}
}

func TestKernelPlanDigestConservesInputs(t *testing.T) {
	w, _, ap := auditFixture(t)
	domain := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	auditing := ContributorDescriptor{Owner: "audit/postgres", ContractID: "audit.records", Version: 1}
	base := CommandPlan{Contributors: []ContributorDescriptor{domain, auditing}, Audits: []AuditPlan{ap}}
	fingerprint := [32]byte{1}
	original, err := KernelPlanDigest(w.state.binding, fingerprint, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Contributors[0], p.Contributors[1] = p.Contributors[1], p.Contributors[0] },
		func(p *CommandPlan) { p.Contributors[0].Version++ },
		func(p *CommandPlan) { p.Contributors[1].ContractID = "audit.other" },
		func(p *CommandPlan) { p.Audits[0].EventIndex++ },
		func(p *CommandPlan) { p.Audits[0].BindingDigest[1]++ },
		func(p *CommandPlan) { p.Audits[0].RetentionPolicyVersion++ },
		func(p *CommandPlan) { p.Audits[0].MaxRecordBytes-- },
		func(p *CommandPlan) { p.Audits[0].MaxRecordBytes--; p.Audits[0].MaxAggregateBytes-- },
	} {
		p := CommandPlan{Contributors: append([]ContributorDescriptor(nil), base.Contributors...), Audits: append([]AuditPlan(nil), base.Audits...)}
		change(&p)
		d, err := KernelPlanDigest(w.state.binding, fingerprint, p)
		if err != nil || d == original {
			t.Fatal("valid distinct plan not bound", err)
		}
	}
	base.Digest = [32]byte{99}
	d, err := KernelPlanDigest(w.state.binding, fingerprint, base)
	if err != nil || d != original {
		t.Fatal("self-referential digest")
	}
}

func TestKernelPlanCannotBindForeignOrLateWork(t *testing.T) {
	w, _, ap := auditFixture(t)
	ds := []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}}
	r, _ := NewContributorRegistry([]Contributor{&registryContributor{ds[0]}, &registryContributor{ds[1]}})
	p := CommandPlan{Contributors: ds, Audits: []AuditPlan{ap}}
	fp := [32]byte{1}
	p.Digest, _ = KernelPlanDigest(w.state.binding, fp, p)
	admitted, e := r.admitKernelPlan(w.state.binding, fp, p)
	if e != nil {
		t.Fatal(e)
	}
	if e = admitted.bindWork(w); e == nil {
		t.Fatal("unbound Work accepted")
	}
	other, _ := NewContributorRegistry([]Contributor{&registryContributor{ds[0]}, &registryContributor{ds[1]}})
	w.state.registry = other.state
	if e = admitted.bindWork(w); e == nil {
		t.Fatal("foreign Work accepted")
	}
	w.state.registry = r.state
	w.state.binding.CorrelationID = "other"
	if e = admitted.bindWork(w); e == nil {
		t.Fatal("foreign command Work accepted")
	}
	w.state.binding = admitted.binding
	w.state.sqlStarted = true
	if e = admitted.bindWork(w); e == nil {
		t.Fatal("late plan accepted")
	}
	w.state.sqlStarted = false
	if e = admitted.bindWork(w); e != nil {
		t.Fatal(e)
	}
	if e = admitted.bindWork(w); e == nil {
		t.Fatal("repeated plan accepted")
	}
	if e = (*admittedKernelPlan)(nil).bindWork(w); e == nil {
		t.Fatal("nil plan accepted")
	}
	if e = admitted.bindWork(Work{}); e == nil {
		t.Fatal("zero Work accepted")
	}
}

func TestKernelPlanRejectsInvalidAdmission(t *testing.T) {
	w, _, ap := auditFixture(t)
	domain := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	auditing := ContributorDescriptor{Owner: "audit/postgres", ContractID: "audit.records", Version: 1}
	extra := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	registry, _ := NewContributorRegistry([]Contributor{&registryContributor{domain}, &registryContributor{auditing}, &registryContributor{extra}})
	good := CommandPlan{Contributors: []ContributorDescriptor{domain, auditing}, Audits: []AuditPlan{ap}}
	fingerprint := [32]byte{1}
	good.Digest, _ = KernelPlanDigest(w.state.binding, fingerprint, good)
	cases := []CommandPlan{
		{},
		{Contributors: good.Contributors, Audits: good.Audits},
		{Contributors: []ContributorDescriptor{domain}, Audits: good.Audits, Digest: good.Digest},
		{Contributors: []ContributorDescriptor{auditing}, Audits: good.Audits, Digest: good.Digest},
		{Contributors: []ContributorDescriptor{domain, auditing, extra}, Audits: good.Audits, Digest: good.Digest},
		{Contributors: []ContributorDescriptor{domain, domain, auditing}, Audits: good.Audits, Digest: good.Digest},
		{Contributors: good.Contributors, Digest: good.Digest},
		{Contributors: good.Contributors, Audits: []AuditPlan{ap, ap}, Digest: good.Digest},
	}
	for i, p := range cases {
		if a, e := registry.admitKernelPlan(w.state.binding, fingerprint, p); e == nil || a != nil {
			t.Fatalf("invalid plan %d admitted", i)
		}
	}
	changed := w.state.binding
	changed.CorrelationID = "other"
	if _, e := registry.admitKernelPlan(changed, fingerprint, good); e == nil {
		t.Fatal("scope substitution accepted")
	}
	if _, e := registry.admitKernelPlan(w.state.binding, [32]byte{2}, good); e == nil {
		t.Fatal("fingerprint substitution accepted")
	}
	badAudit := ap
	badAudit.EventType = "identity.user.delete"
	if _, e := KernelPlanDigest(w.state.binding, fingerprint, CommandPlan{Contributors: good.Contributors, Audits: []AuditPlan{badAudit}}); e == nil {
		t.Fatal("wrong required action accepted")
	}
	if _, e := KernelPlanDigest(w.state.binding, [32]byte{}, good); e == nil {
		t.Fatal("zero fingerprint accepted")
	}
	if _, e := (*ContributorRegistry)(nil).admitKernelPlan(w.state.binding, fingerprint, good); e == nil {
		t.Fatal("nil registry accepted")
	}
}
