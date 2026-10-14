package postgres

import (
	"context"
	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"strconv"
	"testing"
	"time"
)

type planLifecycleContributor struct{ registryContributor }

func (*planLifecycleContributor) PersistLifecycle(context.Context, Work) error { return nil }

func lifecycleFixture(t *testing.T) (Work, LifecyclePlan) {
	t.Helper()
	w, r, ap := auditFixture(t)
	if err := bindAuditPlans(w, []AuditPlan{ap}); err != nil {
		t.Fatal(err)
	}
	if err := w.StageAudit(ap.EventIndex, r); err != nil {
		t.Fatal(err)
	}
	p := LifecyclePlan{EventType: "identity.created.v1", EventIndex: 0, BeforeVersion: 0, AfterVersion: 1}
	return w, p
}

func TestLifecycleSnapshotRejectsConflictingAudit(t *testing.T) {
	for _, version := range []string{"2", "18446744073709551615"} {
		w, p := lifecycleFixture(t)
		if err := bindLifecyclePlan(w, &p); err != nil {
			t.Fatal(err)
		}
		if err := w.StageLifecycle(0, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
			t.Fatal(err)
		}
		r := w.state.audits.records[0]
		w.state.audits.records[0] = changedAudit(t, r, func(in *audit.RecordInput) { in.Attributes["aggregate.after_version"] = version }, "", true)
		if records, err := w.StagedLifecycle(); err == nil || records != nil {
			t.Fatal("audit and lifecycle disagree on authoritative version")
		}
	}
}

func TestLifecycleImplementedOperationMappings(t *testing.T) {
	for _, partition := range []struct {
		operation, event, kind string
		before                 uint64
	}{
		{"identity.user.create", "identity.created.v1", "user", 0},
		{"identity.user.update-admin", "identity.updated.v1", "user", 1},
		{"identity.profile.update", "identity.updated.v1", "user", 1},
		{"identity.user.suspend", "identity.suspended.v1", "user", 1},
		{"identity.user.restore", "identity.restored.v1", "user", 1},
		{"identity.admin.user-ban", "identity.suspended.v1", "user", 1},
		{"identity.admin.user-unban", "identity.restored.v1", "user", 1},
		{"identity.account.link-token", "social_provider.linked.v1", "account", 0},
		{"identity.account.link-token", "social_provider.linked.v1", "account", 4},
		{"identity.account.unlink", "social_provider.unlinked.v1", "account", 1},
		{"identity.identifier.attach", "identifier.added.v1", "identifier", 0},
		{"identity.identifier.replace", "identifier.changed.v1", "identifier", 1},
		{"identity.identifier.make-primary", "identifier.changed.v1", "identifier", 1},
		{"identity.identifier.verify", "identifier.verified.v1", "identifier", 1},
		{"identity.identifier.remove", "identifier.removed.v1", "identifier", 1},
	} {
		t.Run(partition.operation, func(t *testing.T) {
			w, r, ap := auditFixture(t)
			b := &w.state.binding
			b.OperationID = partition.operation
			target := string(b.UserID)
			if partition.kind != "user" {
				b.RecordID = "record-a"
				target = b.RecordID
			}
			if partition.operation == "identity.account.link-token" {
				b.LinkMode = identity.AccountLinkExplicit
			}
			r = changedAudit(t, r, func(in *audit.RecordInput) {
				in.Action = kernelCommandAudit(b.OperationID)
				in.Subject.Type = partition.kind
				in.Subject.ID = target
				in.Attributes["aggregate.type"] = partition.kind
				in.Attributes["aggregate.id"] = target
				in.Attributes["retention.class"] = "protected"
				in.Attributes["aggregate.before_version"] = strconv.FormatUint(partition.before, 10)
				in.Attributes["aggregate.after_version"] = strconv.FormatUint(partition.before+1, 10)
			}, "", true)
			ap.EventType = r.Action()
			ap.BindingDigest, _ = AuditBindingDigest(*b, r)
			if err := bindAuditPlans(w, []AuditPlan{ap}); err != nil {
				t.Fatal(err)
			}
			if err := w.StageAudit(0, r); err != nil {
				t.Fatal(err)
			}
			p := LifecyclePlan{EventType: partition.event, BeforeVersion: partition.before, AfterVersion: partition.before + 1}
			if err := bindLifecyclePlan(w, &p); err != nil {
				t.Fatal("supported lifecycle rejected", err)
			}
			if err := w.StageLifecycle(0, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
				t.Fatal(err)
			}
			records, err := w.StagedLifecycle()
			if err != nil || records[0].SubjectType != partition.kind || records[0].SubjectID != target || records[0].EventType != partition.event {
				t.Fatal("target or event changed", err)
			}
		})
	}
}

func TestLifecycleStagingConservesCommandIdentity(t *testing.T) {
	w, p := lifecycleFixture(t)
	if err := bindLifecyclePlan(w, &p); err != nil {
		t.Fatal(err)
	}
	if records, err := w.StagedLifecycle(); err == nil || records != nil {
		t.Fatal("missing event exposed")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := w.StageLifecycle(p.EventIndex, now); err != nil {
		t.Fatal(err)
	}
	records, err := w.StagedLifecycle()
	if err != nil || len(records) != 1 {
		t.Fatal("event missing", err)
	}
	r := records[0]
	if r.TenantID != w.state.binding.TenantID || r.CommandID != w.state.binding.CommandID || r.UserID != w.state.binding.UserID || r.SubjectID != string(w.state.binding.UserID) || r.SubjectType != "user" || r.EventType != p.EventType || r.BeforeVersion != 0 || r.AfterVersion != 1 || r.OccurredAt != now || r.ID == "" {
		t.Fatal("scope or versions changed")
	}
	other, _ := lifecycleFixture(t)
	if err := bindLifecyclePlan(other, &p); err != nil {
		t.Fatal(err)
	}
	if err := other.StageLifecycle(p.EventIndex, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	again, _ := other.StagedLifecycle()
	if r.ID != again[0].ID {
		t.Fatal("retry time changed deterministic identity")
	}
	records[0].EventType = "private-input"
	again, _ = w.StagedLifecycle()
	if again[0].EventType != p.EventType {
		t.Fatal("snapshot aliases staging")
	}
	p.EventType = "private-input"
	if again[0].EventType == p.EventType {
		t.Fatal("plan aliases staging")
	}
	if w.StageLifecycle(0, now) == nil {
		t.Fatal("duplicate event accepted")
	}
	if _, err := w.StagedLifecycle(); err == nil {
		t.Fatal("poisoned Work exposed event")
	}
}

func TestLifecycleInvalidInputsFailClosed(t *testing.T) {
	for _, change := range []func(*LifecyclePlan){
		func(p *LifecyclePlan) { p.EventType = "unknown" },
		func(p *LifecyclePlan) { p.EventType = "identity.deleted.v1" },
		func(p *LifecyclePlan) { p.AfterVersion = 0 },
		func(p *LifecyclePlan) { p.BeforeVersion = 1; p.AfterVersion = 2 },
	} {
		w, p := lifecycleFixture(t)
		change(&p)
		if bindLifecyclePlan(w, &p) == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
	for _, timestamp := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Now().UTC().Truncate(time.Microsecond).Add(time.Nanosecond)} {
		w, p := lifecycleFixture(t)
		if err := bindLifecyclePlan(w, &p); err != nil {
			t.Fatal(err)
		}
		if w.StageLifecycle(0, timestamp) == nil {
			t.Fatal("invalid event time accepted")
		}
	}
	w, p := lifecycleFixture(t)
	if bindLifecyclePlan(w, &p) != nil {
		t.Fatal("bind failed")
	}
	if w.StageLifecycle(1, time.Now().UTC().Truncate(time.Microsecond)) == nil {
		t.Fatal("undeclared index accepted")
	}
	w, p = lifecycleFixture(t)
	w.state.sqlStarted = true
	if bindLifecyclePlan(w, &p) == nil {
		t.Fatal("late declaration accepted")
	}
	w, p = lifecycleFixture(t)
	if bindLifecyclePlan(w, &p) != nil || bindLifecyclePlan(w, &p) == nil {
		t.Fatal("repeated declaration accepted")
	}
	invalidateWork(w)
	if w.StageLifecycle(0, time.Now()) == nil {
		t.Fatal("closed Work accepted")
	}
	if (Work{}).StageLifecycle(0, time.Now()) == nil {
		t.Fatal("zero Work accepted")
	}
}

func TestKernelLifecyclePlanBindsPhaseAndDigest(t *testing.T) {
	w, record, ap := auditFixture(t)
	lp := LifecyclePlan{EventType: "identity.created.v1", BeforeVersion: 0, AfterVersion: 1}
	domain := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	auditing := ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
	lifecycle := ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
	p := CommandPlan{Contributors: []ContributorDescriptor{domain, auditing, lifecycle}, Audits: []AuditPlan{ap}, Lifecycle: &lp}
	p.Digest, _ = KernelPlanDigest(w.state.binding, [32]byte{1}, p)
	registry, _ := NewContributorRegistry([]Contributor{&registryContributor{domain}, &planAuditContributor{registryContributor{auditing}}, &planLifecycleContributor{registryContributor{lifecycle}}})
	admitted, err := registry.admitKernelPlan(w.state.binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	w.state.registry = registry.state
	lp.EventIndex++
	if err = admitted.bindWork(w); err != nil {
		t.Fatal(err)
	}
	if err = w.StageAudit(ap.EventIndex, record); err != nil {
		t.Fatal(err)
	}
	if err = w.StageLifecycle(0, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		t.Fatal("plan alias changed event index", err)
	}
	changed, err := KernelPlanDigest(w.state.binding, [32]byte{1}, p)
	if err != nil || changed == p.Digest {
		t.Fatal("lifecycle declaration not in digest")
	}
	p.Lifecycle.EventIndex = 0
	bad, _ := NewContributorRegistry([]Contributor{&registryContributor{domain}, &planAuditContributor{registryContributor{auditing}}, &registryContributor{lifecycle}})
	if _, err = bad.admitKernelPlan(w.state.binding, [32]byte{1}, p); err == nil {
		t.Fatal("descriptor-only outbox phase accepted")
	}
}
