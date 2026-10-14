package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

func auditFixture(t *testing.T) (Work, audit.Record, AuditPlan) {
	t.Helper()
	binding := codecBinding()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: binding}}
	b, err := audit.NewBuilder(audit.BuilderConfig{Limits: securityAuditLimits(), IDGenerator: randomProfileAuditID})
	if err != nil {
		t.Fatal(err)
	}
	record, err := b.Build(audit.RecordInput{
		OccurredAt: time.Now().UTC(), Action: binding.OperationID, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor:      audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)},
		Subject:    audit.SubjectInput{Type: "user", ID: string(binding.UserID)},
		Context:    audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID},
		Policy:     audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"},
		Changes:    audit.ChangeSetInput{NoChange: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(binding.CommandID), "retention.class": "standard", "aggregate.type": "user", "aggregate.id": string(binding.UserID), "aggregate.before_version": "0", "aggregate.after_version": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
	if err != nil {
		t.Fatal(err)
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := AuditBindingDigest(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	plan := AuditPlan{EventType: binding.OperationID, SchemaVersion: 1, EventIndex: 0, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}
	return w, record, plan
}

func changedAudit(t *testing.T, original audit.Record, change func(*audit.RecordInput), id string, redact bool) audit.Record {
	t.Helper()
	input := audit.RecordInput{OccurredAt: original.OccurredAt(), Action: original.Action(), Outcome: original.Outcome(), ReasonCode: original.ReasonCode(), Actor: audit.ActorInput{Kind: original.Actor().Kind(), ID: original.Actor().ID()}, Subject: audit.SubjectInput{Type: original.Subject().Type(), ID: original.Subject().ID()}, Context: audit.ContextInput{TenantID: original.Context().TenantID(), CorrelationID: original.Context().CorrelationID()}, Changes: audit.ChangeSetInput{NoChange: true}, Policy: original.Policy(), Attributes: original.Attributes()}
	change(&input)
	config := audit.BuilderConfig{IDGenerator: randomProfileAuditID}
	if id != "" {
		config.IDGenerator = func() (string, error) { return id, nil }
	}
	b, err := audit.NewBuilder(config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Build(input)
	if err != nil {
		t.Fatal("record mutation fixture rejected", err)
	}
	if redact {
		keys := make([]string, 0, len(input.Attributes))
		for key := range input.Attributes {
			keys = append(keys, key)
		}
		rules, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: keys})
		if err != nil {
			t.Fatal(err)
		}
		r, err = rules.Redact(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func randomProfileAuditID() (string, error) {
	id, err := identity.NewSubjectID()
	return string(id), err
}

func TestWorkAuditCannotSubstituteRequiredAction(t *testing.T) {
	w, _, plan := auditFixture(t)
	plan.EventType = "identity.user.delete"
	if bindAuditPlans(w, []AuditPlan{plan}) == nil {
		t.Fatal("create command admitted delete audit")
	}
}

func TestWorkAuditImplementedCommandActionMappings(t *testing.T) {
	for _, partition := range []struct{ operation, action, kind string }{
		{"identity.account.link-token", "identity.account.link", "account"},
		{"identity.identifier.attach", "identity.identifier.add", "identifier"},
		{"identity.identifier.replace", "identity.identifier.change", "identifier"},
		{"identity.identifier.make-primary", "identity.identifier.change", "identifier"},
		{"identity.identifier.verify", "identity.identifier.verify", "identifier"},
		{"identity.identifier.remove", "identity.identifier.remove", "identifier"},
		{"identity.account.unlink", "identity.account.unlink", "account"},
		{"identity.user.update-admin", "identity.user.update", "user"},
		{"identity.profile.update", "identity.user.update", "user"},
		{"identity.admin.user-ban", "identity.user.suspend", "user"},
		{"identity.admin.user-unban", "identity.user.restore", "user"},
		{"identity.user.suspend", "identity.user.suspend", "user"},
		{"identity.user.restore", "identity.user.restore", "user"},
	} {
		t.Run(partition.operation, func(t *testing.T) {
			w, r, p := auditFixture(t)
			w.state.binding.OperationID = partition.operation
			target := string(w.state.binding.UserID)
			if partition.kind != "user" {
				w.state.binding.RecordID = "record-a"
				target = "record-a"
			}
			if partition.operation == "identity.account.link-token" {
				w.state.binding.LinkMode = identity.AccountLinkExplicit
			}
			r = changedAudit(t, r, func(i *audit.RecordInput) {
				i.Action = partition.action
				i.Subject.Type = partition.kind
				i.Subject.ID = target
				i.Attributes["aggregate.type"] = partition.kind
				i.Attributes["aggregate.id"] = target
				i.Attributes["retention.class"] = "protected"
			}, "", true)
			digest, err := AuditBindingDigest(w.state.binding, r)
			if err != nil {
				t.Fatal("supported core binding rejected", err)
			}
			p.EventType, p.BindingDigest = partition.action, digest
			if err := bindAuditPlans(w, []AuditPlan{p}); err != nil {
				t.Fatal("implemented command audit rejected", err)
			}
			if err := w.StageAudit(0, r); err != nil {
				t.Fatal("implemented command cannot stage", err)
			}
			if completeAudits(w) != nil || w.state.audits.records[0].Action() != partition.action {
				t.Fatal("canonical action missing or changed")
			}
		})
	}
}

func TestWorkAuditAdministrativeLinkRequiresProtectedRetention(t *testing.T) {
	for _, protected := range []bool{false, true} {
		name := "standard denied"
		if protected {
			name = "protected admitted"
		}
		t.Run(name, func(t *testing.T) {
			w, r, p := auditFixture(t)
			w.state.binding.OperationID = "identity.account.link-token"
			w.state.binding.RecordID = "account-a"
			w.state.binding.LinkMode = identity.AccountLinkAdministrative
			r = changedAudit(t, r, func(i *audit.RecordInput) {
				i.Action = "identity.account.link"
				i.Subject.Type = "account"
				i.Subject.ID = "account-a"
				i.Attributes["aggregate.type"] = "account"
				i.Attributes["aggregate.id"] = "account-a"
				i.Attributes["retention.class"] = "protected"
			}, "", true)
			digest, err := AuditBindingDigest(w.state.binding, r)
			if err != nil {
				t.Fatal("protected link fixture", err)
			}
			p.EventType, p.BindingDigest = "identity.account.link", digest
			if err := bindAuditPlans(w, []AuditPlan{p}); err != nil {
				t.Fatal(err)
			}
			if !protected {
				r = changedAudit(t, r, func(i *audit.RecordInput) { i.Attributes["retention.class"] = "standard" }, "", true)
			}
			err = w.StageAudit(0, r)
			if protected {
				if err != nil || completeAudits(w) != nil {
					t.Fatal("protected administrative link rejected")
				}
			} else if err == nil || w.state.failed == nil {
				t.Fatal("administrative link retained as standard")
			}
		})
	}
}

func TestWorkAuditPlansRequireExactKernelEvent(t *testing.T) {
	for name, change := range map[string]func(AuditPlan) []AuditPlan{
		"missing":         func(AuditPlan) []AuditPlan { return nil },
		"repeated event":  func(p AuditPlan) []AuditPlan { q := p; q.EventIndex++; return []AuditPlan{p, q} },
		"schema":          func(p AuditPlan) []AuditPlan { p.SchemaVersion = 2; return []AuditPlan{p} },
		"digest":          func(p AuditPlan) []AuditPlan { p.BindingDigest = [32]byte{}; return []AuditPlan{p} },
		"retention":       func(p AuditPlan) []AuditPlan { p.RetentionPolicyVersion = 0; return []AuditPlan{p} },
		"record count":    func(p AuditPlan) []AuditPlan { p.RequiredRecordCount = 2; return []AuditPlan{p} },
		"optional":        func(p AuditPlan) []AuditPlan { p.Required = false; return []AuditPlan{p} },
		"record bound":    func(p AuditPlan) []AuditPlan { p.MaxRecordBytes = 16385; return []AuditPlan{p} },
		"aggregate bound": func(p AuditPlan) []AuditPlan { p.MaxAggregateBytes = 16385; return []AuditPlan{p} },
	} {
		t.Run(name, func(t *testing.T) {
			w, _, p := auditFixture(t)
			if bindAuditPlans(w, change(p)) == nil {
				t.Fatal("invalid audit plan admitted")
			}
		})
	}
}

func TestWorkAuditRejectsInvalidRecordPartitions(t *testing.T) {
	for name, mutate := range map[string]func(*audit.RecordInput){
		"missing aggregate":              func(i *audit.RecordInput) { delete(i.Attributes, "aggregate.id") },
		"wrong aggregate":                func(i *audit.RecordInput) { i.Attributes["aggregate.id"] = "foreign-user" },
		"unknown attribute":              func(i *audit.RecordInput) { i.Attributes["foreign.field"] = "synthetic-private" },
		"wrong command":                  func(i *audit.RecordInput) { i.Attributes["command.id"] = "AAAAAAAAAAAAAAAAAAAACA" },
		"wrong tenant":                   func(i *audit.RecordInput) { i.Context.TenantID = "tenant-b" },
		"wrong actor":                    func(i *audit.RecordInput) { i.Actor.ID = "actor-b" },
		"wrong policy":                   func(i *audit.RecordInput) { i.Policy.Version = "2" },
		"wrong target":                   func(i *audit.RecordInput) { i.Subject.ID = "foreign-user" },
		"wrong correlation":              func(i *audit.RecordInput) { i.Context.CorrelationID = "foreign" },
		"unknown reason":                 func(i *audit.RecordInput) { i.ReasonCode = "foreign_reason" },
		"unknown outcome reason":         func(i *audit.RecordInput) { i.Outcome = audit.OutcomeUnknown },
		"free description":               func(i *audit.RecordInput) { i.Description = "synthetic-private" },
		"denial with success reason":     func(i *audit.RecordInput) { i.Outcome = audit.OutcomeDenied },
		"failure with success reason":    func(i *audit.RecordInput) { i.Outcome = audit.OutcomeFailed },
		"denial with operational reason": func(i *audit.RecordInput) { i.Outcome = audit.OutcomeDenied; i.ReasonCode = "provider_unavailable" },
		"failure with policy reason":     func(i *audit.RecordInput) { i.Outcome = audit.OutcomeFailed; i.ReasonCode = "not_authorized" },
		"raw request ID":                 func(i *audit.RecordInput) { i.Context.RequestID = "synthetic@example.invalid" },
		"raw producer":                   func(i *audit.RecordInput) { i.Context.SourceService = "synthetic private producer" },
	} {
		t.Run(name, func(t *testing.T) {
			w, r, p := auditFixture(t)
			if bindAuditPlans(w, []AuditPlan{p}) != nil {
				t.Fatal("plan fixture")
			}
			r = changedAudit(t, r, mutate, "", true)
			if w.StageAudit(0, r) == nil || w.state.failed == nil {
				t.Fatal("invalid record accepted or Work not poisoned")
			}
		})
	}
	t.Run("nonrandom ID", func(t *testing.T) {
		w, r, p := auditFixture(t)
		if bindAuditPlans(w, []AuditPlan{p}) != nil {
			t.Fatal("plan fixture")
		}
		r = changedAudit(t, r, func(*audit.RecordInput) {}, "fixed", true)
		if w.StageAudit(0, r) == nil {
			t.Fatal("nonrandom ID staged")
		}
	})
	t.Run("no redaction policy", func(t *testing.T) {
		w, r, p := auditFixture(t)
		if bindAuditPlans(w, []AuditPlan{p}) != nil {
			t.Fatal("plan fixture")
		}
		r = changedAudit(t, r, func(*audit.RecordInput) {}, "", false)
		if w.StageAudit(0, r) == nil {
			t.Fatal("unprocessed audit staged")
		}
	})
}

func TestWorkAuditStagingIsDeclaredOwnedAndComplete(t *testing.T) {
	w, record, plan := auditFixture(t)
	plans := []AuditPlan{plan}
	if err := bindAuditPlans(w, plans); err != nil {
		t.Fatal(err)
	}
	plans[0].EventType = "changed"
	if err := completeAudits(w); err == nil {
		t.Fatal("missing required audit accepted")
	}
	if err := w.StageAudit(0, record); err != nil {
		t.Fatal(err)
	}
	if err := completeAudits(w); err != nil {
		t.Fatal(err)
	}
	if w.state.audits.records[0].ID() != record.ID() {
		t.Fatal("builder ID replaced")
	}
	if err := w.StageAudit(0, record); err == nil {
		t.Fatal("duplicate staging accepted")
	}
	if w.state.failed == nil {
		t.Fatal("invalid staging did not poison Work")
	}
}

func TestWorkAuditUndeclaredZeroAndClosedDeny(t *testing.T) {
	w, record, _ := auditFixture(t)
	if err := (Work{}).StageAudit(0, record); err == nil {
		t.Fatal("zero staged")
	}
	if err := w.StageAudit(0, record); err == nil {
		t.Fatal("undeclared staged")
	}
	w, record, plan := auditFixture(t)
	if err := bindAuditPlans(w, []AuditPlan{plan}); err != nil {
		t.Fatal(err)
	}
	invalidateWork(w)
	if err := w.StageAudit(0, record); err == nil {
		t.Fatal("closed staged")
	}
}

func TestWorkAuditBudgetsLifetimeAndSnapshots(t *testing.T) {
	t.Run("record budget", func(t *testing.T) {
		w, r, p := auditFixture(t)
		p.MaxRecordBytes = 1
		p.MaxAggregateBytes = 1
		if bindAuditPlans(w, []AuditPlan{p}) != nil {
			t.Fatal("budget fixture")
		}
		if w.StageAudit(0, r) == nil || w.state.failed == nil {
			t.Fatal("record budget bypassed")
		}
	})
	t.Run("undeclared index", func(t *testing.T) {
		w, r, p := auditFixture(t)
		if bindAuditPlans(w, []AuditPlan{p}) != nil {
			t.Fatal("index fixture")
		}
		if w.StageAudit(1, r) == nil {
			t.Fatal("undeclared index staged")
		}
	})
	t.Run("cannot rebind", func(t *testing.T) {
		w, _, p := auditFixture(t)
		if bindAuditPlans(w, []AuditPlan{p}) != nil || bindAuditPlans(w, []AuditPlan{p}) == nil {
			t.Fatal("audit plan rebound")
		}
	})
	t.Run("cancelled staging", func(t *testing.T) {
		w, r, p := auditFixture(t)
		if bindAuditPlans(w, []AuditPlan{p}) != nil {
			t.Fatal("cancel fixture")
		}
		w.state.cancel()
		var cancelled identity.CancelledError
		if !errors.As(w.StageAudit(0, r), &cancelled) || completeAudits(w) == nil {
			t.Fatal("cancelled Work staged or completed audit")
		}
	})
	t.Run("owned record", func(t *testing.T) {
		w, r, p := auditFixture(t)
		if bindAuditPlans(w, []AuditPlan{p}) != nil || w.StageAudit(0, r) != nil {
			t.Fatal("owned fixture")
		}
		attrs := r.Attributes()
		attrs["command.id"] = "changed"
		if w.state.audits.records[0].Attributes()["command.id"] != string(w.state.binding.CommandID) {
			t.Fatal("record accessor mutated staged event")
		}
	})
	for _, partition := range []struct {
		outcome audit.Outcome
		reason  string
	}{{audit.OutcomeDenied, "not_authorized"}, {audit.OutcomeFailed, "provider_unavailable"}, {audit.OutcomeUnknown, "commit_unknown"}} {
		t.Run(partition.reason, func(t *testing.T) {
			w, r, p := auditFixture(t)
			if bindAuditPlans(w, []AuditPlan{p}) != nil {
				t.Fatal("outcome fixture")
			}
			r = changedAudit(t, r, func(i *audit.RecordInput) { i.Outcome = partition.outcome; i.ReasonCode = partition.reason }, "", true)
			if w.StageAudit(0, r) != nil || completeAudits(w) != nil {
				t.Fatal("valid outcome rejected")
			}
			if w.state.audits.records[0].Outcome() != partition.outcome || w.state.audits.records[0].ReasonCode() != partition.reason {
				t.Fatal("outcome rewritten")
			}
		})
	}
}
