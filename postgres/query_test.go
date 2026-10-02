package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type queryDecision func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f queryDecision) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, dc)
}

func TestQueryCommandDoesNotExposeReplayPayload(t *testing.T) {
	b := codecBinding()
	b.OperationID, b.ActorID = "identity.profile.update", identity.ActorID(b.UserID)
	q, dc := queryInputs(b)
	private := "synthetic-private-profile"
	r := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, ExpectedVersion: 1, AuditEventID: "audit", User: identity.User{ID: b.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 2}, Profile: &identity.UserProfile{ID: b.UserID, TenantID: b.TenantID, Version: 2, Name: private}}
	body, err := encodeJournalResult(claimRequest{safeFields: cborMap(commandScope(b))}, r)
	if err != nil {
		t.Fatal(err)
	}
	state, class, version := "committed", "committed", int32(1)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c, _, _ := coordinatorFixture(t)
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		return commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), state: &state, until: &now, now: now, plan: []byte{1}, resultVersion: &version, class: &class, result: body}, nil
	}
	got, err := c.QueryCommand(context.Background(), q, dc)
	if err != nil || got != (CommandRecord{Binding: b, Outcome: identity.CommitOutcomeCommitted}) || got.Validate() != nil {
		t.Fatal("safe observation lost historical metadata")
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), private) || strings.Contains(fmt.Sprintf("%#v", got), private) {
		t.Fatal("public query exposed private replay data")
	}
}

func queryInputs(b identity.CommandBinding) (identity.RecoveryQuery, authorization.DecisionContext) {
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	dc := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind},
		Tenant:  authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID),
		Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)},
	}}
	return q, dc
}

func callerForQuery(caller authorization.DecisionContext, q identity.RecoveryQuery) authorization.DecisionContext {
	caller = caller.Clone()
	caller.Request.Subject.ID, caller.Request.Subject.Kind = authorization.SubjectID(q.ActorID), q.ActorKind
	caller.Request.Tenant = authorization.TenantID(q.TenantID)
	caller.Request.Action = authorization.Action(q.OperationID)
	caller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	return caller
}

func TestQueryCommandConstantWorkAndScope(t *testing.T) {
	for _, state := range []string{"pending", "committed", "aborted"} {
		b := codecBinding()
		q, dc := queryInputs(b)
		until := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
		version := int32(1)
		class := "committed"
		result := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeNotCommitted}
		if state == "committed" {
			result.Outcome = identity.CommitOutcomeCommitted
			result.User = identity.User{ID: b.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}
			result.AuditEventID = "audit-id"
		} else if state == "aborted" {
			class = "denied"
		}
		body, err := encodeJournalResult(claimRequest{safeFields: cborMap(commandScope(b))}, result)
		if err != nil {
			t.Fatal(err)
		}
		stored := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), state: &state, until: &until, now: until.Add(time.Second), plan: []byte{1}}
		if state != "pending" {
			stored.resultVersion, stored.class, stored.result = &version, &class, body
		}
		c, _, _ := coordinatorFixture(t)
		var reads, decisions int
		allow := true
		missing := false
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(ctx context.Context, got authorization.DecisionContext) (authorization.Decision, error) {
			decisions++
			if _, ok := ctx.Deadline(); !ok || got.Request.Environment.Time.IsZero() || got.PolicyRevision != 9 {
				t.Fatal("unbounded/current-policy query")
			}
			outcome := authorization.Deny
			if allow {
				outcome = authorization.Allow
			}
			return authorization.Decision{Outcome: outcome, Revision: 9}, nil
		})}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
			reads++
			if missing {
				return commandObservation{}, pgx.ErrNoRows
			}
			return stored, nil
		}
		got, err := c.QueryCommand(context.Background(), q, dc)
		if got.Binding != b || got.Validate() != nil || state == "pending" && got.Outcome != identity.CommitOutcomeInProgress || state != "pending" && got != (CommandRecord{Binding: b, Outcome: result.Outcome}) {
			t.Fatal("historical result lost", state, err)
		}
		for _, change := range []func(*identity.RecoveryQuery){
			func(q *identity.RecoveryQuery) { q.TenantID = "other" },
			func(q *identity.RecoveryQuery) { q.UserID = "other" },
			func(q *identity.RecoveryQuery) { q.ActorID = "other" },
			func(q *identity.RecoveryQuery) { q.ActorKind = authorization.SubjectAPIKey },
			func(q *identity.RecoveryQuery) { q.OperationID = "identity.user.suspend" },
			func(q *identity.RecoveryQuery) { q.RecordID = "other" },
			func(q *identity.RecoveryQuery) { q.LinkMode = identity.AccountLinkExplicit },
		} {
			other := q
			change(&other)
			beforeReads, beforeDecisions := reads, decisions
			got, err := c.QueryCommand(context.Background(), other, callerForQuery(dc, other))
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || got.Outcome != identity.CommitOutcomeInvalid || reads != beforeReads+1 || decisions != beforeDecisions+1 {
				t.Fatal("scope changed result/work shape")
			}
		}
		for _, absent := range []bool{false, true} {
			allow, missing = false, absent
			beforeReads, beforeDecisions := reads, decisions
			got, err := c.QueryCommand(context.Background(), q, dc)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || got != (CommandRecord{}) || reads != beforeReads+1 || decisions != beforeDecisions+1 {
				t.Fatal("absence/denial enumeration")
			}
		}
	}
}

func TestQueryCommandFailsClosedOnCorruptHistoryAndPolicy(t *testing.T) {
	b := codecBinding()
	q, dc := queryInputs(b)
	state := "pending"
	until := time.Now().UTC().Truncate(time.Microsecond)
	good := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), state: &state, until: &until, now: until, plan: []byte{1}}
	for _, mutate := range []func(*commandObservation){
		func(o *commandObservation) { o.state = nil },
		func(o *commandObservation) { o.until = nil },
		func(o *commandObservation) { o.plan = nil },
		func(o *commandObservation) { o.scope = []byte{0} },
		func(o *commandObservation) { o.now = time.Time{} },
		func(o *commandObservation) { o.result = []byte{0} },
		func(o *commandObservation) { v := int32(99); o.resultVersion = &v },
		func(o *commandObservation) { s := "other"; o.state = &s },
	} {
		observed := good
		mutate(&observed)
		c, _, _ := coordinatorFixture(t)
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
		got, err := c.QueryCommand(context.Background(), q, dc)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || got != (CommandRecord{}) {
			t.Fatal("corrupt history produced an outcome")
		}
	}
	for _, decision := range []queryDecision{
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 8}, nil
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{}, nil
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{}, errors.New("private-policy-diagnostic")
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			panic("private-policy-diagnostic")
		},
	} {
		c, _, _ := coordinatorFixture(t)
		reads := 0
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: decision}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { reads++; return good, nil }
		got, err := c.QueryCommand(context.Background(), q, dc)
		if err == nil || got != (CommandRecord{}) || reads != 1 {
			t.Fatal("invalid/stale/failing policy disclosed result or bypassed read")
		}
	}
}

func TestQueryCommandOwnsRecordPolicyScope(t *testing.T) {
	for _, operation := range []string{"identity.account.unlink", "identity.account.link-token", "identity.identifier.attach", "identity.identifier.remove"} {
		b := codecBinding()
		b.OperationID, b.RecordID = operation, "record-original"
		if operation == "identity.account.link-token" {
			b.LinkMode = identity.AccountLinkAdministrative
		}
		q, dc := queryInputs(b)
		dc.Request.Resource.Attributes = authorization.Attributes{"identity.command.record-id": authorization.StringValue("forged-record"), "identity.command.link-mode": authorization.StringValue("forged-mode")}
		c, _, _ := coordinatorFixture(t)
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(_ context.Context, got authorization.DecisionContext) (authorization.Decision, error) {
			for key, expected := range map[authorization.AttributeName]string{"identity.command.id": string(b.CommandID), "identity.command.record-id": b.RecordID, "identity.command.link-mode": strconv.FormatUint(uint64(b.LinkMode), 10)} {
				value, ok := got.Request.Resource.Attributes[key].String()
				if !ok || value != expected {
					t.Fatal("caller replaced immutable query-policy scope")
				}
			}
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		state := "pending"
		now := time.Now().UTC().Truncate(time.Microsecond)
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
			return commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: cborMap(commandScope(b)), state: &state, until: &now, now: now, plan: []byte{1}}, nil
		}
		got, err := c.QueryCommand(context.Background(), q, dc)
		if err != nil || got.Binding != b || got.Validate() != nil {
			t.Fatal("record scope not preserved", err)
		}
		original, _ := dc.Request.Resource.Attributes["identity.command.record-id"].String()
		if original != "forged-record" {
			t.Fatal("caller-owned maps mutated")
		}
	}
}

func TestCommandRecordAndQueryPolicyAdmission(t *testing.T) {
	for _, policy := range []CommandQueryPolicy{{}, {Clock: clock.System{}, PolicyVersion: 9}, {Authorization: queryDecision(nil), Clock: clock.System{}, PolicyVersion: 9}} {
		if validCommandQueryPolicy(policy) {
			t.Fatal("nil or typed-nil query dependency admitted")
		}
	}
	for _, record := range []CommandRecord{{}, {Binding: codecBinding(), Outcome: identity.CommitOutcomeUnknown}, {Binding: codecBinding(), Outcome: identity.CommitOutcomeCommitted, RetryAfter: time.Second}, {Binding: codecBinding(), Outcome: identity.CommitOutcomeInProgress}, {Binding: codecBinding(), Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Minute + time.Nanosecond}} {
		if record.Validate() == nil {
			t.Fatal("invalid public command observation admitted")
		}
	}
	policy := CommandQueryPolicy{PolicyVersion: 9}
	if encoded, err := json.Marshal(policy); err == nil || len(encoded) != 0 || fmt.Sprintf("%#v", policy) != "postgres.CommandQueryPolicy(redacted)" {
		t.Fatal("runtime query composition exposed")
	}
}
