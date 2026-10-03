package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type admissionClock struct{}

func (admissionClock) Now() time.Time { return time.Time{} }

func TestCommandAdmissionDistinguishesAuthorizedAbsenceOnly(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	query, caller := queryInputs(codecBinding())
	allow := true
	reads, decisions := 0, 0
	policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(ctx context.Context, got authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		admission, _ := got.Request.Resource.Attributes["identity.command.read-admission"].Bool()
		recovery, _ := got.Request.Resource.Attributes["identity.command.recovery"].Bool()
		if _, bounded := ctx.Deadline(); !bounded || !admission || recovery {
			t.Fatal("admission lacks bounded distinct owned policy context")
		}
		outcome := authorization.Deny
		if allow {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	})}
	c.admissionPolicy = &policy
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		reads++
		return commandObservation{}, pgx.ErrNoRows
	}
	caller.Request.Resource.Attributes = authorization.Attributes{
		"identity.command.read-admission": authorization.BoolValue(false),
		"identity.command.recovery":       authorization.BoolValue(true),
	}
	got, err := c.ObserveCommandAdmission(context.Background(), query, caller)
	if err != nil || !got.Absent || got.Record != (CommandRecord{}) || got.Validate() != nil || reads != 1 || decisions != 1 {
		t.Fatal("authorized true absence unavailable", got, err)
	}
	for _, mismatch := range []bool{false, true} {
		allow = mismatch
		bad := caller.Clone()
		if mismatch {
			bad.Request.Subject.ID = "other-actor"
		}
		beforeReads, beforeDecisions := reads, decisions
		got, err = c.ObserveCommandAdmission(context.Background(), query, bad)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got != (CommandAdmission{}) || reads != beforeReads+1 || decisions != beforeDecisions+1 {
			t.Fatal("denied/mismatched absence disclosed or changed work shape", err)
		}
	}
	// Admission opt-in must not implicitly enable ordinary receipt lookup.
	if got, err := c.QueryCommand(context.Background(), query, caller); err == nil || got != (CommandRecord{}) {
		t.Fatal("admission enabled QueryCommand")
	}
	c.admissionPolicy = nil
	if got, err := c.ObserveCommandAdmission(context.Background(), query, caller); err == nil || got != (CommandAdmission{}) {
		t.Fatal("disabled admission disclosed absence")
	}
}

func TestCommandAdmissionRejectsLateAndFailedAbsence(t *testing.T) {
	for _, mode := range []string{"read error", "cancelled read", "cancelled policy", "policy error"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := coordinatorFixture(t)
			query, caller := queryInputs(codecBinding())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.admissionPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				if mode == "cancelled policy" {
					cancel()
				}
				if mode == "policy error" {
					return authorization.Decision{}, errors.New("private")
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
				if mode == "cancelled read" {
					cancel()
				}
				if mode == "read error" {
					return commandObservation{}, errors.New("private")
				}
				return commandObservation{}, pgx.ErrNoRows
			}
			got, err := c.ObserveCommandAdmission(ctx, query, caller)
			if err == nil || got != (CommandAdmission{}) {
				t.Fatal("failed/late observation became absence")
			}
		})
	}
}

func TestCommandAdmissionValueRejectsInvalidShapes(t *testing.T) {
	for _, value := range []CommandAdmission{
		{},
		{Absent: true, Record: CommandRecord{Binding: codecBinding()}},
		{Record: CommandRecord{Binding: codecBinding(), Outcome: identity.CommitOutcomeUnknown}},
		{Absent: true, Record: CommandRecord{RetryAfter: time.Second}},
	} {
		if value.Validate() == nil {
			t.Fatal("invalid admission shape accepted")
		}
	}
}

func admissionHistory(t *testing.T, state, class string) (*Coordinator, identity.RecoveryQuery, authorization.DecisionContext, commandObservation) {
	t.Helper()
	c, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := claimFingerprint([32]byte{1}, claim.canonical)
	wire, err := encodeFeaturePlan(spec.Binding, fingerprint, plan)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(-time.Second)
	observed := commandObservation{tenant: string(spec.Binding.TenantID), purpose: spec.Binding.OperationID, scope: claim.safeFields, state: &state, until: &until, now: now, plan: wire, fingerprint: bytes.Clone(fingerprint[:])}
	if state != "pending" {
		receipt := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: spec.Operation}}
		if state == "committed" {
			receipt.Outcome, receipt.AuditEventID, receipt.Feature.AfterVersion = identity.CommitOutcomeCommitted, "audit", 1
		}
		observed.result, err = encodeJournalResult(claim, receipt)
		if err != nil {
			t.Fatal(err)
		}
		version := int32(1)
		observed.resultVersion, observed.class = &version, &class
	}
	q, caller := queryInputs(spec.Binding)
	c.admissionPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
	return c, q, caller, observed
}

func TestCommandAdmissionPreservesHistoricalOutcomes(t *testing.T) {
	for _, class := range []string{"pending", "committed", "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		t.Run(class, func(t *testing.T) {
			state := "aborted"
			if class == "pending" || class == "committed" {
				state = class
			}
			c, q, caller, stored := admissionHistory(t, state, class)
			original, wantErr := commandReceipt(q, stored, nil)
			got, err := c.ObserveCommandAdmission(context.Background(), q, caller)
			if got.Absent || got.Validate() != nil || got.Record.Binding != original.Binding || got.Record.Outcome != original.Outcome || got.Record.RetryAfter != original.RetryAfter || got.Record.Feature == nil {
				t.Fatal("safe historical outcome lost", got, err)
			}
			if (err == nil) != (wantErr == nil) || err != nil && err.Error() != wantErr.Error() {
				t.Fatal("terminal classification lost", err, wantErr)
			}
			operation := *got.Record.Feature
			got.Record.Feature.SchemaVersion++
			again, _ := c.ObserveCommandAdmission(context.Background(), q, caller)
			if again.Record.Feature == nil || *again.Record.Feature != operation {
				t.Fatal("caller changed observed history")
			}
		})
	}
}

func TestCommandAdmissionNeverTreatsExistingClaimAsAbsent(t *testing.T) {
	for _, mode := range []string{"retired", "wrong tenant", "wrong actor", "missing journal", "corrupt plan", "corrupt scope", "corrupt fingerprint", "corrupt receipt"} {
		t.Run(mode, func(t *testing.T) {
			c, q, caller, stored := admissionHistory(t, "committed", "committed")
			switch mode {
			case "retired":
				stored.retired = true
			case "wrong tenant":
				stored.tenant = "other"
			case "wrong actor":
				q.ActorID = "other"
				caller = callerForQuery(caller, q)
			case "missing journal":
				stored.state = nil
			case "corrupt plan":
				stored.plan = []byte{1}
			case "corrupt scope":
				stored.scope = []byte{1}
			case "corrupt fingerprint":
				stored.fingerprint = nil
			case "corrupt receipt":
				stored.result = []byte{1}
			}
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return stored, nil }
			got, err := c.ObserveCommandAdmission(context.Background(), q, caller)
			if err == nil || got != (CommandAdmission{}) {
				t.Fatal("existing bad claim disclosed absence or history", err)
			}
		})
	}
}

func TestCommandAdmissionCurrentCallerAndPolicyFences(t *testing.T) {
	changes := map[string]func(*authorization.DecisionContext){
		"actor":         func(c *authorization.DecisionContext) { c.Request.Subject.ID = "other" },
		"kind":          func(c *authorization.DecisionContext) { c.Request.Subject.Kind = authorization.SubjectAPIKey },
		"tenant":        func(c *authorization.DecisionContext) { c.Request.Tenant = "other" },
		"action":        func(c *authorization.DecisionContext) { c.Request.Action = "other.action" },
		"resource type": func(c *authorization.DecisionContext) { c.Request.Resource.Type = "other" },
		"resource id":   func(c *authorization.DecisionContext) { c.Request.Resource.ID = "other" },
		"policy":        func(c *authorization.DecisionContext) { c.PolicyRevision++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, q, caller, _ := admissionHistory(t, "pending", "pending")
			change(&caller)
			got, err := c.ObserveCommandAdmission(context.Background(), q, caller)
			var forbidden identity.ForbiddenError
			if !errors.As(err, &forbidden) || got != (CommandAdmission{}) {
				t.Fatal("caller mismatch disclosed admission", err)
			}
		})
	}
	for _, mode := range []string{"stale decision", "zero clock", "panic"} {
		t.Run(mode, func(t *testing.T) {
			c, q, caller, _ := admissionHistory(t, "pending", "pending")
			c.admissionPolicy.Authorization = queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				if mode == "panic" {
					panic("private")
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 8}, nil
			})
			if mode == "zero clock" {
				c.admissionPolicy.Clock = admissionClock{}
			}
			got, err := c.ObserveCommandAdmission(context.Background(), q, caller)
			if err == nil || got != (CommandAdmission{}) {
				t.Fatal("invalid policy disclosed admission", err)
			}
		})
	}
}

func TestCommandAdmissionInvalidRequestsNeverRead(t *testing.T) {
	c, q, caller, _ := admissionHistory(t, "pending", "pending")
	c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
		t.Fatal("invalid request read primary")
		return commandObservation{}, nil
	}
	for _, change := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.CommandID = "bad" },
		func(q *identity.RecoveryQuery) { q.TenantID = "" },
		func(q *identity.RecoveryQuery) { q.UserID = "" },
		func(q *identity.RecoveryQuery) { q.ActorID = "" },
		func(q *identity.RecoveryQuery) { q.ActorKind = "" },
		func(q *identity.RecoveryQuery) { q.OperationID = "bad action" },
		func(q *identity.RecoveryQuery) { q.RecordID = "bad record" },
	} {
		bad := q
		change(&bad)
		if got, err := c.ObserveCommandAdmission(context.Background(), bad, caller); err == nil || got != (CommandAdmission{}) {
			t.Fatal("invalid request admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := c.ObserveCommandAdmission(ctx, q, caller); !errors.Is(err, context.Canceled) || got != (CommandAdmission{}) {
		t.Fatal("cancelled request admitted")
	}
	if got, err := c.ObserveCommandAdmission(nil, q, caller); err == nil || got != (CommandAdmission{}) {
		t.Fatal("nil context admitted")
	}
	var zero *Coordinator
	if got, err := zero.ObserveCommandAdmission(context.Background(), q, caller); err == nil || got != (CommandAdmission{}) {
		t.Fatal("nil coordinator admitted")
	}
}
