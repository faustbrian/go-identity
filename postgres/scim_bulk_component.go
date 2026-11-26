package postgres

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

const maximumSCIMBulkComponentMembers = 1000 // SCIM native Bulk cardinality ceiling.

// SCIMBulkComponentMember pairs an original Group-create reservation with the
// exact opaque command used to reserve it. The native owner may supply only
// members of the same retained component, in execution order.
type SCIMBulkComponentMember struct {
	Reservation Reservation
	Command     identity.Command
}

// SCIMBulkGroupComponentFailureContributor retains a complete Group component's
// dependency failures after the shared mutations have been rolled back. The
// exact original owner is called once for each member. The last call receives
// the complete member count and settles the parent counter and cutoff. Other
// calls receive zero and must not change the parent. Work cannot be retained.
type SCIMBulkGroupComponentFailureContributor interface {
	SCIMBulkChildFailureContributor
	RecordSCIMBulkGroupComponentFailure(context.Context, Work, int) error
}

// Format prevents diagnostics from expanding the original command or lease.
func (SCIMBulkComponentMember) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SCIMBulkComponentMember(redacted)"))
}

// MarshalJSON rejects serialization of this execution-only pair.
func (SCIMBulkComponentMember) MarshalJSON() ([]byte, error) {
	return nil, invalidWork()
}

// ExecuteSCIMBulkGroupCreateComponent is a trusted native SCIM composition
// seam. Each member owns its original journal, Work, audit and lifecycle, but
// every member shares one primary transaction. The native owner must verify
// the exact retained component and its dependencies under Work. Results are
// returned in input order only after the entire transaction commits. A
// precommit failure rolls back every staged effect. A Work-bound Group denial
// can commit all original failure receipts instead, after proven rollback. A
// failed commit response leaves the component for checkpoint recovery.
func ExecuteSCIMBulkGroupCreateComponent(ctx context.Context, members []SCIMBulkComponentMember) (results []identity.CommandResult, err error) {
	if ctx == nil {
		return nil, invalidWork()
	}
	root, binding, maximum, order, err := admitSCIMBulkGroupCreateComponent(members)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, maximum)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return nil, readFailure(bounded, err)
	}
	for _, i := range order {
		if !members[i].Reservation.state.started.CompareAndSwap(false, true) {
			return nil, identity.ConflictError{}
		}
	}
	tx, err := root.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, readFailure(bounded, err)
	}
	works := make([]Work, len(members))
	commitStarted := false
	defer func() {
		for _, w := range works {
			if w.state != nil {
				invalidateWork(w)
			}
		}
		if !commitStarted {
			cleanup, stop := context.WithTimeout(context.Background(), maximum)
			defer stop()
			if tx.Rollback(cleanup) != nil {
				results, err = nil, identity.UnknownCommitError{CommandID: binding.CommandID}
			}
		}
	}()
	deadline, _ := bounded.Deadline()
	// All member claim/journal locks are acquired before the ordinary tenant
	// exclusion, matching single-command acquisition order. Stable command
	// order avoids opposite lock order between attempts for the same members.
	for _, i := range order {
		r := members[i].Reservation.state
		w, err := r.coordinator.openDomainWork(bounded, tx, r, func() {})
		if err != nil {
			return nil, err
		}
		w.state.execution.component = true
		works[i] = w
		if end, _ := w.state.ctx.Deadline(); end.Before(deadline) {
			deadline = end
		}
	}
	execution, stop := context.WithDeadline(bounded, deadline)
	defer stop()
	if err := configureKernelWork(execution, works[0]); err != nil {
		return nil, err
	}
	// A single savepoint covers every provisional member effect. On a known
	// denial it discards them before terminalization, while the original root
	// claim/journal and tenant locks remain held. Only root Commit is durable.
	domain, err := tx.Begin(execution)
	if err != nil {
		return nil, readFailure(execution, err)
	}
	for _, w := range works {
		w.state.tx = domain
	}
	staged := make([]identity.CommandResult, len(members))
	var denied bool
	for i, w := range works {
		staged[i], err = w.state.execution.coordinator.ApplyFeature(execution, w, members[i].Command)
		if err != nil {
			code := w.state.featureFailure
			if code != FeatureFailureInvalidGroupMember && code != FeatureFailureConflict {
				return nil, err
			}
			denied = true
			break
		}
	}
	if denied {
		if err := domain.Rollback(execution); err != nil {
			return nil, identity.UnavailableError{}
		}
		for _, w := range works {
			invalidateWork(w)
		}
		for i, member := range members {
			r := member.Reservation.state
			w, err := r.coordinator.openDomainWork(execution, tx, r, func() {})
			if err != nil {
				return nil, err
			}
			w.state.execution.component = true
			works[i] = w
			count := 0
			if i == len(members)-1 {
				count = len(members)
			}
			staged[i], err = r.coordinator.stageSCIMBulkGroupComponentFailure(w, count)
			if err != nil {
				return nil, err
			}
		}
	} else {
		for i, w := range works {
			if err := w.state.execution.coordinator.stageDomainCommit(w, staged[i]); err != nil {
				return nil, err
			}
		}
		if err := domain.Commit(execution); err != nil {
			return nil, readFailure(execution, err)
		}
	}
	for _, w := range works {
		invalidateWork(w)
	}
	if err := execution.Err(); err != nil {
		return nil, readFailure(execution, err)
	}
	commitStarted = true
	if err := tx.Commit(execution); err != nil {
		return nil, identity.UnknownCommitError{CommandID: binding.CommandID}
	}
	return staged, nil
}

func (c *Coordinator) stageSCIMBulkGroupComponentFailure(w Work, count int) (result identity.CommandResult, err error) {
	if !c.owns(w) || !w.state.execution.component || count < 0 || count > maximumSCIMBulkComponentMembers {
		return result, invalidWork()
	}
	r := w.state.execution.reservation
	now, err := w.DatabaseTime(w.state.ctx)
	if err != nil {
		return result, err
	}
	records, err := featureMutationAudits(w.state.ctx, r.plan, now, "conflict")
	if err != nil || len(records) != 1 {
		return result, invalidAudit()
	}
	if err := w.StageAudit(r.plan.audits[0].EventIndex, records[0]); err != nil {
		return result, err
	}
	if err := c.persistAuditPhase(w); err != nil {
		return result, identity.UnavailableError{}
	}
	entry, err := c.registry.selectFeatureOperation(*r.plan.feature)
	if err != nil {
		return result, err
	}
	owner, ok := entry.contributor.(SCIMBulkGroupComponentFailureContributor)
	if !ok || w.state.featureInvocation != nil {
		return result, invalidWork()
	}
	err = func() (failure error) {
		w.state.featureInvocation = owner
		w.state.scimBulkSkip = &scimBulkSkipPhase{plan: r.plan}
		defer func() {
			w.state.featureInvocation = nil
			w.state.scimBulkSkip = nil
			if recover() != nil {
				failure = identity.UnavailableError{}
			}
		}()
		return owner.RecordSCIMBulkGroupComponentFailure(w.state.ctx, w, count)
	}()
	if err != nil || w.state.rows != nil || w.usable() != nil {
		return result, identity.UnavailableError{}
	}
	result = featureOutcome(w.state.binding, r.request.feature, identity.CommitOutcomeNotCommitted, 0)
	// Native 424 checkpoints carry component semantics. The original kernel
	// receipts retain their usual no-effect class and reveal no member cause.
	if err := terminalizeJournal(w.state.ctx, w.state.tx, r.request, r.journal, r.owner, result, "conflict"); err != nil {
		return identity.CommandResult{}, err
	}
	return result, nil
}

func admitSCIMBulkGroupCreateComponent(members []SCIMBulkComponentMember) (*Coordinator, identity.CommandBinding, time.Duration, []int, error) {
	if len(members) == 0 || len(members) > maximumSCIMBulkComponentMembers {
		return nil, identity.CommandBinding{}, 0, nil, invalidWork()
	}
	var root *Coordinator
	var binding identity.CommandBinding
	var maximum time.Duration
	order := make([]int, len(members))
	commands := make(map[identity.CommandID]struct{}, len(members))
	targets := make(map[string]struct{}, len(members))
	for i, member := range members {
		r := member.Reservation.state
		if !scimBulkGroupCreateReservation(r, member.Command) {
			return nil, identity.CommandBinding{}, 0, nil, invalidWork()
		}
		b := r.plan.binding
		if i == 0 {
			root, binding, maximum = r.coordinator, b, r.coordinator.maximumDuration
		} else if r.coordinator.pool.Raw() != root.pool.Raw() ||
			b.TenantID != binding.TenantID || b.ActorID != binding.ActorID ||
			b.CorrelationID != binding.CorrelationID ||
			b.PolicyID != binding.PolicyID || b.PolicyVersion != binding.PolicyVersion {
			return nil, identity.CommandBinding{}, 0, nil, invalidWork()
		}
		if _, exists := commands[b.CommandID]; exists {
			return nil, identity.CommandBinding{}, 0, nil, invalidWork()
		}
		if _, exists := targets[b.RecordID]; exists {
			return nil, identity.CommandBinding{}, 0, nil, invalidWork()
		}
		commands[b.CommandID], targets[b.RecordID] = struct{}{}, struct{}{}
		maximum = min(maximum, r.coordinator.maximumDuration)
		order[i] = i
	}
	slices.SortFunc(order, func(i, j int) int {
		return strings.Compare(string(members[i].Reservation.state.request.commandID), string(members[j].Reservation.state.request.commandID))
	})
	return root, binding, maximum, order, nil
}

func scimBulkGroupCreateReservation(r *reservationState, command identity.Command) bool {
	if r == nil || r.coordinator == nil || r.coordinator.pool == nil || r.coordinator.pool.Raw() == nil ||
		r.plan == nil || r.plan.belongsTo(r.coordinator.registry) != nil || r.authentication != nil || r.executionRequest != nil || r.preparation != nil {
		return false
	}
	p := r.plan
	if p.feature == nil || p.feature.Operation.OperationID != "identity.scim.group-create" ||
		featureFailureSubject(p.feature.Operation) != "scim_group" || p.feature.Contributor != scimUserCreationDescriptor() ||
		p.binding.ActorKind != authorization.SubjectServiceAccount || p.binding.RecordID == "" ||
		p.lifecycle == nil || p.lifecycle.BeforeVersion != 0 || p.lifecycle.AfterVersion != 1 ||
		p.scimBulkDenial != 0 || len(p.audits) != 1 || p.audits[0].EventType != scimBulkApplyChildAudit || p.audits[0].RetentionClass != "protected" {
		return false
	}
	parent, err := identity.ParseCommandID(p.binding.CorrelationID)
	if err != nil || parent == p.binding.CommandID {
		return false
	}
	entry, err := r.coordinator.registry.selectFeatureOperation(*p.feature)
	if err != nil {
		return false
	}
	if _, ok := entry.contributor.(SCIMBulkGroupComponentFailureContributor); !ok {
		return false
	}
	q, err := prepareClaim(command, r.coordinator.keys.retained[r.coordinator.keys.current])
	return err == nil && q.commandID == r.request.commandID && bytes.Equal(q.canonical, r.request.canonical)
}
