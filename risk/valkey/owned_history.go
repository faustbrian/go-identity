package valkey

import (
	"context"

	"github.com/faustbrian/go-identity/risk"
)

// history uses acknowledged original journal facts. It never calls Prepare,
// recovers raw subject inputs, recalculates intent or samples a new clock.
// The original aliases must still be retained by this native configuration.
func (l commandLayout) history(ctx context.Context, reader risk.VelocityJournalVerifier, lease risk.VelocityLease, history risk.VelocityHistory) (commandPlan, []risk.Counter, error) {
	b, err := reader.History(ctx, lease, history)
	if err != nil {
		return commandPlan{}, nil, err
	}
	scope, err := reader.Lease(lease)
	if err != nil {
		return commandPlan{}, nil, err
	}
	if b.Outcome != risk.VelocityHistoryCommitted && b.Outcome != risk.VelocityHistoryNotCommitted {
		return commandPlan{}, nil, ErrUnavailable
	}
	a, err := l.policy.Admit(risk.Action(b.Operation))
	if err != nil || l.replay.Namespace() != scope.Namespace || b.Namespace != scope.Namespace || b.Tenant != scope.Tenant || b.PolicyVersion > a.PolicyVersion || risk.Phase(b.Phase) != a.Profile.Phase || b.Window != a.Profile.Window || b.Limit != a.Profile.Limit || len(b.Targets) != len(a.Profile.Dimensions) {
		return commandPlan{}, nil, risk.ErrInvalidCounterCommand
	}
	binding := risk.CounterBinding{Tenant: b.Tenant, Operation: risk.Action(b.Operation), Phase: risk.Phase(b.Phase), PolicyVersion: b.PolicyVersion, PreparedAt: b.PreparedAt, Window: b.Window, Limit: b.Limit, Fingerprint: b.Fingerprint}
	aliases := len(b.Targets[0].Keys)
	for i, target := range b.Targets {
		if risk.Dimension(target.Dimension) != a.Profile.Dimensions[i] || len(target.Keys) != aliases {
			return commandPlan{}, nil, risk.ErrInvalidCounterCommand
		}
		original := risk.CounterTarget{Dimension: risk.Dimension(target.Dimension)}
		for _, key := range target.Keys {
			retained := false
			for _, local := range l.keys {
				if local.Version() == key.Version {
					retained = true
					break
				}
			}
			if !retained {
				return commandPlan{}, nil, risk.ErrInvalidCounterCommand
			}
			original.Keys = append(original.Keys, risk.CounterKey{Version: key.Version, Encoded: key.Encoded})
		}
		binding.Targets = append(binding.Targets, original)
	}
	plan, err := l.plan(binding, scope.Epoch, b.Attempt)
	if err != nil {
		return commandPlan{}, nil, err
	}
	var snapshot []risk.Counter
	// PostgreSQL stores snapshots by dimension, not policy rank. Address each
	// original snapshot to its target without altering its count or clock facts.
	for _, target := range b.Targets {
		for _, s := range b.Snapshot {
			if s.Kind == string(target.Dimension) {
				snapshot = append(snapshot, s)
			}
		}
	}
	return plan, snapshot, nil
}
