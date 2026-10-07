package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// OwnedLease supplies cross-adapter custody after checking the exact
// acknowledged primary lease. Only configured issuance can mint this custody;
// reading requires its separately retained verifier. Construction grants
// neither dispatch nor health; native effects still require their own fence.
func (r VelocityRecovery) OwnedLease(ctx context.Context, lease VelocityRecoveryLease) (risk.VelocityLease, error) {
	if r.state == nil || r.state.journalIssuer == (risk.VelocityJournalIssuer{}) {
		return risk.VelocityLease{}, identity.InvalidInputError{Field: "velocity_recovery"}
	}
	if err := r.CheckLease(ctx, lease); err != nil {
		return risk.VelocityLease{}, err
	}
	l := lease.state
	var namespace [32]byte
	copy(namespace[:], r.state.journal.namespace)
	owned, err := r.state.journalIssuer.Lease(risk.VelocityLeaseBinding{Tenant: l.tenant, Namespace: namespace, Epoch: l.epoch, Owner: l.token, Generation: l.generation, ExpiresAt: l.expires}, func(ctx context.Context) error { return r.CheckLease(ctx, lease) })
	if err != nil {
		return risk.VelocityLease{}, identity.UnavailableError{}
	}
	return owned, nil
}

// OwnedHistory rereads the original authenticated record and change position
// under the exact live lease. Only immutable records returned by this recovery
// owner are eligible; structural projections cannot become native authority.
// The primary transaction is closed before any native effect can begin.
// Pending/unknown are retained facts, never noncommit or permission to retry.
func (r VelocityRecovery) OwnedHistory(ctx context.Context, lease VelocityRecoveryLease, owned risk.VelocityLease, record VelocityReplayRecord) (risk.VelocityHistory, error) {
	if r.state == nil || lease.state == nil || lease.state.owner != r.state || record.state == nil || record.state.owner != r.state {
		return risk.VelocityHistory{}, identity.InvalidInputError{Field: "velocity_history"}
	}
	s, l := r.state, lease.state
	facts, custodyErr := s.journalReader.Lease(owned)
	var namespace [32]byte
	copy(namespace[:], s.journal.namespace)
	if custodyErr != nil || facts.Tenant != l.tenant || facts.Namespace != namespace || facts.Epoch != l.epoch || facts.Owner != l.token || facts.Generation != l.generation || !facts.ExpiresAt.Equal(l.expires) {
		return risk.VelocityHistory{}, identity.InvalidInputError{Field: "velocity_history"}
	}
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return risk.VelocityHistory{}, err
	}
	defer cancel()
	tx, err := s.journal.pool.Raw().BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return risk.VelocityHistory{}, identity.UnavailableError{}
	}
	defer velocityRollback(tx)
	if err := s.lock(bounded, tx, l.tenant); err != nil {
		return risk.VelocityHistory{}, err
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return risk.VelocityHistory{}, err
	}
	current, err := s.readReplayRecord(bounded, tx, l.tenant, record.state.sequence, record.state.position)
	if err != nil {
		return risk.VelocityHistory{}, err
	}
	b := current.state.projection
	// Translate the authenticated projection classification explicitly; public
	// counter results have different ordinals and no pending classification.
	var outcome risk.VelocityHistoryOutcome
	switch b.Outcome {
	case VelocityReplayPending:
		outcome = risk.VelocityHistoryPending
	case VelocityReplayCommitted:
		outcome = risk.VelocityHistoryCommitted
	case VelocityReplayNotCommitted:
		outcome = risk.VelocityHistoryNotCommitted
	case VelocityReplayUnknown:
		outcome = risk.VelocityHistoryUnknown
	default:
		return risk.VelocityHistory{}, identity.UnavailableError{}
	}
	h := risk.VelocityHistoryBinding{ID: b.ID, Position: current.state.position, Tenant: b.Tenant, Namespace: b.Namespace, Attempt: b.AttemptDigest, Fingerprint: b.Fingerprint, Operation: b.Operation, Phase: b.Phase, PolicyVersion: b.PolicyVersion, PreparedAt: b.PreparedAt, RecordedAt: b.RecordedAt, Window: b.Window, Limit: b.Limit, Outcome: outcome, Targets: b.Targets, Snapshot: b.Snapshot}
	history, err := s.journalIssuer.History(owned, h)
	if err != nil {
		return risk.VelocityHistory{}, identity.UnavailableError{}
	}
	if _, err := s.liveLease(bounded, tx, l); err != nil {
		return risk.VelocityHistory{}, err
	}
	if err := tx.Commit(bounded); err != nil {
		return risk.VelocityHistory{}, identity.UnavailableError{}
	}
	return history, nil
}
