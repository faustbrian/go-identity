package postgres

import (
	"context"
	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// AuditContributor is the open, versioned durable audit phase implemented by
// audit/postgres. Only the sole Coordinator invokes PersistAudits, after every
// required event is staged, through the same generation-bound Work as the
// protected mutation. Implementations must write canonical records and their
// command/index binding atomically, treating exact replay as idempotent and
// changed bytes or event-ID reuse as integrity failure. They must not retain
// Work, close/begin transactions, perform network I/O or invoke caller hooks.
// A nil error means staging succeeded, not that the Coordinator committed.
type AuditContributor interface {
	Contributor
	PersistAudits(context.Context, Work) error
}

// StagedAudit is an owned declaration/immutable record pair selected before
// SQL and admitted by Work.StageAudit. This is not a persistence receipt.
type StagedAudit struct {
	Plan   AuditPlan
	Record audit.Record
	// Feature and SubjectType are the owned frozen native scope needed by
	// audit/postgres to recompute FeatureAuditBindingDigest. Both are zero for
	// kernel commands; this projection is not current authority or a receipt.
	Feature     identity.FeatureOperation
	SubjectType string
}

// StagedAudits returns an owned snapshot only after every declared index has
// passed staging. Changing the returned slice/plan cannot change Work. Record
// accessors retain audit's immutable-by-contract ownership. Zero, incomplete,
// poisoned, closed or expired Work returns no records and a redacted error.
// Only the declared audit contributor uses this snapshot for same-transaction
// persistence; this method performs no I/O or callbacks and conveys no closure
// or durable authority. Work's serial-use and bounded lifetime apply.
func (w Work) StagedAudits() ([]StagedAudit, error) {
	if err := completeAudits(w); err != nil {
		return nil, err
	}
	a := w.state.audits
	result := make([]StagedAudit, len(a.plans))
	for i, p := range a.plans {
		result[i] = StagedAudit{Plan: p, Record: a.records[i]}
		if w.state.feature != nil {
			result[i].Feature = w.state.feature.Operation
			result[i].SubjectType = w.state.subjectType
		}
	}
	return result, nil
}
