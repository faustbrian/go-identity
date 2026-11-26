package postgres

import (
	"context"
	"testing"
)

type reconciliationAuditTestOwner struct {
	AuditContributor
	marker int
}

func (*reconciliationAuditTestOwner) PersistSCIMBulkReconciliationAudit(context.Context, Work) error {
	return invalidWork()
}

func TestSCIMBulkReconciliationExposureIsInvocationBound(t *testing.T) {
	w, record, _ := auditFixture(t)
	owner := &reconciliationAuditTestOwner{marker: 1}
	other := &reconciliationAuditTestOwner{marker: 1}
	if _, err := w.StagedSCIMBulkReconciliationAudit(owner); err == nil {
		t.Fatal("ordinary Work must not expose a reconciliation event")
	}
	w.state.scimBulkReconciliation = &scimBulkReconciliationAudit{owner: owner, record: record}
	if _, err := w.StagedSCIMBulkReconciliationAudit(other); err == nil {
		t.Fatal("matching contributor types must not substitute for the exact invocation")
	}
	if got, err := w.StagedSCIMBulkReconciliationAudit(owner); err != nil || got.ID() != record.ID() {
		t.Fatal("the enlisted audit owner must see only the staged event", err)
	}
	invalidateWork(w)
	if _, err := w.StagedSCIMBulkReconciliationAudit(owner); err == nil {
		t.Fatal("the same audit owner must lose access when Work closes")
	}
}
