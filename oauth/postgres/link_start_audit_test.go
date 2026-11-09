package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestRPTransactionAuditUsesCatalogActionsAndStandardRetention(t *testing.T) {
	p, now, _ := rpOutputFixture(t)
	for _, tc := range []struct {
		op            identity.FeatureOperation
		action        string
		before, after uint64
	}{
		{rpLinkStartOperation(), "identity.oauth.start_authorization", 0, 1},
		{rpDenialOperation(), "identity.oauth.handle_callback", 1, 2},
	} {
		b := p.input.binding()
		b.OperationID, b.SchemaID, b.SchemaVersion = tc.op.OperationID, tc.op.SchemaID, tc.op.SchemaVersion
		plan, err := rpTransactionAudit(context.Background(), b, tc.op, tc.before, tc.after, *now, 1)
		if err != nil || plan.EventType != tc.action || plan.RetentionClass != "standard" {
			t.Fatal("RP operation is not observable under its catalog action and retention", b.OperationID)
		}
	}
}
