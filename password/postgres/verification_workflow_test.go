package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

// Plan: missing/zero owners, canceled contexts, invalid sensitive input and
// incomplete/foreign recovery scope deny before native work. Real forwarding,
// signed issuance, SQL effects and proof-free history use the integration lane.
func TestVerificationWorkflowRejectsInvalidBeforeNative(t *testing.T) {
	for _, native := range []*ReauthenticationService{nil, {}} {
		if workflow, err := NewVerificationWorkflow(native); err == nil || workflow != nil {
			t.Fatal("zero native service selected")
		}
	}
	for _, workflow := range []*VerificationWorkflow{nil, {}} {
		if out, err := workflow.Verify(context.Background(), password.VerificationRequest{}); !errors.Is(err, password.ErrPasswordWork) || out != (password.VerificationResult{}) {
			t.Fatal("zero owner fabricated proof/outcome")
		}
		if out, err := workflow.Recover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) || out != (password.VerificationResult{}) {
			t.Fatal("zero owner fabricated history")
		}
	}
	w := &VerificationWorkflow{native: func() *ReauthenticationService { t.Fatal("invalid input reached native owner"); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Verify(ctx, password.VerificationRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatal("verification lost cancellation")
	}
	if _, err := w.Recover(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, context.Canceled) {
		t.Fatal("recovery lost cancellation")
	}
	if _, err := w.Verify(nil, password.VerificationRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil verification context admitted")
	}
	if _, err := w.Recover(nil, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil recovery context admitted")
	}
	if _, err := w.Verify(context.Background(), password.VerificationRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("zero input admitted")
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: "user", Kind: authorization.SubjectUser}, Tenant: "tenant", Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	q := identity.RecoveryQuery{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser, OperationID: "identity.password.verify", RecordID: "AAAAAAAAAAAAAAAAAAAAAQ"}
	for _, mutate := range []func(*identity.RecoveryQuery, *authorization.DecisionContext){
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) {
			q.CommandID = "invalid"
			q.RecordID = "invalid"
		},
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) { q.TenantID = "foreign" },
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) { q.UserID = "foreign" },
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) { q.ActorID = "foreign" },
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) {
			q.ActorKind = authorization.SubjectServiceAccount
		},
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) {
			q.OperationID = "identity.password.change"
		},
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) { q.RecordID = "other" },
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) { q.AnonymousFlowID = "foreign" },
		func(q *identity.RecoveryQuery, _ *authorization.DecisionContext) {
			q.LinkMode = identity.AccountLinkExplicit
		},
		func(_ *identity.RecoveryQuery, c *authorization.DecisionContext) { c.PolicyRevision = 0 },
		func(_ *identity.RecoveryQuery, c *authorization.DecisionContext) {
			c.Request.Subject.Kind = authorization.SubjectServiceAccount
		},
	} {
		bad, decision := q, caller.Clone()
		mutate(&bad, &decision)
		if out, err := w.Recover(context.Background(), bad, decision); !errors.Is(err, password.ErrPasswordWork) || out != (password.VerificationResult{}) {
			t.Fatal("foreign/incomplete recovery scope admitted")
		}
	}
}
