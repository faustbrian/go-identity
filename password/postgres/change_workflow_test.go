package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

func TestChangeWorkflowRejectsMissingAndCanceledComposition(t *testing.T) {
	for _, native := range []*KeyedPasswordChangeService{nil, {}} {
		if workflow, err := NewChangeWorkflow(native); err == nil || workflow != nil {
			t.Fatal("zero native owner selected portable workflow")
		}
	}
	for _, workflow := range []*ChangeWorkflow{nil, {}} {
		out, err := workflow.Change(context.Background(), password.ChangeRequest{})
		if !errors.Is(err, password.ErrPasswordWork) || out != (password.ChangeResult{}) {
			t.Fatal("zero facade fabricated password outcome")
		}
		out, err = workflow.Recover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{})
		if !errors.Is(err, password.ErrPasswordWork) || out != (password.ChangeResult{}) {
			t.Fatal("zero facade fabricated recovery outcome")
		}
	}
	// This private accessor must never be reached on absent/canceled/invalid
	// input. Real forwarding is covered through the public native SQL integration.
	workflow := &ChangeWorkflow{native: func() *KeyedPasswordChangeService { t.Fatal("denied input reached native work"); return nil }}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if out, err := workflow.Change(ctx, password.ChangeRequest{}); !errors.Is(err, context.Canceled) || out != (password.ChangeResult{}) {
		t.Fatal("caller cancellation lost")
	}
	if out, err := workflow.Recover(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, context.Canceled) || out != (password.ChangeResult{}) {
		t.Fatal("recovery cancellation lost")
	}
	if _, err := workflow.Change(nil, password.ChangeRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil context admitted")
	}
	if _, err := workflow.Recover(nil, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil recovery context admitted")
	}
	if _, err := workflow.Change(context.Background(), password.ChangeRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("keyless zero input admitted")
	}
}
