package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

// Plan: a missing cookie profile never selects bearer work. Denied intrinsic
// input/cancellation cannot enter native work; real forwarding uses native SQL.
func TestCookieChangeWorkflowRejectsMissingComposition(t *testing.T) {
	for _, native := range []*CookieKeyedPasswordChangeService{nil, {}} {
		if workflow, err := NewCookieChangeWorkflow(native); err == nil || workflow != nil {
			t.Fatal("missing native cookie profile selected")
		}
	}
	for _, workflow := range []*CookieChangeWorkflow{nil, {}} {
		if out, err := workflow.Change(context.Background(), password.CookieChangeRequest{}); !errors.Is(err, password.ErrPasswordWork) || out != (password.ChangeResult{}) {
			t.Fatal("missing cookie owner fabricated outcome")
		}
		if out, err := workflow.Recover(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) || out != (password.ChangeResult{}) {
			t.Fatal("missing cookie owner fabricated recovery")
		}
	}
	workflow := &CookieChangeWorkflow{native: func() *CookieKeyedPasswordChangeService {
		t.Fatal("denied input reached native cookie work")
		return nil
	}}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if out, err := workflow.Change(ctx, password.CookieChangeRequest{}); !errors.Is(err, context.Canceled) || out != (password.ChangeResult{}) {
		t.Fatal("cookie cancellation lost")
	}
	if out, err := workflow.Recover(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, context.Canceled) || out != (password.ChangeResult{}) {
		t.Fatal("cookie recovery cancellation lost")
	}
	if _, err := workflow.Change(nil, password.CookieChangeRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil cookie context admitted")
	}
	if _, err := workflow.Recover(nil, identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("nil cookie recovery context admitted")
	}
	if _, err := workflow.Change(context.Background(), password.CookieChangeRequest{}); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("keyless cookie request admitted")
	}
}
