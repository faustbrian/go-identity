package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func TestMeteredCheckRecoveryRejectsWrongProtocol(t *testing.T) {
	var c *Coordinator
	if _, err := c.RecoverOTPMeteredCheck(context.Background(), identity.RecoveryQuery{}, OTPAttemptPlan{Mode: OTPConsume}, authorization.DecisionContext{}); err == nil {
		t.Fatal("consuming protocol admitted to check recovery")
	}
	if _, err := c.RecordOTPMeteredCheck(nil, identity.CommandBinding{}, identity.Command{}, CommandPlan{}); err == nil {
		t.Fatal("nil context admitted")
	}
}
