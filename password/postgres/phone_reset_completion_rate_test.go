package passwordpostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

type phoneResetCompletionRateSource interface {
	PasswordResetCompletionRateSource(context.Context, capability.Proof, otp.SendFlow, authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error)
}

func TestPhoneResetCompletionRateSourceRequiresConfiguredCustody(t *testing.T) {
	for _, service := range []*PhonePasswordResetRequestService{nil, {}, {read: func() *phoneResetRequestService { return nil }}} {
		owner, ok := any(service).(phoneResetCompletionRateSource)
		if !ok {
			t.Fatal("native phone completion has no authenticated rate source")
		}
		ctx, stop := context.WithCancel(context.Background())
		stop()
		for _, caller := range []context.Context{nil, context.Background(), ctx} {
			user, credential, challenge, lifetime, err := owner.PasswordResetCompletionRateSource(caller, capability.Proof{}, otp.SendFlow{}, authorization.DecisionContext{})
			if err == nil || user != "" || credential != "" || challenge != "" || lifetime != 0 {
				t.Fatal("unconfigured rate source exposed original scope")
			}
		}
	}
}
