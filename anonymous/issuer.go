package anonymous

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Issuer is the owned anonymous workflow port, not an application domain store.
// Signin must admit current action-specific risk and original pre-auth cookie,
// atomically create the kernel/lifecycle/session plus required audit/outbox, and
// deliver only a newly acknowledged original session. Matching keyed retries
// retain the original outcome without new entropy, risk work or bearer reveal.
// Changed intent conflicts. Recovery checks original cookie possession and
// current disclosure authority, never executes or reissues. Unknown is not
// rollback. Calls honor bounded contexts and support independent concurrent
// requests; inputs and caller collections remain immutable during each call.
type Issuer interface {
	Signin(context.Context, SigninRequest) (SigninResult, error)
	RecoverSignin(context.Context, SigninRecoveryRequest) (SigninResult, error)
}

// SigninResult distinguishes durable outcome from fresh delivery. Only a new
// committed, error-free Signin may contain Session.Token/CSRFToken or cookie
// metadata. Replays/recovery retain outcome/correlation only, not current guest
// authentication. Error/cancellation/unknown must withhold all credentials.
// RetryAfter is positive only for an in-progress original command. Inspect the
// error and Outcome separately; recovery correlation grants no disclosure.
type SigninResult struct {
	Outcome    identity.CommitOutcome
	Session    session.IssueResult
	CSRFToken  session.CSRFToken
	Recovery   SigninRecovery
	Replayed   bool
	RetryAfter time.Duration
}

func (SigninResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymous.SigninResult(redacted)"))
}
func (SigninResult) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (SigninResult) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (SigninResult) LogValue() slog.Value {
	return slog.StringValue("anonymous.SigninResult(redacted)")
}
