package session

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
)

// PreAuthIssueCommand freezes a server-prepared original flow with a stable
// command identity and correlation. Record is structural, not authentication.
// Server initiation owns nonce, cookie commitment, original time and resolved
// remember policy; never decode this value directly from HTTP input. The same
// complete command must be retained across retries; no raw cookie is accepted.
// Copies preserve immutable Record custody and may be read concurrently. Zero
// is invalid at execution; this scalar contract performs no IO or validation.
type PreAuthIssueCommand struct {
	CommandID     identity.CommandID
	CorrelationID string
	Record        PreAuthTransaction
}

// PreAuthIssueExecutor is the storage-neutral owned initiation/recovery seam.
// Implementations authorize configured service scope and atomically stage the
// exact original flow, required effects and receipt under the sole command
// owner. Unknown never authorizes issuance under a different command. Exact
// replay/recovery return historical metadata, no cookie or renewed flow.
// Recovery must not reserve missing commands or infer rollback from flow
// absence. Calls must be bounded, cancellation-aware and concurrency-safe.
// This seam does not create flow entropy, select policy or reveal credentials.
type PreAuthIssueExecutor interface {
	ExecutePreAuthIssue(context.Context, PreAuthIssueCommand) (identity.CommandResult, error)
	RecoverPreAuthIssue(context.Context, identity.RecoveryQuery) (identity.CommandResult, error)
}

// Format redacts flow custody and correlation for every formatting verb.
func (PreAuthIssueCommand) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreAuthIssueCommand(redacted)")
}

// MarshalJSON denies implicit original flow or command disclosure.
func (PreAuthIssueCommand) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit original flow disclosure, including map keys.
func (PreAuthIssueCommand) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
