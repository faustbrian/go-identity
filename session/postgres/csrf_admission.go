package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RequireCSRF checks a synchronizer token against the exact command-frozen
// session and fences that complete record and active family on the original
// primary transaction. A structural token match alone never grants admission.
// The named dedicated key must be selected by trusted policy; no alternate
// key version is tried. Missing state, wrong tokens and stale state deny as
// redacted Forbidden. Invalid configuration/session inputs are InvalidInput;
// storage failures and cancellation follow RequireSession's classifications.
//
// This is a trusted participant helper, not a standalone authorization API.
// The owner MUST pass its original bounded transaction, abort or poison it on
// every error, retain the locks through protected work, and check all other
// applicable authorities and temporal validity before commit. It must acquire
// any session write fence before calling this helper, not upgrade shared locks
// afterwards. A replica, cache or autocommit pool cannot satisfy this contract.
// HTTP channel/origin policy and pre-auth one-use flows remain separate owners.
// Success does not renew freshness, consume a token, or issue any credential.
func RequireCSRF[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, expected session.Session, token session.CSRFToken, key session.CSRFKey) error {
	if ctx == nil || nilSessionHandle(q) || !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return identity.InvalidInputError{Field: "session_csrf"}
	}
	spec, err := expected.Bindings()
	if err != nil {
		return identity.InvalidInputError{Field: "session_csrf"}
	}
	if ctx.Err() != nil {
		return readError(ctx, ctx.Err())
	}
	state := expected.CSRFState()
	if state.Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, token, key) != nil {
		return identity.ForbiddenError{}
	}
	return RequireSession(ctx, q, c, expected)
}
