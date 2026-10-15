package postgres

import (
	"context"
	"fmt"
	"maps"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// CookieRevokeOneExecutor selects original-transaction CSRF enforcement for
// cookie logout. It borrows the primary pool and trusted dependencies, copies
// configuration/eligible keys, starts no goroutines and is concurrency-safe.
// Each call registers a private native participant with ephemeral token custody;
// no shared request state, context payload, durable raw token or second command
// owner exists. The existing coordinator owns reservation, mutation and effects.
// Zero is invalid. Close borrowed dependencies only after all calls finish.
type CookieRevokeOneExecutor struct {
	pool   *database.Pool
	config RevokeOneExecutorConfig
	keys   []session.CSRFKey
	base   *RevokeOneExecutor
}

type revokeCSRFInput struct {
	token session.CSRFToken
	key   session.CSRFKey
}

var _ session.RevokeOneExecutor = (*CookieRevokeOneExecutor)(nil)
var _ session.CSRFRevokeOneExecutor = (*CookieRevokeOneExecutor)(nil)

// NewCookieRevokeOneExecutor validates the same owned native composition as
// NewRevokeOneExecutor, with 1..4 eligible dedicated keys of distinct positive
// versions. It performs no IO. Install the same migrations first. Key retirement
// and overlap are explicit deployment policy; no alternate version is tried.
// Caller-owned maps, policy structs and the key slice are copied. Dependency
// implementations must remain bounded/concurrency-safe; do not mutate inputs
// during construction. The factory accepts no consumer transaction or store.
func NewCookieRevokeOneExecutor(pool *database.Pool, c RevokeOneExecutorConfig, keys []session.CSRFKey) (*CookieRevokeOneExecutor, error) {
	if len(keys) < 1 || len(keys) > 4 {
		return nil, session.ErrInvalidCSRF
	}
	for i, key := range keys {
		if key.Version() == 0 {
			return nil, session.ErrInvalidCSRF
		}
		for _, previous := range keys[:i] {
			if previous.Version() == key.Version() {
				return nil, session.ErrInvalidCSRF
			}
		}
	}
	base, err := NewRevokeOneExecutor(pool, c)
	if err != nil {
		return nil, err
	}
	c.Execution.Coordinator = copyRevokeCoordinatorConfig(c.Execution.Coordinator)
	if c.Admission != nil {
		selected := copySingleFactorAdmission(*c.Admission)
		c.Admission = &selected
	}
	if c.MFAMagicLink != nil {
		p := *c.MFAMagicLink
		c.MFAMagicLink = &p
	}
	if c.MFAPassword != nil {
		p := *c.MFAPassword
		c.MFAPassword = &p
	}
	return &CookieRevokeOneExecutor{pool: pool, config: c, keys: append([]session.CSRFKey(nil), keys...), base: base}, nil
}

func copyRevokeCoordinatorConfig(c kernel.CoordinatorConfig) kernel.CoordinatorConfig {
	c.RetainedFingerprintKeys = maps.Clone(c.RetainedFingerprintKeys)
	if c.QueryPolicy != nil {
		copy := *c.QueryPolicy
		c.QueryPolicy = &copy
	}
	if c.AdmissionPolicy != nil {
		copy := *c.AdmissionPolicy
		c.AdmissionPolicy = &copy
	}
	if c.FinalAuthentication != nil {
		copy := *c.FinalAuthentication
		c.FinalAuthentication = &copy
	}
	return c
}

// ExecuteRevokeOne rejects direct/legacy dispatch. Browser callers must use the
// explicit strict method; this never reserves, performs IO or clears cookies.
func (*CookieRevokeOneExecutor) ExecuteRevokeOne(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
	return identity.CommandResult{}, session.ErrCSRFDenied
}

// ExecuteRevokeOneWithCSRF revalidates original opaque caller custody and its
// exact state-named key before reservation. Within the original registered
// native invocation, it acquires ordered source/target mutation fences and
// checks the token against the exact active primary session/family before
// mutation. All errors abort; audit/outbox and terminal recovery use the existing
// coordinator. No token/key is persisted, revealed or refreshed. Cancellation,
// exclusive original admission expiry, panic and ambiguous outcome semantics
// match ExecuteRevokeOne on the legacy executor. Matching terminal replay is
// historical metadata, not fresh execution permission or cookie delivery.
func (e *CookieRevokeOneExecutor) ExecuteRevokeOneWithCSRF(ctx context.Context, request session.RevokeOneRequest) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.base == nil || len(e.keys) == 0 {
		return identity.CommandResult{}, session.ErrInvalidInput
	}
	// Construction performs no IO. Only this invocation owns the fresh native
	// participant, while stable descriptors retain the original durable plan.
	invocation, err := NewRevokeOneExecutor(e.pool, e.config)
	if err != nil {
		return identity.CommandResult{}, session.ErrUnavailable
	}
	return invocation.executeRevokeOne(ctx, request, e.keys)
}

func selectRevokeCSRFKey(record session.Session, token session.CSRFToken, keys []session.CSRFKey) (session.CSRFKey, error) {
	state, err := record.CSRFState().Bindings()
	if err != nil {
		return session.CSRFKey{}, session.ErrCSRFDenied
	}
	for _, key := range keys {
		if key.Version() == state.KeyVersion {
			if record.CSRFState().Check(state.Binding, token, key) != nil {
				return session.CSRFKey{}, session.ErrCSRFDenied
			}
			return key, nil
		}
	}
	return session.CSRFKey{}, session.ErrCSRFDenied
}

// RecoverRevokeOneCommand observes the original receipt under current trusted
// access policy, without token custody or execution permission. It uses the same
// retained descriptor/command profile after restart; it never reserves/revokes.
func (e *CookieRevokeOneExecutor) RecoverRevokeOneCommand(ctx context.Context, query identity.RecoveryQuery, caller authorization.DecisionContext) (kernel.CommandRecord, error) {
	if e == nil || e.base == nil {
		return kernel.CommandRecord{}, session.ErrInvalidInput
	}
	return e.base.RecoverRevokeOneCommand(ctx, query, caller)
}

// Format prevents traversal of trusted dependencies and secret configuration.
func (CookieRevokeOneExecutor) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.CookieRevokeOneExecutor(redacted)"))
}

// MarshalJSON rejects implicit runtime/secret export.
func (CookieRevokeOneExecutor) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit runtime/secret text export.
func (CookieRevokeOneExecutor) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
