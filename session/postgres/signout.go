package postgres

import (
	"fmt"
	"time"

	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// SignOutServiceConfig selects owned primary authentication and transactional
// revocation. Execution owns the sole schema, authority profile, trusted clock,
// policy and audit/outbox composition. Validation.Clock must be nil: the factory
// supplies Execution.Clock to both authentication and execution, preventing
// contradictory time sources. Validation retains its key, audience, storage,
// read-budget and uncertainty rules. MaximumDuration bounds the whole logout
// call to 1ms..30s; earlier caller and authority deadlines always win. Zero is
// invalid. Configuration and dependencies must not be mutated during calls.
type SignOutServiceConfig struct {
	Execution       IssueExecutorConfig
	Validation      session.ServiceConfig
	Cookie          session.CookiePolicy
	MaximumDuration time.Duration
}

// Format redacts key, policy and authority configuration.
func (SignOutServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SignOutServiceConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (SignOutServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewSignOutService composes the owned primary reader and native one-session
// executor with core self-signout, without IO or application-written stores.
// Install kernel, authorization, session, revocation, audit and outbox migrations
// first. The borrowed PRIMARY pool and dependencies must outlive calls; close
// them only after operations finish. No goroutines or additional transaction,
// command journal, clock or policy owner are created. Ordinary logout does not
// require final-signin proof composition. Historical unknown-outcome recovery
// remains RecoverRevokeOneCommand on the same owned native executor profile.
func NewSignOutService(pool *database.Pool, c SignOutServiceConfig) (*session.SignOutService, error) {
	if c.Validation.Clock != nil {
		return nil, session.ErrInvalidInput
	}
	c.Validation.Clock = c.Execution.Clock
	reader, err := NewSessionService(pool, SessionServiceConfig{
		Repository: c.Execution.Repository,
		Profile:    IdentifierAdmissionConfig(c.Execution.Profile),
		Validation: c.Validation,
	})
	if err != nil {
		return nil, err
	}
	executor, err := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: c.Execution, Sessions: reader})
	if err != nil {
		return nil, err
	}
	return session.NewSignOutService(reader, executor, session.SignOutConfig{
		Cookie: c.Cookie, PolicyID: c.Execution.PolicyID,
		PolicyVersion: c.Execution.PolicyVersion, MaximumDuration: c.MaximumDuration,
	})
}

var _ session.RevokeOneExecutor = (*RevokeOneExecutor)(nil)
