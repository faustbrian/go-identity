package postgres

import (
	"fmt"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"time"
)

// SetRevocationServiceConfig selects one owned primary/execution profile and
// whole-call all-or-nothing bound. Validation.Clock must be nil: Execution.Clock
// owns authentication and execution. Earlier admission/freshness always wins.
// Dependencies are immutable and borrowed until calls finish. Zero is invalid.
type SetRevocationServiceConfig struct {
	Execution       IssueExecutorConfig
	Validation      session.ServiceConfig
	MaximumSessions uint32
	MaximumDuration time.Duration
}

// NewSetRevocationService composes core credential-based revoke-other/all with
// the primary reader and native transaction owner without IO or consumer glue.
// Apply required kernel, authority, session, bulk-revocation, audit and outbox
// migrations first. The pool is borrowed. Final-signin issuance is not required;
// unsupported authority profiles fail closed rather than dropping dimensions.
func NewSetRevocationService(pool *database.Pool, c SetRevocationServiceConfig) (*session.SetRevocationService, error) {
	if c.Validation.Clock != nil {
		return nil, session.ErrInvalidInput
	}
	c.Validation.Clock = c.Execution.Clock
	reader, err := NewSessionService(pool, SessionServiceConfig{Repository: c.Execution.Repository, Profile: IdentifierAdmissionConfig(c.Execution.Profile), Validation: c.Validation})
	if err != nil {
		return nil, err
	}
	executor, err := NewRevokeSetExecutor(pool, RevokeSetExecutorConfig{Execution: c.Execution, Sessions: reader})
	if err != nil {
		return nil, err
	}
	return session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: c.Execution.PolicyID, PolicyVersion: c.Execution.PolicyVersion, MaximumSessions: c.MaximumSessions, MaximumDuration: c.MaximumDuration})
}

// Format redacts authority, policy and key configuration.
func (SetRevocationServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SetRevocationServiceConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (SetRevocationServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
