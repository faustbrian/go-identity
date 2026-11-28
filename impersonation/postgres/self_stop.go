package impersonationpostgres

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// NewServiceWithSelfStop opts into an exact child-bound stop operation and
// separately issued stop synchronizer. Install SelfStopMigrationSource first.
func NewServiceWithSelfStop(pool *database.Pool, c Config, active ActivationConfig) (*Service, error) {
	s, err := NewServiceWithRevocation(pool, c, active)
	if err != nil {
		return nil, err
	}
	if err := c.Risk.ValidateCounterOnlyOperation(risk.Action(stopAction)); err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	s.selfStop = true
	return s, nil
}

// StopAuthentication combines the original derived bearer and its separate
// synchronizer. Ordinary sessions and ordinary CSRF cannot substitute.
type StopAuthentication struct {
	Tenant identity.TenantID
	Bearer string
	CSRF   session.CSRFToken
}

func (StopAuthentication) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("impersonation.StopAuthentication(redacted)"))
}

func (StopAuthentication) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (StopAuthentication) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type StopInput struct {
	Authentication StopAuthentication
	CommandID      identity.CommandID
	Network        string
}

// PreparedStop is an exact, service-owned command, not reusable authentication.
type PreparedStop struct{ command PreparedCommand }

func (p PreparedStop) Binding() (identity.CommandBinding, error) { return p.command.Binding() }
func (PreparedStop) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("impersonation.PreparedStop(redacted)"))
}
func (PreparedStop) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// StopResult never carries a bearer. Parent is populated only when the caller
// supplied the still-valid exact original actor's ordinary session credential.
// A zero Parent does not undo a committed stop.
type StopResult struct {
	Receipt identity.CommandResult
	Parent  session.GetResult
}

type stopIntent struct {
	row   activationRecord
	proof session.CSRFStateSpec
	csrf  session.CSRFToken
}

var stopLifecycle = kernel.LifecyclePlan{EventType: "impersonation.stopped.v1", BeforeVersion: 3, AfterVersion: 4}

func (p stopIntent) fields() []identity.FeatureField {
	return []identity.FeatureField{
		{Name: "impersonation.activation-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.row.commandID)}},
		{Name: "impersonation.derived-key", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.row.derivedDigest.KeyVersion)}},
		{Name: "impersonation.derived-lookup", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.row.derivedDigest.Sum[:]}},
		{Name: "impersonation.stop-csrf-key", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.proof.KeyVersion)}},
		{Name: "impersonation.stop-csrf-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.proof.Digest[:]}},
	}
}

// PrepareStop authenticates exact child possession and its CSRF without
// requiring the original parent to remain live. It never mutates authority.
func (s *Service) PrepareStop(ctx context.Context, input StopInput) (PreparedStop, error) {
	if s == nil || !s.selfStop || ctx == nil {
		return PreparedStop{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.CommandID)); err != nil {
		return PreparedStop{}, impersonation.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	p, err := s.observeStop(bounded, input.Authentication)
	if err != nil {
		return PreparedStop{}, err
	}
	b := s.binding(stopAction, input.CommandID, p.row.grantID, p.row.tenant, p.row.actor, p.row.target)
	if !p.matches(b) || p.row.status != impersonation.StatusActive || !p.unexpired(s.config.Session.Validation.Clock.Now()) {
		return PreparedStop{}, identity.ForbiddenError{}
	}
	if err := s.authorizeStop(bounded, b); err != nil {
		return PreparedStop{}, err
	}
	prepared, err := s.prepareCommand(bounded, &approvalPhase{service: s, binding: b, stop: &p}, input.Network, p.fields())
	return PreparedStop{command: prepared}, err
}

// ExecuteStop commits one terminal transition, then optionally rechecks
// possession of the original still-valid ordinary actor session. This does
// not issue, rotate or modify that session, even on a replay.
func (s *Service) ExecuteStop(ctx context.Context, prepared PreparedStop, originalParent authentication.BearerCredential) (StopResult, error) {
	p := prepared.command.state
	if s == nil || !s.selfStop || ctx == nil || p == nil || p.owner != s || p.phase.stop == nil {
		return StopResult{}, impersonation.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	receipt, err := s.Execute(bounded, prepared.command)
	result := StopResult{Receipt: receipt}
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		result.Parent = s.resumeStopParent(bounded, p.phase.stop.row, originalParent)
	}
	return result, err
}

func (s *Service) resumeStopParent(ctx context.Context, row activationRecord, bearer authentication.BearerCredential) session.GetResult {
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return session.GetResult{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}
	}
	parent, err := s.sessions.Get(ctx, session.GetRequest{TenantID: row.tenant, Credential: credential})
	if err != nil || parent.ValidateAt(s.config.Session.Validation.Clock.Now()) != nil {
		return session.GetResult{}
	}
	got, err := parent.Session.Bindings()
	if err != nil || got.TenantID != row.tenant || got.UserID != row.actor || got.SessionID != row.parentID ||
		got.Version != row.parentVersion || got.Lookup != row.parentDigest {
		return session.GetResult{}
	}
	return parent
}

// RecoverStop checks exact child custody, then discloses or reconciles only the
// original receipt under the current recovery policy. It cannot resume a parent.
func (s *Service) RecoverStop(ctx context.Context, auth StopAuthentication, binding identity.CommandBinding) (identity.CommandResult, error) {
	if s == nil || !s.selfStop || ctx == nil {
		return identity.CommandResult{}, impersonation.ErrInvalidInput
	}
	return s.recoverBound(ctx, binding, func(bounded context.Context) error {
		p, err := s.observeStop(bounded, auth)
		if err != nil {
			return err
		}
		if !p.matches(binding) {
			return identity.ForbiddenError{}
		}
		return nil
	})
}

func (p stopIntent) matches(b identity.CommandBinding) bool {
	op, _ := approvalOperation(stopAction)
	return b.ValidateFor(op) == nil && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(p.row.actor) &&
		b.UserID == p.row.target && b.TenantID == p.row.tenant && b.RecordID == string(p.row.grantID) &&
		b.CorrelationID == string(b.CommandID) && b.CommandID != identity.CommandID(p.row.grantID) &&
		b.CommandID != p.row.commandID && b.CommandID != p.row.approvalID
}

func (p stopIntent) unexpired(now time.Time) bool {
	return !now.Before(p.row.startedAt) && now.Before(p.row.expiresAt)
}

func (s *Service) observeStop(ctx context.Context, auth StopAuthentication) (stopIntent, error) {
	token, err := parseDerivedCredential(auth.Bearer)
	if err != nil || !validStorageID(string(auth.Tenant)) {
		return stopIntent{}, identity.ForbiddenError{}
	}
	digest, err := token.lookup(s.activation.key, auth.Tenant)
	if err != nil {
		return stopIntent{}, identity.ForbiddenError{}
	}
	row, err := readActivation(ctx, s.pool, auth.Tenant, digest)
	if err != nil {
		return stopIntent{}, err
	}
	proof, err := s.observeStopProof(ctx, row)
	if err != nil {
		return stopIntent{}, err
	}
	if err := checkStopProof(proof, auth.CSRF, s.config.CSRFKey); err != nil {
		return stopIntent{}, err
	}
	return stopIntent{row: row, proof: proof, csrf: auth.CSRF}, nil
}

func (s *Service) observeStopProof(ctx context.Context, row activationRecord) (session.CSRFStateSpec, error) {
	rows, err := s.pool.Raw().Query(ctx, stopProofSelectSQL, string(row.tenant), string(row.grantID))
	if err != nil {
		return session.CSRFStateSpec{}, storageReadError(ctx)
	}
	return loadStopProof(ctx, rows, row)
}

func (p stopIntent) checkPreparedStop(ctx context.Context, s *Service, b identity.CommandBinding) error {
	if !p.matches(b) {
		return identity.ForbiddenError{}
	}
	row, err := readActivation(ctx, s.pool, b.TenantID, p.row.derivedDigest)
	if err != nil {
		return err
	}
	// Exact replay may read a terminal row. Normalize only its lifecycle
	// fields when comparing against the originally prepared immutable lineage.
	row.status, row.version = p.row.status, p.row.version
	if !sameActiveAuthority(row, p.row) {
		return identity.ForbiddenError{}
	}
	proof, err := s.observeStopProof(ctx, row)
	if err != nil {
		return err
	}
	if proof != p.proof {
		return identity.ForbiddenError{}
	}
	return checkStopProof(proof, p.csrf, s.config.CSRFKey)
}

func (s *Service) authorizeStop(ctx context.Context, b identity.CommandBinding) error {
	return s.authorizeTerminalAction(ctx, b, stopAction)
}
