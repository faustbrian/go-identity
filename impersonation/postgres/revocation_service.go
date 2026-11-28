package impersonationpostgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

// NewServiceWithRevocation selects the activation profile and separately
// grants access to the versioned administrator revoke operation. Install the
// full RevocationMigrationSource first; no constructor applies DDL.
func NewServiceWithRevocation(pool *database.Pool, c Config, active ActivationConfig) (*Service, error) {
	s, err := NewServiceWithActivation(pool, c, active)
	if err != nil {
		return nil, err
	}
	if err := c.Risk.ValidateCounterOnlyOperation(risk.Action(revokeAction)); err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	s.revocation = true
	return s, nil
}

// RevokeInput selects a pending (1), approved (2) or active (3) grant.
// Authentication must be a fresh non-impersonated administrator with the
// named revoke permission. Reason is private and excluded from the receipt.
type RevokeInput struct {
	Authentication  Authentication
	CommandID       identity.CommandID
	GrantID         impersonation.GrantID
	ExpectedVersion uint64
	Reason          impersonation.Reason
	Network         string
}

type revocationIntent struct {
	before  uint64
	digest  [32]byte
	payload []byte
}

func revocationLifecycle(before uint64) kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "impersonation.revoked.v1", BeforeVersion: before, AfterVersion: before + 1}
}

func (r revocationIntent) fields(originalDigest [32]byte) []identity.FeatureField {
	return []identity.FeatureField{
		{Name: "impersonation.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: originalDigest[:]}},
		{Name: "impersonation.grant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.before}},
		{Name: "impersonation.revocation-reason", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: r.digest[:]}},
	}
}

// PrepareRevoke authenticates, checks permission for the exact grant and
// freezes its expected version without changing authority. Execute commits
// the terminal transition; Recover only returns the original command receipt.
func (s *Service) PrepareRevoke(ctx context.Context, input RevokeInput) (PreparedCommand, error) {
	if s == nil || !s.revocation || ctx == nil || input.ExpectedVersion < 1 || input.ExpectedVersion > 3 ||
		string(input.CommandID) == string(input.GrantID) {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.CommandID)); err != nil {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.GrantID)); err != nil {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	reason, err := impersonation.NewReason(input.Reason.StorageText())
	if err != nil {
		return PreparedCommand{}, err
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	actor, err := authenticateActor(bounded, s.sessions, s.config.Session, s.config.CSRFKey, input.Authentication)
	if err != nil {
		return PreparedCommand{}, err
	}
	session, err := actor.observed.Session.Bindings()
	if err != nil {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	grant, err := observeGrant(bounded, s.pool, session.TenantID, input.GrantID)
	if errors.Is(err, impersonation.ErrConflict) {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	if err != nil {
		return PreparedCommand{}, err
	}
	binding := s.binding(revokeAction, input.CommandID, grant.id, grant.tenant, session.UserID, grant.target)
	if err := s.authorizeRevocation(bounded, binding); err != nil {
		return PreparedCommand{}, err
	}
	rows, err := s.pool.Raw().Query(bounded, revocableVersionSQL, string(grant.tenant), string(grant.id))
	if err != nil {
		return PreparedCommand{}, storageReadError(bounded)
	}
	if err := requireRevocableVersion(bounded, rows, input.ExpectedVersion); err != nil {
		if errors.Is(err, impersonation.ErrConflict) {
			return PreparedCommand{}, identity.ConflictError{CommandID: binding.CommandID}
		}
		return PreparedCommand{}, err
	}
	intent, err := s.sealRevocation(bounded, binding, grant, reason, input.ExpectedVersion)
	if err != nil {
		return PreparedCommand{}, err
	}
	return s.prepare(bounded, &approvalPhase{service: s, binding: binding, actor: actor, observed: grant, revoke: &intent}, input.Network)
}

func (s *Service) authorizeRevocation(ctx context.Context, b identity.CommandBinding) error {
	op, _ := approvalOperation(revokeAction)
	if b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || identity.UserID(b.ActorID) == b.UserID {
		return identity.ForbiddenError{}
	}
	caller := authorization.DecisionContext{
		PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID,
		Request: authorization.Request{
			Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)},
			Action:  authorization.Action(revokeAction), Tenant: authorization.TenantID(b.TenantID),
			Resource:    authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)},
			Attributes:  authorization.Attributes{"impersonation.grant-id": authorization.StringValue(b.RecordID)},
			Environment: authorization.Environment{Time: s.config.Session.Validation.Clock.Now().UTC()},
		},
	}
	if caller.Validate() != nil {
		return identity.ForbiddenError{}
	}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *Service) sealRevocation(ctx context.Context, b identity.CommandBinding, g grantRecord, reason impersonation.Reason, before uint64) (revocationIntent, error) {
	aad, err := secretenvelope.NewContext(map[string]string{
		"purpose": "identity.impersonation.postgres.revocation.v1", "tenant": string(b.TenantID), "grant": b.RecordID,
		"command": string(b.CommandID), "revoker": string(b.ActorID), "requester": string(g.requester), "target": string(b.UserID),
		"intent": hex.EncodeToString(g.digest[:]), "version": strconv.FormatUint(before, 10),
		"policy": b.PolicyID, "policy_version": strconv.FormatUint(b.PolicyVersion, 10),
	})
	if err != nil {
		return revocationIntent{}, impersonation.ErrInvalidInput
	}
	plaintext := []byte(reason.StorageText())
	defer clear(plaintext)
	payload, err := encryptCustody(ctx, s.config.Envelopes, s.config.EnvelopeKey, aad, plaintext, maximumApprovalPlaintext)
	if err != nil {
		return revocationIntent{}, err
	}
	return revocationIntent{before: before, digest: reason.Digest(), payload: payload}, nil
}

func (p *approvalPhase) applyRevocation(ctx context.Context, w kernel.Work, locked grantRecord, at time.Time) error {
	if p.revoke == nil || !p.service.revocation {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, revocableVersionSQL, string(locked.tenant), string(locked.id))
	if err != nil {
		return err
	}
	if err := requireRevocableVersion(ctx, rows, p.revoke.before); err != nil {
		return err
	}
	return storeRevocation(ctx, w, locked, p.binding, *p.revoke, at)
}
