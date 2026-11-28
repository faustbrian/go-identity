package impersonationpostgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

// NewServiceWithDenial selects terminal denial as well as the existing
// self-stop profile. Apply DenialMigrationSource before serving this
// additional operation. The constructor does not install or inspect schema.
func NewServiceWithDenial(pool *database.Pool, c Config, active ActivationConfig) (*Service, error) {
	s, err := NewServiceWithSelfStop(pool, c, active)
	if err != nil {
		return nil, err
	}
	if err := c.Risk.ValidateCounterOnlyOperation(risk.Action(denyAction)); err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	s.denial = true
	return s, nil
}

// DenyInput selects an exact pending request. Authentication must belong to
// a fresh, non-impersonated administrator distinct from requester and target.
// Reason is private and excluded from the receipt.
type DenyInput struct {
	Authentication  Authentication
	CommandID       identity.CommandID
	GrantID         impersonation.GrantID
	ExpectedVersion uint64
	Reason          impersonation.Reason
	Network         string
}

type denialIntent struct {
	digest  [32]byte
	payload []byte
}

func (d denialIntent) fields(originalDigest [32]byte) []identity.FeatureField {
	return []identity.FeatureField{
		{Name: "impersonation.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: originalDigest[:]}},
		{Name: "impersonation.grant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
		{Name: "impersonation.denial-reason", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: d.digest[:]}},
	}
}

// PrepareDenial authenticates the independent administrator and freezes the
// exact grant and its private decision reason. Execute is the only writer.
func (s *Service) PrepareDenial(ctx context.Context, input DenyInput) (PreparedCommand, error) {
	if s == nil || !s.denial || ctx == nil || input.ExpectedVersion != 1 || input.Reason.StorageText() == "" ||
		!validStoredGrantKey(input.Authentication.Tenant, input.GrantID) || string(input.CommandID) == string(input.GrantID) {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.CommandID)); err != nil {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	actor, err := authenticateActor(bounded, s.sessions, s.config.Session, s.config.CSRFKey, input.Authentication)
	if err != nil {
		return PreparedCommand{}, err
	}
	spec, err := actor.observed.Session.Bindings()
	if err != nil {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	grant, err := observeGrant(bounded, s.pool, spec.TenantID, input.GrantID)
	if errors.Is(err, impersonation.ErrConflict) {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	if err != nil {
		return PreparedCommand{}, err
	}
	if spec.UserID == grant.requester || spec.UserID == grant.target {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	original, err := openRequest(bounded, s.config.Envelopes, grant.tenant, grant.id, grant.requester, grant.target, grant.digest, grant.payload)
	if err != nil {
		return PreparedCommand{}, err
	}
	binding := s.binding(denyAction, input.CommandID, grant.id, grant.tenant, spec.UserID, grant.target)
	if err := s.authorize(bounded, binding, original.request.Scope()); err != nil {
		return PreparedCommand{}, err
	}
	if err := s.requirePendingDenial(bounded, binding); err != nil {
		return PreparedCommand{}, err
	}
	intent, err := s.sealDenial(bounded, binding, grant, input.Reason)
	if err != nil {
		return PreparedCommand{}, err
	}
	return s.prepare(bounded, &approvalPhase{service: s, binding: binding, actor: actor, original: original, observed: grant, deny: &intent}, input.Network)
}

func (s *Service) sealDenial(ctx context.Context, b identity.CommandBinding, g grantRecord, reason impersonation.Reason) (denialIntent, error) {
	aad, err := secretenvelope.NewContext(map[string]string{
		"purpose": "identity.impersonation.postgres.denial.v1", "tenant": string(b.TenantID), "grant": b.RecordID,
		"command": string(b.CommandID), "denier": string(b.ActorID), "requester": string(g.requester), "target": string(b.UserID),
		"intent": hex.EncodeToString(g.digest[:]), "version": "1",
		"policy": b.PolicyID, "policy_version": strconv.FormatUint(b.PolicyVersion, 10),
	})
	if err != nil {
		return denialIntent{}, impersonation.ErrInvalidInput
	}
	plaintext := []byte(reason.StorageText())
	defer clear(plaintext)
	payload, err := encryptCustody(ctx, s.config.Envelopes, s.config.EnvelopeKey, aad, plaintext, maximumApprovalPlaintext)
	if err != nil {
		return denialIntent{}, err
	}
	return denialIntent{digest: reason.Digest(), payload: payload}, nil
}

func (p *approvalPhase) applyDenial(ctx context.Context, w kernel.Work, locked grantRecord, at time.Time) error {
	if p.deny == nil || !p.service.denial {
		return identity.ForbiddenError{}
	}
	return storeDenial(ctx, w, locked, p.binding, *p.deny, at)
}
