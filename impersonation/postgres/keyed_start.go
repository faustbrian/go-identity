package impersonationpostgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// KeyedStartCustody opts into local envelope custody for the original safe
// binding. ConfigurationID is a stable deployment/selected-profile identity.
// Retain old encryption keys while their request mappings remain recoverable.
// The constructor copies Keys; callers own erasure of their source buffers.
// Keys must be independent of request-key lookup, session and CSRF keys.
type KeyedStartCustody struct {
	ConfigurationID string
	ActiveKey       string
	Keys            map[string][]byte
}

func (KeyedStartCustody) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("impersonation.KeyedStartCustody(redacted)"))
}
func (KeyedStartCustody) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// KeyedStartService is an optional request-key adapter for the selected
// self-stop service. It owns no second key mapping, command journal or store.
type KeyedStartService struct {
	native          *Service
	requestKeys     kernel.RequestKeyConfig
	custody         *envelope.Service
	configurationID string
	activeKey       string
}

func (KeyedStartService) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("impersonation.KeyedStartService(redacted)"))
}
func (KeyedStartService) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewKeyedStartService selects the existing prepared request-key migration
// and the already selected impersonation self-stop service. It performs no
// network or database I/O. Install both migration histories before use.
func NewKeyedStartService(native *Service, keys kernel.RequestKeyConfig, custody KeyedStartCustody) (*KeyedStartService, error) {
	if native == nil || !native.selfStop || keys.Policy.PolicyVersion != native.config.Policy.Version() ||
		!validStorageID(custody.ConfigurationID) || !validStorageID(custody.ActiveKey) || len(custody.Keys) > 16 || len(custody.Keys[custody.ActiveKey]) != 32 {
		return nil, impersonation.ErrInvalidInput
	}
	for _, key := range custody.Keys {
		if len(key) != 32 || [32]byte(key) == ([32]byte{}) {
			return nil, impersonation.ErrInvalidInput
		}
	}
	local, err := keyring.New(custody.Keys)
	if err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	sealer, err := envelope.NewService(local)
	if err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	s := &KeyedStartService{native: native, requestKeys: keys, custody: sealer, configurationID: custody.ConfigurationID, activeKey: custody.ActiveKey}
	if _, err := s.coordinator(&approvalPhase{service: native}); err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	return s, nil
}

type KeyedStartInput struct {
	Authentication  Authentication
	GrantID         impersonation.GrantID
	ExpectedVersion uint64
	Network         string
	Key             identity.IdempotencyKey
}

type keyedStartInvocation struct {
	service        *KeyedStartService
	input          StartInput
	scope          kernel.RequestKeyScope
	intent         identity.RequestIntent
	local          PreparedActivation
	projectionHash [32]byte
	failure        error
}

// Start gives the original acknowledged mapping winner one chance to execute
// and disclose the resulting secrets. A retained request never re-prepares or
// reissues: it recovers only the original command's observed result.
func (s *KeyedStartService) Start(ctx context.Context, input KeyedStartInput) (StoppableActivationResult, error) {
	var zero StoppableActivationResult
	if s == nil || s.native == nil || ctx == nil || input.ExpectedVersion != 2 {
		return zero, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.GrantID)); err != nil {
		return zero, impersonation.ErrInvalidInput
	}
	n := s.native
	bounded, cancel := context.WithTimeout(ctx, n.config.Coordinator.MaximumDuration)
	defer cancel()
	actor, err := authenticateActor(bounded, n.sessions, n.config.Session, n.config.CSRFKey, input.Authentication)
	if errors.Is(err, session.ErrUnauthenticated) {
		return zero, identity.ForbiddenError{}
	}
	if err != nil {
		return zero, err
	}
	spec, err := actor.observed.Session.Bindings()
	if err != nil {
		return zero, identity.ForbiddenError{}
	}
	scope := kernel.RequestKeyScope{
		TenantID: spec.TenantID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser,
		Method: "POST", RouteID: startAction,
	}
	phase, err := s.startInvocation(scope, input)
	if err != nil {
		return zero, err
	}
	coordinator, err := s.coordinator(phase)
	if err != nil {
		return zero, err
	}
	p := phase.keyed
	feature := keyedStartRegistration()
	caller := n.startCaller(scope, "identity.request-admission", startAction, string(input.GrantID))
	retained, wire, err := coordinator.ResolvePreparedRequestKey(bounded, scope, input.Key, p.intent, caller, feature, phase)
	defer clear(wire)
	if err != nil {
		if p.failure != nil && bounded.Err() == nil {
			return zero, p.failure
		}
		return zero, err
	}
	original, err := phase.RestoreRequestKey(bounded, retained, wire)
	if err != nil {
		return zero, err
	}
	if local, err := p.local.Binding(); err == nil && local == original && p.projectionHash == sha256.Sum256(wire) {
		return n.ExecuteStoppableStart(bounded, p.local)
	}
	return s.recoverStart(bounded, coordinator, phase, original, input.Authentication)
}

func (s *KeyedStartService) startInvocation(scope kernel.RequestKeyScope, input KeyedStartInput) (*approvalPhase, error) {
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "impersonation.grant-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(input.GrantID)}},
		{Name: "impersonation.grant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: input.ExpectedVersion}},
		{Name: "impersonation.configuration-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.configurationID}},
	})
	if err != nil {
		return nil, err
	}
	p := &keyedStartInvocation{service: s, scope: scope, intent: intent, input: StartInput{
		Authentication: input.Authentication, GrantID: input.GrantID, ExpectedVersion: input.ExpectedVersion, Network: input.Network,
	}}
	return &approvalPhase{service: s.native, keyed: p}, nil
}

func (s *KeyedStartService) coordinator(p *approvalPhase) (*kernel.Coordinator, error) {
	registry, err := s.native.registry(p)
	if err != nil {
		return nil, err
	}
	return kernel.NewCoordinatorWithRequestKeys(s.native.pool, registry, s.native.config.Coordinator, s.requestKeys)
}

func keyedStartRegistration() kernel.FeatureRegistration {
	op, _ := approvalOperation(startAction)
	return kernel.FeatureRegistration{Contributor: approvalDescriptor, Operation: op}
}

func (s *Service) startCaller(scope kernel.RequestKeyScope, resourceType, resourceID, correlation string) authorization.DecisionContext {
	return authorization.DecisionContext{
		PolicyRevision: authorization.Revision(s.config.Policy.Version()), CorrelationID: correlation,
		Request: authorization.Request{
			Subject: authorization.Subject{Kind: scope.ActorKind, ID: authorization.SubjectID(scope.ActorID)},
			Action:  authorization.Action(startAction), Tenant: authorization.TenantID(scope.TenantID),
			Resource:    authorization.Resource{Type: authorization.ResourceType(resourceType), ID: authorization.ResourceID(resourceID)},
			Environment: authorization.Environment{Time: s.config.Session.Validation.Clock.Now().UTC()},
		},
	}
}

func (s *KeyedStartService) recoverStart(ctx context.Context, c *kernel.Coordinator, p *approvalPhase, b identity.CommandBinding, auth Authentication) (StoppableActivationResult, error) {
	var out StoppableActivationResult
	n := s.native
	// Check the frozen grant and today's action policy even on historical
	// replay. An expired grant can yield metadata, never renewed authority.
	g, err := observeGrant(ctx, n.pool, b.TenantID, impersonation.GrantID(b.RecordID))
	if errors.Is(err, impersonation.ErrConflict) {
		return out, identity.ForbiddenError{}
	}
	if err != nil {
		return out, err
	}
	if g.requester != identity.UserID(b.ActorID) || g.target != b.UserID || g.version != 2 {
		return out, identity.ForbiddenError{}
	}
	frozen, err := openRequest(ctx, n.config.Envelopes, g.tenant, g.id, g.requester, g.target, g.digest, g.payload)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	if err := n.authorize(ctx, b, frozen.request.Scope()); err != nil {
		return out, err
	}
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID,
		ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	caller := n.startCaller(p.keyed.scope, "identity.user", string(b.UserID), b.CorrelationID)
	receipt, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, keyedStartRegistration(), p)
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return out, err
	}
	if receipt.Binding != b || receipt.Validate() != nil {
		return out, identity.ForbiddenError{}
	}
	if authErr := n.requireActor(ctx, auth, b); authErr != nil {
		return out, authErr
	}
	out.Receipt = receipt
	return out, err
}
