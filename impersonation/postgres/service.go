package impersonationpostgres

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Config supplies existing owned primary participants. Policy must explicitly
// authorize each administrator against the exact target and requested scope.
// Its selected revision and durable actor-authorization epochs must advance
// when relevant roles, permissions or target eligibility change.
// Schema installation is separate; constructing this service performs no I/O.
type Config struct {
	Policy        impersonation.Policy
	Authorization authorization.Service
	Session       sessionpg.SessionServiceConfig
	CSRFKey       session.CSRFKey
	Risk          *riskpg.Repository
	Audit         kernel.AuditContributor
	Lifecycle     kernel.LifecycleContributor
	Envelopes     *secretenvelope.Service
	EnvelopeKey   string
	Coordinator   kernel.CoordinatorConfig
}

// Format prevents exposing trusted runtime configuration.
func (Config) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("impersonation.Config(redacted)")) }

// MarshalJSON refuses implicit runtime configuration export.
func (Config) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Service runs direct-Go request and distinct-administrator approval, and
// optional activation, online use and revocation. It borrows all dependencies, owns no
// background workers, and never treats approval alone as access authority.
type Service struct {
	pool       *database.Pool
	directory  *kernel.Repository
	sessions   *session.SessionService
	config     Config
	activation *activationService
	revocation bool
	selfStop   bool
}

// Format prevents printing the coordinator's keys and other runtime secrets.
func (Service) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("impersonation.Service(redacted)")) }

// MarshalJSON refuses serialization of the authenticated runtime graph.
func (Service) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewService validates and freezes the selected password-plus-TOTP graph.
// Neither an application-supplied session reader nor a second result journal
// may substitute for the native primary owner.
func NewService(pool *database.Pool, c Config) (*Service, error) {
	if pool == nil || pool.Raw() == nil || c.Policy.Version() == 0 || nilOwner(c.Authorization) || c.Risk == nil || nilOwner(c.Audit) || nilOwner(c.Lifecycle) || c.Envelopes == nil || len(c.EnvelopeKey) == 0 || len(c.EnvelopeKey) > 2048 || c.CSRFKey.Version() == 0 {
		return nil, impersonation.ErrInvalidInput
	}
	if c.Coordinator.MaximumDuration < time.Millisecond || c.Coordinator.MaximumDuration > 5*time.Second || c.Coordinator.FinalAuthentication != nil {
		return nil, impersonation.ErrInvalidInput
	}
	if c.Audit.Descriptor() != (kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}) || c.Lifecycle.Descriptor() != (kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) {
		return nil, impersonation.ErrInvalidInput
	}
	if _, ok := c.Audit.(kernel.RecoveryContributor); !ok {
		return nil, impersonation.ErrInvalidInput
	}
	if _, ok := c.Lifecycle.(kernel.RecoveryContributor); !ok {
		return nil, impersonation.ErrInvalidInput
	}
	for _, action := range []string{requestAction, approveAction} {
		if c.Risk.ValidateCounterOnlyOperation(risk.Action(action)) != nil {
			return nil, impersonation.ErrInvalidInput
		}
	}
	c.Session.Validation.LookupKeys = slices.Clone(c.Session.Validation.LookupKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	c.Coordinator.QueryPolicy = &kernel.CommandQueryPolicy{Authorization: c.Authorization, Clock: c.Session.Validation.Clock, PolicyVersion: c.Policy.Version()}
	c.Coordinator.AdmissionPolicy = nil
	sessions, err := sessionpg.NewMFAPasswordSessionService(pool, c.Session)
	if err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	s := &Service{pool: pool, directory: directory, sessions: sessions, config: c}
	if _, _, err := s.coordinator(&approvalPhase{service: s}); err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	return s, nil
}

func nilOwner(owner any) bool {
	if owner == nil {
		return true
	}
	switch value := reflect.ValueOf(owner); value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// RequestInput is a pending-grant request. CommandID is the stable original
// direct-Go command identity and becomes the returned grant ID. Network is a
// trusted canonical client IP from the owner, not an unchecked HTTP header.
type RequestInput struct {
	Authentication Authentication
	CommandID      identity.CommandID
	Target         identity.UserID
	Scope          impersonation.Scope
	Reason         impersonation.Reason
	Duration       time.Duration
	Network        string
}

// ApproveInput approves one exact pending version and never issues a session.
// CommandID identifies this decision, not the original request.
type ApproveInput struct {
	Authentication  Authentication
	CommandID       identity.CommandID
	GrantID         impersonation.GrantID
	ExpectedVersion uint64
	Reason          impersonation.Reason
	Network         string
}

// PreparedCommand holds a bounded, service-owned exact original command. Reuse
// it for an exact retry; after loss or expiry, recover its frozen Binding with
// fresh credentials instead of preparing a replacement or repeating effects.
type PreparedCommand struct{ state *preparedState }

type preparedState struct {
	phase       *approvalPhase
	owner       *Service
	coordinator *kernel.Coordinator
	plan        kernel.CommandPlan
}

// Format keeps original authentication and command details private.
func (PreparedCommand) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("impersonation.PreparedCommand(redacted)"))
}

// MarshalJSON refuses serialization; Binding supplies proof-free recovery scope.
func (PreparedCommand) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Binding returns exact recovery metadata, not a bearer, proof or grant of access.
func (p PreparedCommand) Binding() (identity.CommandBinding, error) {
	if p.state == nil {
		return identity.CommandBinding{}, impersonation.ErrInvalidInput
	}
	return p.state.phase.binding, nil
}

func (s *Service) coordinator(phase *approvalPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, s.config.Audit, s.config.Lifecycle, s.config.Risk, phase})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, s.config.Coordinator)
	return coordinator, registry, err
}

// PrepareRequest authenticates, authorizes and freezes the pending request.
// No grant, approval or command reservation is created until Execute.
func (s *Service) PrepareRequest(ctx context.Context, input RequestInput) (PreparedCommand, error) {
	if s == nil || ctx == nil {
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
	if err != nil || spec.UserID == input.Target {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	if input.Duration < time.Second || input.Duration > impersonation.MaximumDuration || len(input.Scope.Permissions()) == 0 || input.Reason.StorageText() == "" {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	binding := s.binding(requestAction, input.CommandID, impersonation.GrantID(input.CommandID), spec.TenantID, spec.UserID, input.Target)
	if err := s.authorize(bounded, binding, input.Scope); err != nil {
		return PreparedCommand{}, err
	}
	target, err := s.activeUser(bounded, binding.TenantID, binding.UserID)
	if err != nil {
		return PreparedCommand{}, err
	}
	requesterRecord, err := s.activeUser(bounded, spec.TenantID, spec.UserID)
	if err != nil {
		return PreparedCommand{}, err
	}
	requester, err := impersonation.NewActor(spec.TenantID, spec.UserID)
	if err != nil {
		return PreparedCommand{}, err
	}
	targetValue, err := impersonation.NewTarget(spec.TenantID, target.ID, target.Version)
	if err != nil {
		return PreparedCommand{}, err
	}
	request, err := impersonation.NewRequest(impersonation.RequestInput{Tenant: spec.TenantID, Actor: requester, Target: targetValue, Scope: input.Scope, Reason: input.Reason, Duration: input.Duration, Policy: s.config.Policy})
	if err != nil {
		return PreparedCommand{}, err
	}
	_, _, policy, err := sessionpg.OriginalMFAPasswordSessionAdmission(s.config.Session.Profile, actor.observed.Session, actorAdmissionBinding(binding))
	if err != nil {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	original := originalRequest{request: request, requesterUserVersion: requesterRecord.Version, requesterAuthorityVersion: policy.Version}
	sealed, err := sealRequest(bounded, s.config.Envelopes, s.config.EnvelopeKey, impersonation.GrantID(binding.RecordID), original)
	if err != nil {
		return PreparedCommand{}, err
	}
	return s.prepare(bounded, &approvalPhase{service: s, binding: binding, actor: actor, original: original, target: target, payload: sealed}, input.Network)
}

// PrepareApproval freezes a specific original request, reviewer and reason.
// It does not disclose the original reason or perform a write.
func (s *Service) PrepareApproval(ctx context.Context, input ApproveInput) (PreparedCommand, error) {
	if s == nil || ctx == nil || input.ExpectedVersion != 1 || input.Reason.StorageText() == "" {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.CommandID)); err != nil {
		return PreparedCommand{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.GrantID)); err != nil || string(input.CommandID) == string(input.GrantID) {
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
	observed, err := observeGrant(bounded, s.pool, spec.TenantID, input.GrantID)
	if err != nil {
		return PreparedCommand{}, err
	}
	if observed.requester == spec.UserID || observed.target == spec.UserID {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	original, err := openRequest(bounded, s.config.Envelopes, observed.tenant, observed.id, observed.requester, observed.target, observed.digest, observed.payload)
	if err != nil {
		return PreparedCommand{}, err
	}
	if original.request.Policy() != s.config.Policy {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	binding := s.binding(approveAction, input.CommandID, input.GrantID, spec.TenantID, spec.UserID, observed.target)
	if err := s.authorize(bounded, binding, original.request.Scope()); err != nil {
		return PreparedCommand{}, err
	}
	if observed.version != input.ExpectedVersion {
		return PreparedCommand{}, impersonation.ErrConflict
	}
	if err := s.authorize(bounded, s.originalRequesterBinding(observed), original.request.Scope()); err != nil {
		return PreparedCommand{}, err
	}
	target := identity.User{ID: observed.target, TenantID: spec.TenantID, Status: identity.StatusActive, Version: original.request.Target().Version()}
	approver, err := s.activeUser(bounded, spec.TenantID, spec.UserID)
	if err != nil {
		return PreparedCommand{}, err
	}
	_, _, admission, err := sessionpg.OriginalMFAPasswordSessionAdmission(s.config.Session.Profile, actor.observed.Session, actorAdmissionBinding(binding))
	if err != nil {
		return PreparedCommand{}, identity.ForbiddenError{}
	}
	epoch := approvalEpoch{userVersion: approver.Version, authorizationVersion: admission.Version, namespace: admission.Scope.PolicyNamespace}
	decision := approvalRecord{commandID: input.CommandID, approver: spec.UserID}
	sealed, err := sealActivationApproval(bounded, s.config.Envelopes, s.config.EnvelopeKey, observed, decision, input.Reason, epoch)
	if err != nil {
		return PreparedCommand{}, err
	}
	participant := approvalParticipant{user: approver, epoch: epoch}
	return s.prepare(bounded, &approvalPhase{service: s, binding: binding, actor: actor, original: original, target: target, observed: observed, payload: sealed, reason: input.Reason, approver: participant}, input.Network)
}

func (s *Service) binding(action string, id identity.CommandID, grantID impersonation.GrantID, tenant identity.TenantID, actor, target identity.UserID) identity.CommandBinding {
	op, _ := approvalOperation(action)
	return identity.CommandBinding{CommandID: id, TenantID: tenant, UserID: target, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(grantID), PolicyID: s.config.Policy.ID(), PolicyVersion: s.config.Policy.Version(), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: string(id)}
}

func (s *Service) originalRequesterBinding(grant grantRecord) identity.CommandBinding {
	return s.binding(requestAction, identity.CommandID(grant.id), grant.id, grant.tenant, grant.requester, grant.target)
}

func (s *Service) authorize(ctx context.Context, binding identity.CommandBinding, scope impersonation.Scope) error {
	caller, err := actorDecision(binding, scope, s.config.Session.Validation.Clock.Now())
	if err != nil {
		return err
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

func (s *Service) activeUser(ctx context.Context, tenant identity.TenantID, id identity.UserID) (identity.User, error) {
	u, err := s.directory.Get(ctx, identity.GetUserQuery{TenantID: tenant, UserID: id})
	if ctx.Err() != nil {
		return identity.User{}, ctx.Err()
	}
	if errors.Is(err, identity.ErrUserAbsent) {
		return identity.User{}, identity.ForbiddenError{}
	}
	if err != nil {
		return identity.User{}, identity.UnavailableError{}
	}
	if u.TenantID != tenant || u.ID != id || u.Status != identity.StatusActive {
		return identity.User{}, identity.ForbiddenError{}
	}
	return u, nil
}
