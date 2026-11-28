package impersonationpostgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ActivationConfig selects stateful impersonation. Generate LookupKey
// independently of ordinary session and other identity keys. Replacing the
// key invalidates outstanding derived credentials.
type ActivationConfig struct {
	LookupKey session.DigestKey
}

type activationService struct {
	key         session.DigestKey
	parents     *sessionpg.OriginalPasswordTOTPParentObserver
	authorities *authority.AuthorityStore
}

// NewServiceWithActivation opts into durable start and online validation.
// Install ActivationMigrationSource before selecting this constructor.
// The service borrows all primary dependencies and never applies DDL.
func NewServiceWithActivation(pool *database.Pool, c Config, active ActivationConfig) (*Service, error) {
	s, err := NewService(pool, c)
	if err != nil {
		return nil, err
	}
	if err := c.Risk.ValidateCounterOnlyOperation(risk.Action(startAction)); err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	probe, err := newDerivedCredential()
	if err != nil {
		return nil, err
	}
	probeDigest, err := probe.lookup(active.LookupKey, "composition")
	if err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	for _, ordinary := range c.Session.Validation.LookupKeys {
		if digest, err := probe.lookup(ordinary, "composition"); err != nil || digest == probeDigest {
			return nil, impersonation.ErrInvalidInput
		}
	}
	parent, err := sessionpg.NewOriginalPasswordTOTPParentObserver(pool, c.Session)
	if err != nil {
		return nil, err
	}
	auth, err := authority.NewAuthorityStore(pool.Raw(), c.Coordinator.MaximumDuration)
	if err != nil {
		return nil, err
	}
	s.activation = &activationService{key: active.LookupKey, parents: parent, authorities: auth}
	return s, nil
}

// StartInput selects one exact approved grant owned by the ordinary requester.
// The stable command ID identifies activation, not approval or request.
type StartInput struct {
	Authentication  Authentication
	CommandID       identity.CommandID
	GrantID         impersonation.GrantID
	ExpectedVersion uint64
	Network         string
}

// PreparedActivation owns the exact start command and one unreleased
// credential. Copies share delivery custody. It has no authority until commit.
type PreparedActivation struct {
	command PreparedCommand
}

// Format never traverses credential custody or the authenticated parent.
func (PreparedActivation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "impersonation.PreparedActivation(redacted)")
}

// MarshalJSON refuses automatic serialization of an uncommitted activation.
func (PreparedActivation) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Binding returns safe correlation for exact receipt recovery, not a bearer.
func (p PreparedActivation) Binding() (identity.CommandBinding, error) { return p.command.Binding() }

// ActivationResult carries the historical receipt and a credential transferred
// only once for the original prepared value after commit. Replays and restart
// recovery never issue another credential. Keep Credential out of logs/wire
// serialization; explicitly reveal it to the authorized caller.
type ActivationResult struct {
	Receipt    identity.CommandResult
	Credential DerivedCredential
}

type approvalParticipant struct {
	user  identity.User
	epoch approvalEpoch
}

func (a approvalParticipant) admission() kernel.UserAuthorizationAdmission {
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(a.user.TenantID),
		SubjectID: authorization.SubjectID(a.user.ID), PolicyNamespace: a.epoch.namespace}
	return kernel.UserAuthorizationAdmission{Scope: scope, Version: a.epoch.authorizationVersion}
}

func (a approvalParticipant) commandFields() []identity.FeatureField {
	return []identity.FeatureField{
		{Name: "impersonation.approver-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(a.user.ID)}},
		{Name: "impersonation.approver-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: a.user.Version}},
		{Name: "impersonation.approver-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: a.epoch.namespace}},
		{Name: "impersonation.approver-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: a.epoch.authorizationVersion}},
	}
}

type activationIntent struct {
	approved   impersonation.Grant
	approval   impersonation.Approval
	retained   approvalRecord
	parent     sessionpg.OriginalPasswordTOTPParentReference
	credential DerivedCredential
	digest     session.TokenDigest
	delivered  atomic.Bool
}

func (a *activationIntent) commandFields() []identity.FeatureField {
	return []identity.FeatureField{
		{Name: "impersonation.approval-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(a.retained.commandID)}},
		{Name: "impersonation.approved-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: a.retained.decidedAt}},
		{Name: "impersonation.derived-lookup", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: a.digest.Sum[:]}},
		{Name: "impersonation.derived-key", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(a.digest.KeyVersion)}},
	}
}

// PrepareStart binds the original ordinary TOTP/CSRF requester, exact
// approval and current policy. It does not reserve or activate anything.
func (s *Service) PrepareStart(ctx context.Context, input StartInput) (PreparedActivation, error) {
	if s == nil || s.activation == nil || ctx == nil || input.ExpectedVersion != 2 || string(input.CommandID) == string(input.GrantID) {
		return PreparedActivation{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.CommandID)); err != nil {
		return PreparedActivation{}, impersonation.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.GrantID)); err != nil {
		return PreparedActivation{}, impersonation.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	actor, err := authenticateActor(bounded, s.sessions, s.config.Session, s.config.CSRFKey, input.Authentication)
	if err != nil {
		return PreparedActivation{}, err
	}
	spec, err := actor.observed.Session.Bindings()
	if err != nil {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	g, err := observeGrant(bounded, s.pool, spec.TenantID, input.GrantID)
	if errors.Is(err, impersonation.ErrConflict) {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	if err != nil {
		return PreparedActivation{}, err
	}
	if g.requester != spec.UserID || g.version != input.ExpectedVersion {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	original, err := openRequest(bounded, s.config.Envelopes, g.tenant, g.id, g.requester, g.target, g.digest, g.payload)
	if err != nil || original.request.Policy() != s.config.Policy {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	b := s.binding(startAction, input.CommandID, g.id, g.tenant, g.requester, g.target)
	if err := s.authorize(bounded, b, original.request.Scope()); err != nil {
		return PreparedActivation{}, err
	}
	retained, err := observeRetainedApproval(bounded, s.pool, g)
	if err != nil {
		return PreparedActivation{}, err
	}
	if retained.commandID == input.CommandID {
		return PreparedActivation{}, impersonation.ErrInvalidInput
	}
	reason, epoch, err := openActivationApproval(bounded, s.config.Envelopes, g, retained)
	if err != nil || epoch.namespace != s.config.Session.Profile.PolicyNamespace {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	if err := s.authorize(bounded, s.binding(approveAction, retained.commandID, g.id, g.tenant, retained.approver, g.target), original.request.Scope()); err != nil {
		return PreparedActivation{}, err
	}
	approver, err := impersonation.NewActor(g.tenant, retained.approver)
	if err != nil {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	pending, err := impersonation.NewPendingGrant(g.id, original.request, g.requestedAt)
	if err != nil || !pending.ExpiresAt().Equal(g.expiresAt) {
		return PreparedActivation{}, identity.UnavailableError{}
	}
	approved, approval, err := impersonation.Approve(pending, impersonation.ApprovalInput{GrantID: g.id, ExpectedVersion: 1,
		Request: original.request, Approver: approver, Reason: reason, At: retained.decidedAt})
	if err != nil {
		return PreparedActivation{}, identity.ForbiddenError{}
	}
	credential, err := newDerivedCredential()
	if err != nil {
		return PreparedActivation{}, err
	}
	digest, err := credential.lookup(s.activation.key, g.tenant)
	if err != nil {
		return PreparedActivation{}, err
	}
	start := &activationIntent{approved: approved, approval: approval, retained: retained,
		parent: sessionpg.OriginalPasswordTOTPParentReference{TenantID: spec.TenantID, ActorID: spec.UserID,
			SessionID: spec.SessionID, SessionVersion: spec.Version, Lookup: spec.Lookup}, credential: credential, digest: digest}
	p := &approvalPhase{service: s, binding: b, actor: actor, original: original, observed: g, start: start,
		target:   identity.User{ID: g.target, TenantID: g.tenant, Status: identity.StatusActive, Version: original.request.Target().Version()},
		approver: approvalParticipant{user: identity.User{ID: retained.approver, TenantID: g.tenant, Status: identity.StatusActive, Version: epoch.userVersion}, epoch: epoch}}
	if _, err := p.activationAt(s.config.Session.Validation.Clock.Now()); err != nil {
		return PreparedActivation{}, err
	}
	command, err := s.prepare(bounded, p, input.Network)
	return PreparedActivation{command: command}, err
}

// ExecuteStart atomically activates the prepared grant and transfers credential
// custody to the first exact committed result. An unknown result carries no
// secret; use Recover with the original binding rather than creating a new
// command. Restart recovery discloses metadata only.
func (s *Service) ExecuteStart(ctx context.Context, input PreparedActivation) (ActivationResult, error) {
	prepared := input.command.state
	if s == nil || s.activation == nil || prepared == nil || prepared.owner != s || prepared.phase.start == nil {
		return ActivationResult{}, impersonation.ErrInvalidInput
	}
	receipt, err := s.Execute(ctx, input.command)
	result := ActivationResult{Receipt: receipt}
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted && prepared.phase.start.delivered.CompareAndSwap(false, true) {
		result.Credential = prepared.phase.start.credential
	}
	return result, err
}

const retainedActivationApprovalSQL = `SELECT command_id,approver_id,encrypted_payload,decided_at
 FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`

func observeRetainedApproval(ctx context.Context, pool *database.Pool, g grantRecord) (approvalRecord, error) {
	rows, err := pool.Raw().Query(ctx, retainedActivationApprovalSQL, string(g.tenant), string(g.id))
	if err != nil {
		return approvalRecord{}, storageReadError(ctx)
	}
	return decodeRetainedApproval(ctx, rows, g)
}

func decodeRetainedApproval(ctx context.Context, rows storedGrantRows, g grantRecord) (approvalRecord, error) {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return approvalRecord{}, storageReadError(ctx)
		}
		return approvalRecord{}, identity.ForbiddenError{}
	}
	var id, actor string
	var a approvalRecord
	if err := rows.Scan(&id, &actor, &a.payload, &a.decidedAt); err != nil || rows.Next() || rows.Err() != nil {
		return approvalRecord{}, storageReadError(ctx)
	}
	command, err := identity.ParseCommandID(id)
	a.decidedAt = a.decidedAt.UTC()
	if err != nil || id == string(g.id) || !validStorageID(actor) || actor == string(g.requester) || actor == string(g.target) ||
		len(a.payload) == 0 || len(a.payload) > maximumCustodyEnvelope || !storageExactTime(a.decidedAt) ||
		a.decidedAt.Before(g.requestedAt) || !a.decidedAt.Before(g.expiresAt) {
		return approvalRecord{}, identity.UnavailableError{}
	}
	a.commandID, a.approver = command, identity.UserID(actor)
	return a, nil
}

func (p *approvalPhase) checkRetainedActivationApproval(ctx context.Context, w kernel.Work) error {
	if p.start == nil {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, retainedActivationApprovalSQL, string(p.binding.TenantID), p.binding.RecordID)
	if err != nil {
		return err
	}
	current, err := decodeRetainedApproval(ctx, rows, p.observed)
	if err != nil {
		return err
	}
	frozen := p.start.retained
	if current.commandID != frozen.commandID || current.approver != frozen.approver ||
		!current.decidedAt.Equal(frozen.decidedAt) || !bytes.Equal(current.payload, frozen.payload) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *approvalPhase) activationAt(at time.Time) (impersonation.ActiveBindings, error) {
	start := p.start
	if start == nil {
		return impersonation.ActiveBindings{}, identity.ForbiddenError{}
	}
	lifetime, err := p.actor.observed.Session.Lifetime(at)
	if err != nil {
		return impersonation.ActiveBindings{}, identity.ForbiddenError{}
	}
	_, active, err := impersonation.Activate(start.approved, impersonation.ActivationInput{GrantID: p.observed.id, ExpectedVersion: 2,
		Approval: start.approval, Actor: p.original.request.Actor(), CurrentTarget: p.original.request.Target(),
		CurrentPolicy: p.service.config.Policy, ParentSessionID: start.parent.SessionID, ParentSessionVersion: start.parent.SessionVersion,
		ParentExpiresAt: lifetime.ExpiresAt, At: at})
	return active.Bindings(), err
}

func (p *approvalPhase) applyActivation(ctx context.Context, w kernel.Work, at time.Time) error {
	active, err := p.activationAt(at)
	if err != nil {
		return err
	}
	// Store only digests. Delivery custody remains private in the prepared
	// value and cannot become a persisted or recovered ordinary session.
	return insertActivation(ctx, w, activationRecord{
		tenant: active.TenantID, grantID: active.GrantID, commandID: p.binding.CommandID, approvalID: p.start.retained.commandID,
		actor: active.ActorID, target: active.TargetID, approver: p.approver.user.ID, requestDigest: p.observed.digest,
		scope: active.Scope, policy: active.Policy,
		actorVersion: p.original.requesterUserVersion, targetVersion: active.TargetVersion,
		approverVersion: p.approver.user.Version, approverAuthorityVersion: p.approver.epoch.authorizationVersion,
		authorityNamespace: p.approver.epoch.namespace, parentID: p.start.parent.SessionID, parentVersion: p.start.parent.SessionVersion,
		parentDigest: p.start.parent.Lookup, derivedDigest: p.start.digest,
		startedAt: active.StartedAt, expiresAt: active.ExpiresAt.UTC().Truncate(time.Microsecond), version: active.GrantVersion, status: impersonation.StatusActive})
}

func (p *approvalPhase) checkStoredActivationDeadline(ctx context.Context, w kernel.Work, at time.Time) error {
	if p.start == nil {
		return identity.ForbiddenError{}
	}
	digest := p.start.digest
	rows, err := w.Query(ctx, activationSelectSQL, string(p.binding.TenantID), strconv.FormatUint(uint64(digest.KeyVersion), 10), digest.Sum[:])
	if err != nil {
		return err
	}
	stored, err := decodeActivation(ctx, rows)
	if err != nil {
		return err
	}
	if stored.commandID != p.binding.CommandID || stored.derivedDigest != digest || stored.status != impersonation.StatusActive ||
		!at.Before(stored.expiresAt) {
		return identity.ConflictError{CommandID: p.binding.CommandID}
	}
	return nil
}
