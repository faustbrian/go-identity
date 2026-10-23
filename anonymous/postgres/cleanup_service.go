package anonymouspostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// CleanupConfig selects trusted maintenance, not browser authentication. ActorID
// is fixed by composition; the configured current authorization engine must
// allow selection on identity.anonymous/expired and individual disposal on
// identity.anonymous/<user>, in addition to the coordinator's admission/query
// scopes. Retention runs outside SQL; holds and deferred decisions stay pending.
// MaximumBatch is 1..1000. ConfigurationID versions callback semantics.
// Install selected kernel/session/anonymous disposal+expiry and existing
// request-key preparation histories. Construction never installs or migrates.
type CleanupConfig struct {
	Repository                Config
	Sessions                  sessionpg.Config
	GlobalAuthorityID         string
	ActorID                   identity.ActorID
	ConfigurationID, PolicyID string
	MaximumBatch              uint32
	Clock                     clock.Clock
	Retention                 *identity.PolicyEvaluator
	RetentionPolicyVersion    uint64
	RequestKeys               kernel.RequestKeyConfig
	Coordinator               kernel.CoordinatorConfig
	IntentKey                 [32]byte
	ActiveEnvelopeKeyID       string
}

// CleanupCursor is an exclusive indexed seek position, not eligibility or
// authorization. Eligibility always uses fresh authoritative database time.
// Advance past deferred subjects using Next, then start a later run from zero
// to revisit them. Preserve the exact returned expiry and user tie-breaker.
type CleanupCursor struct {
	ExpiresAt time.Time
	UserID    identity.UserID
}

// CleanupRequest selects one bounded tenant page. Generate RunID once and keep
// it across interruption/retry: each selected subject gets an original random
// command through the existing immutable request-key owner. A batch is NOT one
// atomic/idempotent receipt: repeating selection can include other still-active
// expired subjects. Individual results and CleanupSubject retain exact retries.
// No caller-supplied timestamp, actor, cleanup policy or guest credential exists.
type CleanupRequest struct {
	TenantID identity.TenantID
	RunID    identity.CommandID
	Limit    uint32
	After    *CleanupCursor
}

// CleanupSubjectRequest names a maintenance target and stable run correlation.
// It grants no authority and cannot dispose a permanent/unexpired/terminal user.
// Retry the same input after uncertain request-key admission; after a command
// exists, save its Recovery query. New policy/admission needs a new RunID.
type CleanupSubjectRequest struct {
	TenantID identity.TenantID
	UserID   identity.UserID
	RunID    identity.CommandID
}

// CleanupItem is historical per-subject metadata, never authentication. Error
// is populated by batch execution for a deferred or interrupted item. Unknown
// and InProgress require original recovery, not an invented success/rollback.
type CleanupItem struct {
	UserID     identity.UserID
	Outcome    identity.CommitOutcome
	Recovery   identity.RecoveryQuery
	Replayed   bool
	RetryAfter time.Duration
	Error      error
}

// CleanupResult preserves completed/attempted items even when a later item
// fails. Next follows the last attempted subject; reconcile unknown work before
// advancing. LagKnown alone makes RemainingLag meaningful: it observes the
// tenant's complete active backlog, including held/contended subjects, at
// ObservedAt and saturates at 8760 hours. It is not a future-empty guarantee.
type CleanupResult struct {
	Items        []CleanupItem
	Next         *CleanupCursor
	ObservedAt   time.Time
	RemainingLag time.Duration
	LagKnown     bool
}

// CleanupService owns bounded explicit maintenance, not a scheduler, background
// goroutine, pool or second transaction/recovery engine. Immutable composition
// supports concurrent calls; keep borrowed pool, policies, clock and keys alive.
type CleanupService struct {
	pool       *database.Pool
	repository *Repository
	directory  *kernel.Repository
	domain     *kernel.AnonymousDisposalDomain
	effect     *sessionpg.AnonymousDisposalEffect
	crypto     *envelope.Service
	config     func() CleanupConfig
	profile    [32]byte
}

// NewCleanupService freezes native owners without IO, callbacks or entropy.
// Expired credentials are never accepted as maintenance authority. Stored
// retain/anonymize/delete policy and original hold/authority versions survive
// preparation; every actual owner rechecks them in the same final transaction.
func NewCleanupService(pool *database.Pool, c CleanupConfig, keys *keyring.Provider) (*CleanupService, error) {
	if keys == nil || c.Clock == nil || c.Retention == nil || c.RetentionPolicyVersion == 0 || c.MaximumBatch < 1 || c.MaximumBatch > 1000 || !signinText(string(c.ActorID), 128) || !signinText(c.GlobalAuthorityID, 128) || !signinText(c.ConfigurationID, 128) || !signinText(c.PolicyID, 128) || !signinText(c.ActiveEnvelopeKeyID, 256) || c.IntentKey == ([32]byte{}) || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.AdmissionPolicy.PolicyVersion != c.RequestKeys.Policy.PolicyVersion {
		return nil, anonymous.ErrInvalidInput
	}
	r, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	d, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	domain, err := kernel.NewAnonymousDisposalDomain(d)
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewAnonymousDisposalEffect(c.Sessions)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	q, a := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &a
	frame, err := json.Marshal(struct {
		Configuration, Policy, Schema, Sessions, Global, Actor, Namespace string
		PolicyVersion, RetentionVersion                                   uint64
	}{c.ConfigurationID, c.PolicyID, c.Repository.Schema, c.Sessions.Schema, c.GlobalAuthorityID, string(c.ActorID), c.RequestKeys.Namespace, a.PolicyVersion, c.RetentionPolicyVersion})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	s := &CleanupService{pool: pool, repository: r, directory: d, domain: domain, effect: effect, crypto: crypto, profile: sha256.Sum256(frame), config: func() CleanupConfig { return c }}
	clear(frame)
	if _, _, err := s.coordinator(&cleanupPhase{service: s}); err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	return s, nil
}

func (s *CleanupService) coordinator(p *cleanupPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, l, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.pool, r, s.config().Coordinator, s.config().RequestKeys)
	return c, r, err
}

func (s *CleanupService) caller(tenant identity.TenantID, resource, id string) authorization.DecisionContext {
	c := s.config()
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(c.RequestKeys.Policy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.anonymous.expire", Resource: authorization.Resource{Type: authorization.ResourceType(resource), ID: authorization.ResourceID(id)}}}
}

func (s *CleanupService) allow(ctx context.Context, tenant identity.TenantID, user string) error {
	d, err := s.config().Coordinator.AdmissionPolicy.Authorization.Decide(ctx, s.caller(tenant, "identity.anonymous", user))
	if err != nil {
		return identity.UnavailableError{}
	}
	if d.Outcome != authorization.Allow || d.Revision != authorization.Revision(s.config().RequestKeys.Policy.PolicyVersion) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *CleanupService) intent(r CleanupSubjectRequest) (identity.RequestIntent, identity.IdempotencyKey, error) {
	if (anonymous.SubjectQuery{TenantID: r.TenantID, UserID: r.UserID}).Validate() != nil {
		return identity.RequestIntent{}, identity.IdempotencyKey{}, anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.RunID)); err != nil {
		return identity.RequestIntent{}, identity.IdempotencyKey{}, anonymous.ErrInvalidInput
	}
	// CommandID's public contract requires server-random IDs, never IDs derived
	// from user data. Only the existing retry-key owner allocates that identity;
	// the fixed-width run and canonical subject merely namespace its lookup key.
	key, err := identity.NewIdempotencyKey([]byte("cleanup_" + string(r.RunID) + "_" + string(r.UserID)))
	if err != nil {
		return identity.RequestIntent{}, identity.IdempotencyKey{}, anonymous.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Request CleanupSubjectRequest
		Profile [32]byte
	}{r, s.profile})
	if err != nil {
		return identity.RequestIntent{}, identity.IdempotencyKey{}, anonymous.ErrInvalidInput
	}
	defer clear(frame)
	c := s.config()
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write(frame)
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	i, err := identity.NewRequestIntent([]identity.FeatureField{{Name: "cleanup.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
	return i, key, err
}

// CleanupSubject expires one exact subject with original per-run retry custody.
// Preparation/callbacks occur outside SQL; the existing coordinator alone owns
// reservation, commit, failure and reconciliation. A terminal retry does not
// reread a now-disposed subject, renew its deadline or perform disposal twice.
func (s *CleanupService) CleanupSubject(ctx context.Context, r CleanupSubjectRequest) (out CleanupItem, err error) {
	out.UserID = r.UserID
	if ctx == nil || s == nil || s.config == nil {
		return out, anonymous.ErrInvalidInput
	}
	intent, key, err := s.intent(r)
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			err = signinPublicError(ctx, err)
			if ctx.Err() == nil && out.Outcome == identity.CommitOutcomeUnknown && out.Recovery.CommandID != "" {
				err = identity.UnknownCommitError{CommandID: out.Recovery.CommandID}
			}
		}
	}()
	if err = s.allow(ctx, r.TenantID, string(r.UserID)); err != nil {
		return out, err
	}
	p := &cleanupPhase{service: s, request: r}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: s.config().ActorID, ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: expiryOperation().OperationID}
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, key, intent, s.caller(r.TenantID, "identity.request-admission", scope.RouteID), p.registration(), p)
	if err != nil {
		if p.deferred && ctx.Err() == nil {
			return out, identity.ForbiddenError{}
		}
		return out, err
	}
	defer clear(wire)
	if err = p.restore(ctx, k, wire, intent); err != nil {
		return out, err
	}
	b := p.input.Command.Binding
	out.Recovery, out.Outcome = deletionQuery(b), identity.CommitOutcomeUnknown
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	reservation, result, err := p.coordinator.ReserveCommand(ctx, b, p.command, plan)
	if result.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = result.Outcome
	}
	out.RetryAfter = result.RetryAfter
	if err != nil || reservation == (kernel.Reservation{}) {
		out.Replayed = err == nil && result.Outcome == identity.CommitOutcomeCommitted
		return out, err
	}
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		return out, err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	result, err = p.coordinator.ApplyFeature(ctx, w, p.command)
	if err != nil {
		result, err = p.coordinator.Abort(w, err)
	} else {
		result, err = p.coordinator.Commit(w, result)
	}
	if result.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = result.Outcome
	}
	out.RetryAfter = result.RetryAfter
	return out, err
}

// RecoverCleanup reconciles the original command under current service query
// policy. It restores authenticated input, never live guest authentication or
// retention admission; missing/corrupt history never establishes rollback.
func (s *CleanupService) RecoverCleanup(ctx context.Context, q identity.RecoveryQuery) (out CleanupItem, err error) {
	out.UserID = q.UserID
	if ctx == nil || s == nil || s.config == nil {
		return out, anonymous.ErrInvalidInput
	}
	if q.ActorID != s.config().ActorID || q.ActorKind != authorization.SubjectServiceAccount || q.OperationID != expiryOperation().OperationID || q.RecordID != string(q.UserID) || q.AnonymousFlowID != "" || q.LinkMode != 0 || (anonymous.SubjectQuery{TenantID: q.TenantID, UserID: q.UserID}).Validate() != nil {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil {
			err = signinPublicError(ctx, err)
		}
	}()
	p := &cleanupPhase{service: s}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return out, err
	}
	caller := s.caller(q.TenantID, "identity.user", string(q.UserID))
	k, wire, err := p.coordinator.QueryRequestPreparation(ctx, q, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restore(ctx, k, wire, identity.RequestIntent{}); err != nil || deletionQuery(p.input.Command.Binding) != q {
		return out, identity.ForbiddenError{}
	}
	out.Recovery, out.Replayed, out.Outcome = q, true, identity.CommitOutcomeUnknown
	result, err := p.coordinator.RecoverFeatureCommand(ctx, q, caller)
	if result.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = result.Outcome
	}
	out.RetryAfter = result.RetryAfter
	return out, err
}

func (*CleanupService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.CleanupService(redacted)"))
}
func (*CleanupService) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (CleanupConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.CleanupConfig(redacted)"))
}
func (CleanupConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (CleanupConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (CleanupItem) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.CleanupItem(redacted)"))
}
func (CleanupItem) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (CleanupResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.CleanupResult(redacted)"))
}
func (CleanupResult) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }

func cleanupDeferred(err error) bool {
	var denied identity.ForbiddenError
	return errors.As(err, &denied)
}
