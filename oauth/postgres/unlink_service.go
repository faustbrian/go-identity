package postgres

import (
	"context"
	"fmt"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const accountUnlinkOperation = "identity.account.unlink"

// UnlinkRequest is trusted native input, not an HTTP request body. ActorScope,
// Session and Network come from the authenticated transport. The optimistic
// account and known-empty factor versions select the original authorized
// intent; use the exact same values, proof, session and command ID on a retry.
// Remote provider revocation is not part of this local unlink profile.
type UnlinkRequest struct {
	CommandID              identity.CommandID
	Change                 identity.AccountUnlinkChange
	Session                auth.BearerCredential
	CSRF                   session.CSRFToken
	Primary                auth.ReauthenticationProof
	ActorScope             authorization.DecisionContext
	FactorAuthorityVersion uint64
	Network, CorrelationID string
}

func (UnlinkRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.UnlinkRequest(redacted)"))
}

func (UnlinkRequest) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "oauth_unlink_request"}
}

func (r UnlinkRequest) MarshalText() ([]byte, error) { return r.MarshalJSON() }

// UnlinkService is the explicit self-user, fresh-password unlink profile.
// It borrows an existing native OAuth owner and the same primary password
// owner. It starts no background processes, HTTP routes, migrations or
// provider network requests. Each call uses an independent native phase.
type UnlinkService struct {
	link    *LinkService
	primary *passwordpg.AccountUnlinkPrimarySource
	config  identity.AccountUnlinkConfig
	redact  identity.RedactFunc
}

// NewUnlinkService selects local account and encrypted token erasure. Install
// the corresponding unlink preparation, risk-alias and password-consumption
// histories before invoking the service. Existing link/signin constructors
// do not select unlink by default. All dependencies are borrowed.
func NewUnlinkService(link *LinkService, primary *passwordpg.AccountUnlinkPrimarySource, query identity.UserQueryConfig, redact identity.RedactFunc) (*UnlinkService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_unlink_configuration"}
	if link == nil || link.config == nil {
		return nil, invalid
	}
	c := link.config()
	if c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy == nil ||
		query.PolicyID != c.PolicyID || query.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion ||
		query.MaximumDuration > c.MaximumDuration ||
		!primary.MatchesAccountUnlinkSource(link.pool, c.Session, query.PolicyVersion) {
		return nil, invalid
	}
	query.RedactionReasons = slices.Clone(query.RedactionReasons)
	s := &UnlinkService{link: link, primary: primary, redact: redact, config: identity.AccountUnlinkConfig{
		Query: query, ProofIssuer: c.Capability.Crypto.Issuer, ProofAudience: c.Capability.Audience, MaximumProofAge: 20 * time.Second,
	}}
	if _, err := s.core(link.directory, kernel.PreparedAccountUnlink{}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *UnlinkService) core(repo identity.AccountUnlinkRepository, prepared kernel.PreparedAccountUnlink) (*identity.AccountUnlinkService, error) {
	return identity.NewPreparedAccountUnlinkService(repo, prepared, s.link.config().Coordinator.AdmissionPolicy.Authorization, s.redact, s.config)
}

func (s *UnlinkService) binding(id identity.CommandID, tenant identity.TenantID, user identity.UserID, account identity.AccountID, scope authorization.DecisionContext, correlation string) identity.CommandBinding {
	if correlation == "" {
		correlation = string(id)
	}
	return identity.CommandBinding{
		CommandID: id, TenantID: tenant, UserID: user, ActorID: identity.ActorID(scope.Request.Subject.ID), ActorKind: scope.Request.Subject.Kind,
		OperationID: accountUnlinkOperation, SchemaID: "identity-account", SchemaVersion: 1,
		PolicyID: s.config.Query.PolicyID, PolicyVersion: s.config.Query.PolicyVersion, RecordID: string(account), CorrelationID: correlation,
	}
}

func (s *UnlinkService) coordinator(phase *rpUnlinkPhase) (*kernel.AccountUnlinkUnitOfWork, []kernel.ContributorDescriptor, error) {
	link := s.link
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{link.directory, auditing, lifecycle, capabilitypg.NewParticipant(), link.counters, phase, link.issuer})
	if err != nil {
		return nil, nil, err
	}
	c := link.config()
	coordinator, err := kernel.NewCoordinator(link.pool, registry, c.Coordinator)
	if err != nil {
		return nil, nil, err
	}
	uow, err := kernel.NewAccountUnlinkUnitOfWork(coordinator, link.directory, kernel.AccountUnlinkUnitOfWorkConfig{RetentionPolicyVersion: c.AuditRetentionPolicyVersion})
	if err != nil {
		return nil, nil, err
	}
	return uow, registry.Descriptors()[:6], nil
}

// Unlink removes one linked social account, invalidates dependent credentials
// and erases encrypted local provider custody in the sole PostgreSQL commit.
// The verified password must actually remain usable and the original factor
// generation must still be known-empty. The source password proof is consumed
// only in that same commit. It neither remotely revokes nor returns tokens.
func (s *UnlinkService) Unlink(ctx context.Context, r UnlinkRequest) (out identity.AccountUnlinkResult, err error) {
	if s == nil || s.link == nil || ctx == nil {
		return out, identity.InvalidInputError{Field: "oauth_unlink_request"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer stop()
	b := s.binding(r.CommandID, r.Change.TenantID, r.Change.UserID, r.Change.AccountID, r.ActorScope, r.CorrelationID)
	if b.ActorKind != authorization.SubjectUser || b.UserID == "" || string(b.ActorID) != string(b.UserID) {
		return out, identity.ForbiddenError{}
	}
	out.CommandID = b.CommandID
	// The signed primary's issuance time is stable across exact retries.
	// Current authority and actual DB freshness are checked again by Work.
	at := r.Primary.Proof.IssuedAt.UTC()
	if at.IsZero() || at.Nanosecond() != 0 {
		return out, identity.ForbiddenError{}
	}
	link := s.link
	c := link.config()
	versions, found, err := link.counters.OriginalAccountUnlinkCounterKeys(ctx, link.pool, b, at, c.Session.Repository.MaximumDuration)
	if err != nil {
		return out, err
	}
	input := identity.AccountUnlinkPreparationCommand{Binding: b, Change: r.Change, SessionID: r.Primary.SessionID,
		SessionVersion: r.Primary.SessionVersion, Primary: r.Primary, FactorAuthorityVersion: r.FactorAuthorityVersion}
	if r.CSRF != (session.CSRFToken{}) {
		// Keep the cookie synchronizer bound to exact request replay. This
		// digest cannot replace the primary owner's actual session-bound check.
		custody, err := r.CSRF.Digest(link.intentCSRF, session.CSRFBinding{TenantID: b.TenantID, SessionID: "oauth-unlink-intent-v1", SessionVersion: 1})
		if err != nil {
			return out, identity.ForbiddenError{}
		}
		digest, err := custody.Bindings()
		if err != nil {
			return out, identity.ForbiddenError{}
		}
		input.CSRFCommitment = digest.Digest
	}
	attribution := risk.Subject{User: string(b.UserID), Session: input.SessionID, Network: r.Network}
	var original identity.Command
	var counter kernel.CommandCounterPlan
	if found {
		original, counter, err = link.counters.PrepareAccountUnlinkPreparationCountersWithRetainedKeys(input, r.Session, attribution, at, versions)
	} else {
		original, counter, err = link.counters.PrepareAccountUnlinkPreparationCounters(input, r.Session, attribution, at)
	}
	if err != nil {
		return out, err
	}
	primary, admissionErr := s.primary.Prepare(ctx, original, r.ActorScope, r.CSRF)
	phase := &rpUnlinkPhase{service: link, original: original, primary: primary, admissionErr: admissionErr}
	if phase.admissionErr == nil {
		phase.password, phase.admissionErr = primary.RemainingPassword(ctx)
	}
	uow, owners, err := s.coordinator(phase)
	if err != nil {
		return out, err
	}
	audits, err := kernel.AccountUnlinkAudits(ctx, original, c.AuditRetentionPolicyVersion)
	if err != nil {
		return out, err
	}
	phase.declaration = kernel.CommandPlan{
		Contributors: owners, Audits: audits, CommandCounters: &counter,
		Lifecycle: &kernel.LifecyclePlan{EventType: "social_provider.unlinked.v1", BeforeVersion: r.Change.ExpectedAccountVersion, AfterVersion: r.Change.ExpectedAccountVersion + 1},
	}
	prepared, err := uow.PrepareUnlink(ctx, original, phase.declaration)
	if err != nil {
		if result, ok := prepared.Observation(); ok {
			out.CommitOutcome = result.Outcome
		}
		return out, err
	}
	if _, observed := prepared.Observation(); observed {
		service, err := s.core(link.directory, prepared)
		if err != nil {
			return out, err
		}
		return service.RecoverAccountUnlink(ctx, identity.AccountUnlinkRecoveryRequest{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AccountID: r.Change.AccountID, ActorScope: r.ActorScope})
	}
	intent, ready := prepared.Intent()
	if !ready {
		out.CommitOutcome = identity.CommitOutcomeUnknown
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	service, err := s.core(unlinkAccessRepository{directory: link.directory, ref: phase.password}, prepared)
	if err != nil {
		return out, err
	}
	return service.AccountUnlinkPrepared(ctx, identity.PreparedAccountUnlinkRequest{Command: intent, ActorScope: r.ActorScope})
}

// Recover reports only the exact original scoped outcome under current core
// authorization. It can reconcile expired pending work without possessing an
// expired password proof; it never makes that command executable again.
func (s *UnlinkService) Recover(ctx context.Context, r identity.AccountUnlinkRecoveryRequest) (identity.AccountUnlinkResult, error) {
	if s == nil || s.link == nil || ctx == nil {
		return identity.AccountUnlinkResult{}, identity.InvalidInputError{Field: "oauth_unlink_recovery"}
	}
	b := s.binding(r.CommandID, r.TenantID, r.UserID, r.AccountID, r.ActorScope, "")
	uow, _, err := s.coordinator(&rpUnlinkPhase{service: s.link})
	if err != nil {
		return identity.AccountUnlinkResult{}, err
	}
	observed, err := uow.RecoveryHandle(b)
	if err != nil {
		return identity.AccountUnlinkResult{}, err
	}
	service, err := s.core(s.link.directory, observed)
	if err != nil {
		return identity.AccountUnlinkResult{}, err
	}
	return service.RecoverAccountUnlink(ctx, r)
}

type unlinkAccessRepository struct {
	directory *kernel.Repository
	ref       identity.CredentialRef
}

func (r unlinkAccessRepository) GetAccountUnlinkState(ctx context.Context, q identity.AccountUnlinkQuery) (identity.AccountUnlinkState, error) {
	state, err := r.directory.GetAccountUnlinkState(ctx, q)
	if err != nil {
		return identity.AccountUnlinkState{}, err
	}
	markIndependentUnlinkPassword(state.Access.Methods, r.ref)
	return state, nil
}
