package identity

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
)

// ProviderRevocationOutcome is an initial external-intent observation. Zero is
// invalid. Local commit never implies successful provider network revocation.
type ProviderRevocationOutcome uint8

const (
	ProviderRevocationNotRequested ProviderRevocationOutcome = iota + 1
	ProviderRevocationPending
)

// AccountUnlinkReceipt is the immutable local unlink admission. These positive
// next versions and the removed account's tombstone are persisted atomically.
// ProviderOutcome is initial pending/not-requested, not current external state.
type AccountUnlinkReceipt struct {
	AccountID                                                                    AccountID
	ExpectedAccountVersion, ExpectedSocialLinkVersion, ExpectedCredentialVersion uint64
	TombstoneVersion, SocialLinkVersion, CredentialVersion                       uint64
	InvalidatesCredential                                                        bool
	ProviderOutcome                                                              ProviderRevocationOutcome
}

func (r AccountUnlinkReceipt) valid() bool {
	if !validDirectoryID(string(r.AccountID)) || !unlinkVersion(r.ExpectedAccountVersion) || !unlinkVersion(r.ExpectedSocialLinkVersion) || !unlinkVersion(r.ExpectedCredentialVersion) || r.TombstoneVersion != r.ExpectedAccountVersion+1 || r.SocialLinkVersion != r.ExpectedSocialLinkVersion+1 || (r.ProviderOutcome != ProviderRevocationNotRequested && r.ProviderOutcome != ProviderRevocationPending) {
		return false
	}
	next := r.ExpectedCredentialVersion
	if r.InvalidatesCredential {
		next++
	}
	return r.CredentialVersion == next
}

// AccountUnlinkCommand is structural adapter input, not independently minted
// authority. Proof is the canonical authenticated capability grant. The trusted
// service verifies its configured authority first. The durable owner must check
// replay before CAS, revalidate time/session/credential/policy bindings under
// locks, reserve/finalize its single use with the mutation, repeat final-access
// eligibility and atomically write tombstone, audit, authority events, provider
// cleanup intent and original receipt. Never serialize a bearer into a receipt.
type AccountUnlinkCommand struct {
	Binding        CommandBinding
	Change         AccountUnlinkChange
	Proof          capability.Grant
	SessionID      string
	SessionVersion uint64
	RevokeProvider bool
}

// NewAccountUnlinkCommand freezes validated intent. Construction does not
// authorize or establish freshness; only trusted composition crosses UnitOfWork.
func NewAccountUnlinkCommand(s AccountUnlinkCommand) (Command, error) {
	if s.Binding.RecordID != string(s.Change.AccountID) {
		return Command{}, InvalidInputError{Field: "unlink_command"}
	}
	if !validCommandBinding(s.Binding) || s.Binding.OperationID != "identity.account.unlink" || s.Binding.SchemaID != "identity-account" || s.Binding.SchemaVersion != 1 || s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) || s.Change.TenantID != s.Binding.TenantID || s.Change.UserID != s.Binding.UserID || !validDirectoryID(string(s.Change.AccountID)) || !validDirectoryID(s.SessionID) || s.SessionVersion == 0 || !unlinkVersion(s.Change.ExpectedUserVersion) || !unlinkVersion(s.Change.ExpectedAccountVersion) || !unlinkVersion(s.Change.ExpectedSocialLinkVersion) || !unlinkVersion(s.Change.ExpectedCredentialVersion) {
		return Command{}, InvalidInputError{Field: "unlink_command"}
	}
	p := s.Proof.Payload()
	if !validDirectoryID(p.ID) || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || len(p.Caveats) != 9 || s.Proof.Authorize(capability.Use{Audience: p.Audiences[0], Subject: string(s.Binding.UserID), Tenant: string(s.Binding.TenantID), Resource: string(s.Change.AccountID), Operation: "identity.account.unlink", Caveats: unlinkCaveats(s)}) != nil {
		return Command{}, InvalidInputError{Field: "unlink_proof"}
	}
	return Command{unlink: &s}, nil
}

// UnlinkAccount returns an immutable adapter value copy for this variant only.
func (c Command) UnlinkAccount() (AccountUnlinkCommand, bool) {
	if c.unlink == nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.link != nil || c.identifier != nil {
		return AccountUnlinkCommand{}, false
	}
	return *c.unlink, true
}

func unlinkCaveats(s AccountUnlinkCommand) map[string]string {
	return map[string]string{
		"revoke_provider": strconv.FormatBool(s.RevokeProvider),
		"command_id":      string(s.Binding.CommandID), "session_id": s.SessionID, "session_version": strconv.FormatUint(s.SessionVersion, 10), "user_version": strconv.FormatUint(s.Change.ExpectedUserVersion, 10), "account_version": strconv.FormatUint(s.Change.ExpectedAccountVersion, 10), "social_link_version": strconv.FormatUint(s.Change.ExpectedSocialLinkVersion, 10), "credential_version": strconv.FormatUint(s.Change.ExpectedCredentialVersion, 10), "policy_version": strconv.FormatUint(s.Binding.PolicyVersion, 10)}
}

// AccountUnlinkQuery is an exact bounded consistent primary partition read.
// It must include tombstone social-link authority after removal for replay.
type AccountUnlinkQuery struct {
	TenantID  TenantID
	UserID    UserID
	AccountID AccountID
}

// AccountUnlinkRepository owns primary user/account/eligibility snapshots and
// tombstones, not provider network work. Implementations honor bounded contexts
// and concurrent calls. ErrUserAbsent has no public enumeration distinction.
type AccountUnlinkRepository interface {
	GetAccountUnlinkState(context.Context, AccountUnlinkQuery) (AccountUnlinkState, error)
}

// AccountUnlinkRequest is trusted core input, not a public JSON shape. Session
// and actor bindings come from authenticated composition, never caller claims.
// Retain command/change/session/proof/provider choice across retries.
type AccountUnlinkRequest struct {
	CommandID      CommandID
	Change         AccountUnlinkChange
	SessionID      string
	SessionVersion uint64
	Proof          capability.Proof
	RevokeProvider bool
	ActorScope     authorization.DecisionContext
	CorrelationID  string
}

// AccountUnlinkRecoveryRequest grants no continuation authority by ID alone.
// Current exact subject policy governs disclosure of the original receipt.
type AccountUnlinkRecoveryRequest struct {
	CommandID  CommandID
	TenantID   TenantID
	UserID     UserID
	AccountID  AccountID
	ActorScope authorization.DecisionContext
}

// AccountUnlinkResult distinguishes durable observation from permitted output.
// Unknown/withheld output carries no version/provider success. Committed remains
// committed even when cancellation or redaction withholds its projection.
type AccountUnlinkResult struct {
	CommandID       CommandID
	CommitOutcome   CommitOutcome
	Version         uint64
	ProviderOutcome ProviderRevocationOutcome
}

// AccountUnlinkConfig pins a single trusted capability issuer and audience.
// MaximumProofAge is positive and at most fifteen minutes; no implicit defaults.
type AccountUnlinkConfig struct {
	Query                      UserQueryConfig
	ProofIssuer, ProofAudience string
	MaximumProofAge            time.Duration
}

// AccountUnlinkService owns core admission, scoped recovery and observation.
// It owns no store, transaction, locks, goroutines or provider I/O. Dependencies
// are trusted composition capabilities and must honor concurrent bounded calls.
type AccountUnlinkService struct {
	repo   AccountUnlinkRepository
	uow    UnitOfWork
	caps   capability.Service
	policy *AccountService
	config AccountUnlinkConfig
}

// NewAccountUnlinkService validates dependencies/configuration without I/O.
func NewAccountUnlinkService(repo AccountUnlinkRepository, uow UnitOfWork, auth authorization.Service, redact RedactFunc, caps capability.Service, config AccountUnlinkConfig) (*AccountUnlinkService, error) {
	if nilDependency(repo) || nilDependency(uow) || nilDependency(caps) || !validClaimIssuer(config.ProofIssuer) || !validDirectoryID(config.ProofAudience) || config.MaximumProofAge <= 0 || config.MaximumProofAge > 15*time.Minute {
		return nil, InvalidInputError{Field: "unlink_configuration"}
	}
	p, e := newQueryPolicy(auth, redact, config.Query)
	if e != nil {
		return nil, e
	}
	return &AccountUnlinkService{repo: repo, uow: uow, caps: caps, policy: &AccountService{policy: p}, config: config}, nil
}

// AccountUnlink verifies exact one-use capability bindings and current primary
// admission, then delegates replay/CAS and atomic effects to the sole UnitOfWork.
// Signature validation never consumes the proof. Only same-command replay may
// pass older expected versions; the durable owner rejects new stale commands.
func (s *AccountUnlinkService) AccountUnlink(ctx context.Context, r AccountUnlinkRequest) (out AccountUnlinkResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.Version = 0
			out.ProviderOutcome = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{r.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "unlink_context"}
	}
	if r.CorrelationID == "" {
		r.CorrelationID = string(r.CommandID)
	}
	b := CommandBinding{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: "identity.account.unlink", PolicyID: s.config.Query.PolicyID, PolicyVersion: s.config.Query.PolicyVersion, SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: r.CorrelationID}
	b.RecordID = string(r.Change.AccountID)
	if !validCommandBinding(b) {
		return out, InvalidInputError{Field: "unlink_binding"}
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, now, e := s.admit(ctx, r.Change.TenantID, r.Change.UserID, r.Change.AccountID, r.ActorScope, false)
	if e != nil {
		return out, e
	}
	g, e := s.caps.Verify(ctx, r.Proof, "identity.account.unlink", s.config.ProofAudience)
	if ce := readContextError(ctx); ce != nil {
		return out, ce
	}
	if e != nil {
		return out, ForbiddenError{}
	}
	p := g.Payload()
	if p.Issuer != s.config.ProofIssuer || len(p.Audiences) != 1 || p.Audiences[0] != s.config.ProofAudience || p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || now.Before(p.IssuedAt) || now.Before(p.NotBefore) || !now.Before(p.ExpiresAt) || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > s.config.MaximumProofAge || now.Sub(p.IssuedAt) >= s.config.MaximumProofAge {
		return out, ForbiddenError{}
	}
	command, e := NewAccountUnlinkCommand(AccountUnlinkCommand{Binding: b, Change: r.Change, Proof: g, SessionID: r.SessionID, SessionVersion: r.SessionVersion, RevokeProvider: r.RevokeProvider})
	if e != nil {
		return out, ForbiddenError{}
	}
	state, e := s.repo.GetAccountUnlinkState(ctx, AccountUnlinkQuery{r.Change.TenantID, r.Change.UserID, r.Change.AccountID})
	if ce := readContextError(ctx); ce != nil {
		return out, ce
	}
	if e != nil {
		if errors.Is(e, ErrUserAbsent) {
			return out, ForbiddenError{}
		}
		return out, UnavailableError{}
	}
	if state.AccountID != r.Change.AccountID || !(AccountSnapshot{User: state.Access.User, Accounts: state.Access.Accounts}).valid(r.Change.TenantID, r.Change.UserID) || !unlinkVersion(state.CredentialVersion) || !unlinkVersion(state.SocialLinkVersion) {
		return out, UnavailableError{}
	}
	if !state.Access.User.Status.AllowsAuthentication() {
		return out, ForbiddenError{}
	}
	if r.Change.ExpectedUserVersion > state.Access.User.Version || r.Change.ExpectedSocialLinkVersion > state.SocialLinkVersion || r.Change.ExpectedCredentialVersion > state.CredentialVersion {
		return out, ConflictError{r.CommandID}
	}
	if r.Change.ExpectedUserVersion == state.Access.User.Version {
		if _, e := ApplyAccountUnlink(state, r.Change, now); e != nil {
			return out, e
		}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(state.Access.User.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(state.Access.User.Version, 10))
	dc.Request.Resource.Attributes["identity.account.id"] = authorization.StringValue(string(r.Change.AccountID))
	dc.Request.Resource.Attributes["identity.account.social-link-version"] = authorization.StringValue(strconv.FormatUint(state.SocialLinkVersion, 10))
	dc.Request.Resource.Attributes["identity.account.credential-version"] = authorization.StringValue(strconv.FormatUint(state.CredentialVersion, 10))
	if e := s.policy.allow(ctx, dc); e != nil {
		return out, e
	}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Execute(ctx, command)
	if !receipt.valid() || receipt.Binding != b || receipt.Outcome == CommitOutcomeCommitted && (receipt.ExpectedVersion != r.Change.ExpectedUserVersion || receipt.Unlink.AccountID != r.Change.AccountID || receipt.Unlink.ExpectedAccountVersion != r.Change.ExpectedAccountVersion || receipt.Unlink.ExpectedSocialLinkVersion != r.Change.ExpectedSocialLinkVersion || receipt.Unlink.ExpectedCredentialVersion != r.Change.ExpectedCredentialVersion || (receipt.Unlink.ProviderOutcome == ProviderRevocationPending) != r.RevokeProvider) {
		return out, unknownError(ctx, r.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, e, dc)
}

// RecoverAccountUnlink performs only scoped primary recovery; no proof is
// consumed, account changed, new command allocated or provider call made.
func (s *AccountUnlinkService) RecoverAccountUnlink(ctx context.Context, r AccountUnlinkRecoveryRequest) (out AccountUnlinkResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.Version = 0
			out.ProviderOutcome = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{r.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "unlink_context"}
	}
	if _, ok := decodeID(string(r.CommandID)); !ok || !validDirectoryID(string(r.AccountID)) {
		return out, InvalidInputError{Field: "unlink_recovery"}
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, _, e := s.admit(ctx, r.TenantID, r.UserID, r.AccountID, r.ActorScope, true)
	if e != nil {
		return out, e
	}
	q := RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: "identity.account.unlink", RecordID: string(r.AccountID)}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Recover(ctx, q)
	if !receipt.valid() || receipt.Binding.OperationID != q.OperationID || receipt.Binding.RecordID != q.RecordID || receipt.Binding.CommandID != q.CommandID || receipt.Binding.TenantID != q.TenantID || receipt.Binding.UserID != q.UserID || receipt.Binding.ActorID != q.ActorID || receipt.Binding.ActorKind != q.ActorKind || receipt.Outcome == CommitOutcomeCommitted && receipt.Unlink.AccountID != r.AccountID {
		return out, unknownError(ctx, r.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, e, dc)
}

func (s *AccountUnlinkService) admit(ctx context.Context, tenant TenantID, user UserID, account AccountID, scope authorization.DecisionContext, recovery bool) (authorization.DecisionContext, time.Time, error) {
	zero := authorization.DecisionContext{}
	if scope.Request.Subject.Kind != authorization.SubjectUser || string(scope.Request.Subject.ID) != string(user) {
		return zero, time.Time{}, ForbiddenError{}
	}
	if e := validateQueryContext(scope, tenant, string(user), "identity.account.unlink", "identity.user", s.config.Query.PolicyVersion); e != nil {
		return zero, time.Time{}, e
	}
	if e := readContextError(ctx); e != nil {
		return zero, time.Time{}, e
	}
	if e := s.config.Query.ValidateCanonicalUserID(ctx, user); e != nil {
		if ce := readContextError(ctx); ce != nil {
			return zero, time.Time{}, ce
		}
		return zero, time.Time{}, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return zero, time.Time{}, e
	}
	now := s.config.Query.Clock.Now()
	if now.IsZero() {
		return zero, time.Time{}, UnavailableError{}
	}
	dc := scope.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for key := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(key), "identity.") {
			delete(dc.Request.Resource.Attributes, key)
		}
	}
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(recovery)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(!recovery)
	dc.Request.Resource.Attributes["identity.account.id"] = authorization.StringValue(string(account))
	if e := s.policy.allow(ctx, dc); e != nil {
		return zero, time.Time{}, e
	}
	return dc, now, nil
}

func (s *AccountUnlinkService) finish(ctx context.Context, out AccountUnlinkResult, r CommandResult, e error, dc authorization.DecisionContext) (AccountUnlinkResult, error) {
	projection := &UserCreationService{policy: s.policy.policy}
	_, err := projection.finish(ctx, UserCreateResult{CommandID: out.CommandID, CommitOutcome: out.CommitOutcome}, r, e, dc)
	if err != nil {
		return out, err
	}
	out.Version = r.User.Version
	out.ProviderOutcome = r.Unlink.ProviderOutcome
	return out, nil
}
