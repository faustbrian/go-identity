package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
)

// AccountLinkCommand is frozen structural intent for the sole durable owner.
// Proof is the canonical verified capability grant, not caller proof material.
// Trusted feature composition independently verifies registered provider subject,
// canonical verified claims and actor session/consent (or implicit pre-auth
// mapping) before issuance by the configured identity authority. This command
// and its constructor do not mint that authority. The adapter must repeat fresh
// time, provider enablement, policy/session/identifier and one-use checks under
// locks, then atomically consume proof/risk with all mutation participants.
type AccountLinkCommand struct {
	Binding              CommandBinding
	Change               AccountLinkChange
	Proof                capability.Grant
	SessionID            string
	SessionVersion       uint64
	PreAuthTransactionID PreAuthTransactionID
}

func validLinkActor(mode AccountLinkMode, kind authorization.SubjectKind, actor ActorID, user UserID) bool {
	switch mode {
	case AccountLinkExplicit:
		return kind == authorization.SubjectUser && string(actor) == string(user)
	case AccountLinkImplicit:
		return kind == authorization.SubjectServiceAccount
	case AccountLinkAdministrative:
		return kind == authorization.SubjectUser
	default:
		return false
	}
}

func validLinkContinuation(s AccountLinkCommand) bool {
	if s.Change.Mode == AccountLinkImplicit {
		_, e := ParsePreAuthTransactionID(string(s.PreAuthTransactionID))
		return e == nil && s.SessionID == "" && s.SessionVersion == 0
	}
	return s.PreAuthTransactionID == "" && validDirectoryID(s.SessionID) && s.SessionVersion > 0
}

func validLinkCommandShape(s AccountLinkCommand) bool {
	return validCommandBinding(s.Binding) && s.Binding.RecordID == string(s.Change.Account.ID) && s.Binding.LinkMode == s.Change.Mode && s.Binding.OperationID == "identity.account.link-token" && s.Binding.SchemaID == "identity-account" && s.Binding.SchemaVersion == 1 && s.Change.valid() && s.Change.Account.TenantID == s.Binding.TenantID && s.Change.Account.UserID == s.Binding.UserID && validLinkActor(s.Change.Mode, s.Binding.ActorKind, s.Binding.ActorID, s.Binding.UserID) && validLinkContinuation(s)
}

// NewAccountLinkCommand snapshots validated intent. It grants no authority,
// canonicalization, provider verification, freshness or database transaction.
func NewAccountLinkCommand(s AccountLinkCommand) (Command, error) {
	if !validLinkCommandShape(s) {
		return Command{}, InvalidInputError{Field: "link_command"}
	}
	p := s.Proof.Payload()
	if !validDirectoryID(p.ID) || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || len(p.Caveats) != 8 || s.Proof.Authorize(capability.Use{Issuer: p.Issuer, Audience: p.Audiences[0], Subject: string(s.Binding.UserID), Tenant: string(s.Binding.TenantID), Resource: string(s.Change.Account.ID), Operation: "identity.account.link-token", Caveats: linkCaveats(s)}) != nil {
		return Command{}, InvalidInputError{Field: "link_proof"}
	}
	s.Change = cloneLinkChange(s.Change)
	return Command{link: &s}, nil
}

// Format redacts the entire structural proof/command envelope.
func (AccountLinkCommand) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.AccountLinkCommand(redacted)")
}

// AccountLinkProofSpec is bounded unsigned issuance intent, not verified
// evidence. Command.Proof must be zero. Its issuer/ID/time and exact actor/
// provider/identifier/continuation bindings come from trusted feature ceremony
// composition, never caller assertions or matching profile email alone.
type AccountLinkProofSpec struct {
	Command   AccountLinkCommand
	Issuer    string
	Audience  string
	ID        string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// BuildAccountLinkProofPayload owns the canonical eight-caveat issuance shape
// so feature packages need not reconstruct its binding protocol. It performs
// no signing, authorization, provider verification or clock read. Only a
// configured trusted capability signer may issue it after actual proof and
// policy checks. Time is second-precision UTC, expiry exclusive and no more
// than five minutes after issuance. The returned payload/map is caller-owned;
// never log it or confuse a constructed payload with a signed grant.
func BuildAccountLinkProofPayload(s AccountLinkProofSpec) (capability.Payload, error) {
	if !validLinkCommandShape(s.Command) || s.Command.Proof.Payload().ID != "" || !validClaimIssuer(s.Issuer) || len(s.Issuer) > 256 || !validDirectoryID(s.Audience) || !validDirectoryID(s.ID) || s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || s.IssuedAt.UTC().Year() < 1 || s.ExpiresAt.UTC().Year() > 9999 || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > 5*time.Minute {
		return capability.Payload{}, InvalidInputError{Field: "link_proof_spec"}
	}
	return capability.Payload{Version: 1, Issuer: s.Issuer, Audiences: []string{s.Audience}, Subject: string(s.Command.Binding.UserID), Resource: string(s.Command.Change.Account.ID), Operation: "identity.account.link-token", Tenant: string(s.Command.Binding.TenantID), ID: s.ID, MaxUses: 1, IssuedAt: s.IssuedAt.UTC(), NotBefore: s.IssuedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(), Caveats: linkCaveats(s.Command)}, nil
}

// LinkAccount returns an independent typed adapter copy for this variant only.
func (c Command) LinkAccount() (AccountLinkCommand, bool) {
	if c.link == nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.identifier != nil || c.feature != nil || c.privacy != nil {
		return AccountLinkCommand{}, false
	}
	s := *c.link
	s.Change = cloneLinkChange(s.Change)
	return s, true
}

func linkCaveats(s AccountLinkCommand) map[string]string {
	digest, _ := AccountLinkIntentDigest(s.Change)
	return map[string]string{"intent_digest": hex.EncodeToString(digest[:]), "command_id": string(s.Binding.CommandID), "actor_id": string(s.Binding.ActorID), "actor_kind": string(s.Binding.ActorKind), "session_id": linkPresence(s.SessionID), "session_version": strconv.FormatUint(s.SessionVersion, 10), "pre_auth_id": linkPresence(string(s.PreAuthTransactionID)), "policy_version": strconv.FormatUint(s.Binding.PolicyVersion, 10)}
}

func linkPresence(value string) string {
	if value == "" {
		return "absent"
	}
	return "present:" + value
}

// AccountLinkReceipt is immutable local admission metadata. It is not provider
// network success, current authentication authority or lifecycle acknowledgement.
type AccountLinkReceipt struct {
	AccountID                 AccountID
	Mode                      AccountLinkMode
	ExpectedAccountVersion    uint64
	ExpectedSocialLinkVersion uint64
	ExpectedCredentialVersion uint64
	AccountVersion            uint64
	SocialLinkVersion         uint64
	CredentialVersion         uint64
	AddsCredential            bool
}

func (r AccountLinkReceipt) valid() bool {
	if !validDirectoryID(string(r.AccountID)) || r.Mode < AccountLinkExplicit || r.Mode > AccountLinkAdministrative || r.ExpectedAccountVersion == ^uint64(0) || !unlinkVersion(r.ExpectedSocialLinkVersion) || !unlinkVersion(r.ExpectedCredentialVersion) || r.AccountVersion != r.ExpectedAccountVersion+1 || r.SocialLinkVersion != r.ExpectedSocialLinkVersion+1 {
		return false
	}
	next := r.ExpectedCredentialVersion
	if r.AddsCredential {
		next++
	}
	return r.CredentialVersion == next
}

// AccountLinkQuery binds a complete primary lookup to exact candidate metadata.
// Repositories retain record/tombstone and subject-key authority after unlink;
// they never treat absence from a user's account list as tenant-wide absence.
type AccountLinkQuery struct {
	Account Account
	Mode    AccountLinkMode
}

// AccountLinkRepository owns bounded consistent primary reads, including exact
// tenant/provider/issuer/subject collision, tombstone and implicit identifier
// authority. It must honor concurrent bounded contexts; no provider I/O occurs.
type AccountLinkRepository interface {
	GetAccountLinkState(context.Context, AccountLinkQuery) (AccountLinkState, error)
}

// AccountLinkRequest is trusted core composition input, never HTTP JSON or a
// caller claim of verified provider email/freshness. Preserve it across retries.
// Proof is purpose/target/actor/command/continuation-bound signed one-use evidence
// issued only after the feature's actual proof ceremony and admitted policy.
type AccountLinkRequest struct {
	CommandID            CommandID
	Change               AccountLinkChange
	Proof                capability.Proof
	SessionID            string
	SessionVersion       uint64
	PreAuthTransactionID PreAuthTransactionID
	ActorScope           authorization.DecisionContext
	CorrelationID        string
}

// AccountLinkRecoveryRequest grants no access merely by possession of an ID.
// Current policy must authorize the original target/account/mode/actor scope.
type AccountLinkRecoveryRequest struct {
	CommandID  CommandID
	TenantID   TenantID
	UserID     UserID
	AccountID  AccountID
	Mode       AccountLinkMode
	ActorScope authorization.DecisionContext
}

// AccountLinkResult conserves the authoritative commit observation. Known
// commitment remains known when output is withheld. Unknown carries no claimed
// record/version success and is recovered, not silently retried under a new ID.
type AccountLinkResult struct {
	CommandID     CommandID
	CommitOutcome CommitOutcome
	AccountID     AccountID
	Version       uint64
}

// AccountLinkConfig freezes exact proof authority and opt-in policy paths.
// MaximumProofAge is positive and at most five minutes. Administrative reasons
// are 1..32 unique safe registered tokens when enabled, absent when disabled.
// Implicit linking requires one exact trusted workload actor ID; enabling a
// mode or naming an actor never grants authorization or verified provider proof.
type AccountLinkConfig struct {
	Query                 UserQueryConfig
	ProofIssuer           string
	ProofAudience         string
	MaximumProofAge       time.Duration
	AllowAdministrative   bool
	AdministrativeReasons []PolicyReason
	AllowImplicit         bool
	ImplicitActorID       ActorID
}

// AccountLinkService owns identity admission/recovery, not provider ceremonies,
// tokens, transactions, goroutines or a second link store. Dependencies are
// trusted composition capabilities and must honor bounded concurrent calls.
type AccountLinkService struct {
	repo   AccountLinkRepository
	uow    UnitOfWork
	caps   capability.Service
	policy *AccountService
	config AccountLinkConfig
}

// NewAccountLinkService validates and copies configuration without external I/O.
func NewAccountLinkService(repo AccountLinkRepository, uow UnitOfWork, auth authorization.Service, redact RedactFunc, caps capability.Service, c AccountLinkConfig) (*AccountLinkService, error) {
	if nilDependency(repo) || nilDependency(uow) || nilDependency(caps) || !validClaimIssuer(c.ProofIssuer) || !validDirectoryID(c.ProofAudience) || c.MaximumProofAge <= 0 || c.MaximumProofAge > 5*time.Minute || c.AllowImplicit && !validDirectoryID(string(c.ImplicitActorID)) || !c.AllowImplicit && c.ImplicitActorID != "" || c.AllowAdministrative && (len(c.AdministrativeReasons) == 0 || len(c.AdministrativeReasons) > 32) || !c.AllowAdministrative && len(c.AdministrativeReasons) != 0 {
		return nil, InvalidInputError{Field: "link_configuration"}
	}
	for j, r := range c.AdministrativeReasons {
		if !validDirectoryID(string(r)) || slices.Contains(c.AdministrativeReasons[:j], r) {
			return nil, InvalidInputError{Field: "link_reasons"}
		}
	}
	c.AdministrativeReasons = slices.Clone(c.AdministrativeReasons)
	p, e := newQueryPolicy(auth, redact, c.Query)
	if e != nil {
		return nil, e
	}
	return &AccountLinkService{repo: repo, uow: uow, caps: caps, policy: &AccountService{policy: p}, config: c}, nil
}

// AccountLink verifies signed intent before primary lookup and delegates exact
// same-command replay/CAS/atomic effects to the sole UnitOfWork. Verify never
// consumes the capability. Primary lookup is admission only; the durable owner
// repeats authoritative collision, eligibility, proof and policy checks under
// its shared lock/unique-index boundary before applying any state.
func (s *AccountLinkService) AccountLink(ctx context.Context, r AccountLinkRequest) (out AccountLinkResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.AccountID = ""
			out.Version = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{r.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "link_context"}
	}
	r.Change = cloneLinkChange(r.Change)
	if r.CorrelationID == "" {
		r.CorrelationID = string(r.CommandID)
	}
	b := CommandBinding{CommandID: r.CommandID, TenantID: r.Change.Account.TenantID, UserID: r.Change.Account.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: "identity.account.link-token", PolicyID: s.config.Query.PolicyID, PolicyVersion: s.config.Query.PolicyVersion, SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: r.CorrelationID}
	b.RecordID, b.LinkMode = string(r.Change.Account.ID), r.Change.Mode
	if !validCommandBinding(b) || !r.Change.valid() {
		return out, InvalidInputError{Field: "link_binding"}
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, now, e := s.admit(ctx, b.TenantID, b.UserID, r.Change.Account.ID, r.Change.Mode, r.ActorScope, false)
	if e != nil {
		return out, e
	}
	if r.Change.Mode == AccountLinkAdministrative && !slices.Contains(s.config.AdministrativeReasons, r.Change.Reason) {
		return out, ForbiddenError{}
	}
	g, e := s.caps.Verify(ctx, r.Proof, "identity.account.link-token", s.config.ProofAudience)
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
	command, e := NewAccountLinkCommand(AccountLinkCommand{Binding: b, Change: r.Change, Proof: g, SessionID: r.SessionID, SessionVersion: r.SessionVersion, PreAuthTransactionID: r.PreAuthTransactionID})
	if e != nil {
		return out, ForbiddenError{}
	}
	state, e := s.repo.GetAccountLinkState(ctx, AccountLinkQuery{Account: r.Change.Account, Mode: r.Change.Mode})
	if ce := readContextError(ctx); ce != nil {
		return out, ce
	}
	if e != nil {
		if errors.Is(e, ErrUserAbsent) {
			return out, ForbiddenError{}
		}
		return out, UnavailableError{}
	}
	if !state.valid(r.Change, now) {
		return out, UnavailableError{}
	}
	if !state.Access.User.Status.AllowsAuthentication() {
		return out, ForbiddenError{}
	}
	if r.Change.ExpectedUserVersion > state.Access.User.Version || r.Change.ExpectedAccountVersion > state.RecordVersion || r.Change.ExpectedSocialLinkVersion > state.SocialLinkVersion || r.Change.ExpectedCredentialVersion > state.CredentialVersion {
		return out, ConflictError{r.CommandID}
	}
	if r.Change.ExpectedUserVersion == state.Access.User.Version {
		if _, e := ApplyAccountLink(state, r.Change, now); e != nil {
			return out, e
		}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(state.Access.User.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(state.Access.User.Version, 10))
	dc.Request.Resource.Attributes["identity.account.id"] = authorization.StringValue(string(r.Change.Account.ID))
	dc.Request.Resource.Attributes["identity.account.provider"] = authorization.StringValue(r.Change.Account.Provider)
	dc.Request.Resource.Attributes["identity.account.reason"] = authorization.StringValue(string(r.Change.Reason))
	dc.Request.Resource.Attributes["identity.account.social-link-version"] = authorization.StringValue(strconv.FormatUint(state.SocialLinkVersion, 10))
	dc.Request.Resource.Attributes["identity.account.credential-version"] = authorization.StringValue(strconv.FormatUint(state.CredentialVersion, 10))
	if e := s.policy.allow(ctx, dc); e != nil {
		return out, e
	}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Execute(ctx, command)
	if !receipt.valid() || receipt.Binding != b || receipt.Outcome == CommitOutcomeCommitted && (receipt.ExpectedVersion != r.Change.ExpectedUserVersion || receipt.Link.AccountID != r.Change.Account.ID || receipt.Link.Mode != r.Change.Mode || receipt.Link.ExpectedAccountVersion != r.Change.ExpectedAccountVersion || receipt.Link.ExpectedSocialLinkVersion != r.Change.ExpectedSocialLinkVersion || receipt.Link.ExpectedCredentialVersion != r.Change.ExpectedCredentialVersion || receipt.Link.AddsCredential != (r.Change.Method != nil)) {
		return out, unknownError(ctx, r.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, e, dc)
}

// RecoverAccountLink performs only scoped primary receipt recovery under current
// policy. It neither re-executes nor consumes proof, mutates links or calls providers.
func (s *AccountLinkService) RecoverAccountLink(ctx context.Context, r AccountLinkRecoveryRequest) (out AccountLinkResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.AccountID = ""
			out.Version = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{r.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "link_context"}
	}
	if _, ok := decodeID(string(r.CommandID)); !ok || !validDirectoryID(string(r.AccountID)) {
		return out, InvalidInputError{Field: "link_recovery"}
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, _, e := s.admit(ctx, r.TenantID, r.UserID, r.AccountID, r.Mode, r.ActorScope, true)
	if e != nil {
		return out, e
	}
	q := RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: "identity.account.link-token", RecordID: string(r.AccountID), LinkMode: r.Mode}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Recover(ctx, q)
	if !receipt.valid() || receipt.Binding.OperationID != q.OperationID || receipt.Binding.RecordID != q.RecordID || receipt.Binding.LinkMode != q.LinkMode || receipt.Binding.CommandID != q.CommandID || receipt.Binding.TenantID != q.TenantID || receipt.Binding.UserID != q.UserID || receipt.Binding.ActorID != q.ActorID || receipt.Binding.ActorKind != q.ActorKind || receipt.Outcome == CommitOutcomeCommitted && (receipt.Link.AccountID != r.AccountID || receipt.Link.Mode != r.Mode) {
		return out, unknownError(ctx, r.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, e, dc)
}

func (s *AccountLinkService) admit(ctx context.Context, tenant TenantID, user UserID, account AccountID, mode AccountLinkMode, scope authorization.DecisionContext, recovery bool) (authorization.DecisionContext, time.Time, error) {
	zero := authorization.DecisionContext{}
	if !validLinkActor(mode, scope.Request.Subject.Kind, ActorID(scope.Request.Subject.ID), user) || mode == AccountLinkAdministrative && !s.config.AllowAdministrative || mode == AccountLinkImplicit && (!s.config.AllowImplicit || ActorID(scope.Request.Subject.ID) != s.config.ImplicitActorID) {
		return zero, time.Time{}, ForbiddenError{}
	}
	if e := validateQueryContext(scope, tenant, string(user), "identity.account.link-token", "identity.user", s.config.Query.PolicyVersion); e != nil {
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
	dc.Request.Resource.Attributes["identity.account.link-mode"] = authorization.StringValue(strconv.Itoa(int(mode)))
	if e := s.policy.allow(ctx, dc); e != nil {
		return zero, time.Time{}, e
	}
	return dc, now, nil
}

func (s *AccountLinkService) finish(ctx context.Context, out AccountLinkResult, r CommandResult, e error, dc authorization.DecisionContext) (AccountLinkResult, error) {
	projection := &UserCreationService{policy: s.policy.policy}
	_, err := projection.finish(ctx, UserCreateResult{CommandID: out.CommandID, CommitOutcome: out.CommitOutcome}, r, e, dc)
	if err != nil {
		return out, err
	}
	out.AccountID = r.Link.AccountID
	out.Version = r.User.Version
	return out, nil
}
