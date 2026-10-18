package identity

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
)

func identifierOperation(a IdentifierAction) string {
	switch a {
	case IdentifierAttach:
		return "identity.identifier.attach"
	case IdentifierVerify:
		return "identity.identifier.verify"
	case IdentifierMakePrimary:
		return "identity.identifier.make-primary"
	case IdentifierReplace:
		return "identity.identifier.replace"
	case IdentifierRemove:
		return "identity.identifier.remove"
	default:
		return ""
	}
}

func identifierAction(op string) IdentifierAction {
	for a := IdentifierAttach; a <= IdentifierRemove; a++ {
		if identifierOperation(a) == op {
			return a
		}
	}
	return 0
}

func validIdentifierChange(c IdentifierChange) bool {
	if !validDirectoryID(string(c.TenantID)) || !validDirectoryID(string(c.UserID)) || !validDirectoryID(string(c.ID)) || identifierOperation(c.Action) == "" && c.Action != IdentifierRestartVerification && c.Action != IdentifierVerifyPrimary && c.Action != IdentifierRename || !unlinkVersion(c.ExpectedUserVersion) || !unlinkVersion(c.ExpectedAuthorityVersion) {
		return false
	}
	if c.Action == IdentifierAttach || c.Action == IdentifierReplace || c.Action == IdentifierRename {
		if !c.Kind.Valid() || !validIdentifierText(c.CanonicalValue) || c.DisplayValue != "" && !validIdentifierText(c.DisplayValue) || !validNormalizationBinding(c.NormalizationProfile, c.NormalizationVersion) {
			return false
		}
		if c.Action == IdentifierRename && (c.Kind != IdentifierUsername || c.DisplayValue == "" || c.NormalizationProfile == "") {
			return false
		}
	} else if c.Kind != "" || c.CanonicalValue != "" || c.DisplayValue != "" || c.NormalizationProfile != "" || c.NormalizationVersion != 0 {
		return false
	}
	if c.Action == IdentifierAttach {
		return c.ExpectedIdentifierVersion == 0 && c.ExpectedVerificationVersion == 0
	}
	return unlinkVersion(c.ExpectedIdentifierVersion) && unlinkVersion(c.ExpectedVerificationVersion)
}

// IdentifierIntentDigest returns a bounded, deterministic domain-separated
// signed-intent binding. It is not authority, a password hash or a safe reuse
// tombstone; do not publish/store it as an unhashed private-value index.
// The encoding is documented in docs/identifiers.md. No normalization occurs.
func IdentifierIntentDigest(c IdentifierChange) ([32]byte, error) {
	if !validIdentifierChange(c) {
		return [32]byte{}, InvalidInputError{Field: "identifier_intent"}
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "identity-identifier-change-v1\x00")
	fields := []string{string(c.TenantID), string(c.UserID), strconv.Itoa(int(c.Action)), string(c.ID), string(c.Kind), c.CanonicalValue, c.DisplayValue, strconv.FormatUint(c.ExpectedUserVersion, 10), strconv.FormatUint(c.ExpectedAuthorityVersion, 10), strconv.FormatUint(c.ExpectedIdentifierVersion, 10), strconv.FormatUint(c.ExpectedVerificationVersion, 10)}
	// Preserve shipped unbound intent bytes. A bound candidate additionally
	// commits the complete profile; neither bytes nor a revision alone suffice.
	if c.NormalizationProfile != "" {
		fields = append(fields, "normalization-v1", c.NormalizationProfile, strconv.FormatUint(uint64(c.NormalizationVersion), 10))
	}
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = h.Write(size[:])
		_, _ = io.WriteString(h, field)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// IdentifierCommand is immutable intent for the sole durable identity owner.
// Verified proof comes from the configured identity signer only after real
// session, canonicalization and feature challenge/reuse checks. Construction
// grants no such authority. The owner repeats fresh policy, session, proof,
// uniqueness, cooldown and final-access checks under locks before consumption.
type IdentifierCommand struct {
	Binding        CommandBinding
	Change         IdentifierChange
	Proof          capability.Grant
	SessionID      string
	SessionVersion uint64
}

func validIdentifierCommandShape(c IdentifierCommand) bool {
	return validCommandBinding(c.Binding) && validIdentifierChange(c.Change) && c.Binding.RecordID == string(c.Change.ID) && c.Binding.OperationID == identifierOperation(c.Change.Action) && c.Binding.SchemaID == "identity-identifier" && c.Binding.SchemaVersion == 1 && c.Binding.ActorKind == authorization.SubjectUser && string(c.Binding.ActorID) == string(c.Change.UserID) && c.Binding.UserID == c.Change.UserID && c.Binding.TenantID == c.Change.TenantID && validDirectoryID(c.SessionID) && c.SessionVersion > 0
}

func identifierCaveats(c IdentifierCommand) map[string]string {
	digest, _ := IdentifierIntentDigest(c.Change)
	return map[string]string{"intent_digest": hex.EncodeToString(digest[:]), "command_id": string(c.Binding.CommandID), "actor_id": string(c.Binding.ActorID), "session_id": c.SessionID, "session_version": strconv.FormatUint(c.SessionVersion, 10), "policy_version": strconv.FormatUint(c.Binding.PolicyVersion, 10)}
}

// NewIdentifierCommand validates exact signed intent and snapshots the command.
// It does not verify cryptography or consume proof; trusted service composition
// verifies configured issuer/audience and freshness before crossing UnitOfWork.
func NewIdentifierCommand(c IdentifierCommand) (Command, error) {
	if !validIdentifierCommandShape(c) {
		return Command{}, InvalidInputError{Field: "identifier_command"}
	}
	p := c.Proof.Payload()
	if !validDirectoryID(p.ID) || p.Bearer || p.MaxUses != 1 || len(p.Audiences) != 1 || len(p.Caveats) != 6 || c.Proof.Authorize(capability.Use{Issuer: p.Issuer, Audience: p.Audiences[0], Subject: string(c.Change.UserID), Tenant: string(c.Change.TenantID), Resource: string(c.Change.ID), Operation: c.Binding.OperationID, Caveats: identifierCaveats(c)}) != nil {
		return Command{}, InvalidInputError{Field: "identifier_proof"}
	}
	return Command{identifier: &c}, nil
}

// ChangeIdentifier returns a private value copy for this variant only.
func (c Command) ChangeIdentifier() (IdentifierCommand, bool) {
	if c.identifier == nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil || c.feature != nil || c.privacy != nil {
		return IdentifierCommand{}, false
	}
	return *c.identifier, true
}

// IdentifierProof returns optional request-memory custody of the original opaque
// proof attached by IdentifierService after admission. The boolean indicates
// presence, not validity or authorization. The transaction owner must reverify
// it with its configured capability service and reserve/consume atomically.
// Copies share the original proof's one-transfer lifetime; neither this accessor
// nor admission transfers or consumes it. NewIdentifierCommand constructs only
// metadata and does not attach custody. Never persist this proof.
func (c Command) IdentifierProof() (capability.Proof, bool) {
	if _, ok := c.ChangeIdentifier(); !ok || c.identifierProof == nil {
		return capability.Proof{}, false
	}
	return *c.identifierProof, true
}

// Format redacts canonical/display values and the proof envelope.
func (IdentifierCommand) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.IdentifierCommand(redacted)")
}

// IdentifierProofSpec is unsigned trusted ceremony output, never authorization
// or caller-asserted verification. Command.Proof must be zero. The configured
// signer may issue only after exact feature proofs and current policy succeed.
type IdentifierProofSpec struct {
	Command              IdentifierCommand
	Issuer, Audience, ID string
	IssuedAt, ExpiresAt  time.Time
}

// BuildIdentifierProofPayload owns the canonical six-caveat issuance shape.
// No signing, clock, I/O or proof consumption occurs. Instants have whole-second
// precision, UTC persisted representation, exclusive expiry and ≤5m lifetime.
// The returned payload is caller-owned sensitive intent; never log it.
func BuildIdentifierProofPayload(s IdentifierProofSpec) (capability.Payload, error) {
	if !validIdentifierCommandShape(s.Command) || s.Command.Proof.Payload().ID != "" || !validClaimIssuer(s.Issuer) || len(s.Issuer) > 256 || !validDirectoryID(s.Audience) || !validDirectoryID(s.ID) || s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || s.IssuedAt.UTC().Year() < 1 || s.ExpiresAt.UTC().Year() > 9999 || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > 5*time.Minute {
		return capability.Payload{}, InvalidInputError{Field: "identifier_proof_spec"}
	}
	return capability.Payload{Version: 1, Issuer: s.Issuer, Audiences: []string{s.Audience}, Subject: string(s.Command.Change.UserID), Tenant: string(s.Command.Change.TenantID), Resource: string(s.Command.Change.ID), Operation: s.Command.Binding.OperationID, ID: s.ID, MaxUses: 1, IssuedAt: s.IssuedAt.UTC(), NotBefore: s.IssuedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(), Caveats: identifierCaveats(s.Command)}, nil
}

// IdentifierReceipt records committed local admission, never current authority
// or feature challenge/provider success. It contains no identifier values.
// Identifier authority advances once; the owner also persists lifecycle events
// and required cascade admission. Terminal cleanup is not inferred from this.
type IdentifierReceipt struct {
	IdentifierID                               IdentifierID
	Action                                     IdentifierAction
	ExpectedAuthorityVersion, AuthorityVersion uint64
	// IntentDigest is the exact original IdentifierIntentDigest, never current
	// authority or a published private-value index. Retain it only in the
	// protected immutable receipt; public results never disclose it.
	IntentDigest [32]byte
}

func (r IdentifierReceipt) valid() bool {
	return validDirectoryID(string(r.IdentifierID)) && identifierOperation(r.Action) != "" && unlinkVersion(r.ExpectedAuthorityVersion) && r.AuthorityVersion == r.ExpectedAuthorityVersion+1 && r.IntentDigest != ([32]byte{})
}

// Format redacts retained intent fingerprints as well as record metadata.
func (IdentifierReceipt) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.IdentifierReceipt(redacted)")
}

// IdentifierQuery is an exact tenant/user complete primary read. More than
// MaximumIdentifiers is unavailable, not silently truncated or guessed absent.
type IdentifierQuery struct {
	TenantID           TenantID
	UserID             UserID
	MaximumIdentifiers uint16
}

// IdentifierRepository is platform-owned, concurrency-safe primary storage.
// Reads must honor the bounded context, return a consistent full partition and
// ErrUserAbsent for absence. A cache or consumer-supplied store is not authority.
type IdentifierRepository interface {
	GetIdentifierState(context.Context, IdentifierQuery) (IdentifierState, error)
}

// IdentifierChangeRequest is trusted current-human input, not public JSON.
// Preserve the exact command/proof/session/version and intent across retries.
// Canonical values come from the fixed, versioned owning feature policy, not
// client casing or the Go toolchain. Feature pre-auth flows remain separate.
type IdentifierChangeRequest struct {
	CommandID      CommandID
	Change         IdentifierChange
	Proof          capability.Proof
	SessionID      string
	SessionVersion uint64
	ActorScope     authorization.DecisionContext
	CorrelationID  string
}

// IdentifierRecoveryRequest authorizes exact original record/action scope.
// Possession of a command ID alone never authorizes receipt disclosure.
type IdentifierRecoveryRequest struct {
	CommandID    CommandID
	TenantID     TenantID
	UserID       UserID
	IdentifierID IdentifierID
	Action       IdentifierAction
	ActorScope   authorization.DecisionContext
}

// IdentifierResult keeps known commitment even when disclosure fails. Zero
// versions/ID on an error do not imply rollback; unknown requires scoped recovery.
type IdentifierResult struct {
	CommandID                 CommandID
	CommitOutcome             CommitOutcome
	IdentifierID              IdentifierID
	Version, AuthorityVersion uint64
}

// IdentifierConfig freezes query policy and exact signed-proof authority.
// MaximumProofAge is positive and at most five minutes. It does not establish
// current credential-specific reauthentication or challenge verification.
type IdentifierConfig struct {
	Query                      UserQueryConfig
	ProofIssuer, ProofAudience string
	MaximumProofAge            time.Duration
}

// IdentifierService owns identity command admission, not sessions, challenges,
// normalization engines, transactions, caches or goroutines. All dependencies
// must be concurrency-safe and honor bounded contexts. Use trusted composition.
type IdentifierService struct {
	repo   IdentifierRepository
	uow    UnitOfWork
	caps   capability.Service
	policy *AccountService
	config IdentifierConfig
}

// NewIdentifierService validates and freezes policy without external I/O.
func NewIdentifierService(repo IdentifierRepository, uow UnitOfWork, auth authorization.Service, redact RedactFunc, caps capability.Service, c IdentifierConfig) (*IdentifierService, error) {
	if nilDependency(repo) || nilDependency(uow) || nilDependency(caps) || !validClaimIssuer(c.ProofIssuer) || len(c.ProofIssuer) > 256 || !validDirectoryID(c.ProofAudience) || c.MaximumProofAge <= 0 || c.MaximumProofAge > 5*time.Minute {
		return nil, InvalidInputError{Field: "identifier_configuration"}
	}
	p, e := newQueryPolicy(auth, redact, c.Query)
	if e != nil {
		return nil, e
	}
	return &IdentifierService{repo: repo, uow: uow, caps: caps, policy: &AccountService{policy: p}, config: c}, nil
}

// IdentifierChange authorizes before proof/primary access and again against
// current state. The sole owner checks replay before CAS, repeats locked fresh
// evidence/uniqueness/final access and atomically consumes proof/risk with state,
// keyed reuse tombstones, lifecycle events/audit and receipt. This service owns
// no durable reservation and cannot claim atomicity from a primary read alone.
func (s *IdentifierService) IdentifierChange(ctx context.Context, r IdentifierChangeRequest) (out IdentifierResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.IdentifierID = ""
			out.Version = 0
			out.AuthorityVersion = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{r.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "identifier_context"}
	}
	correlation := r.CorrelationID
	if correlation == "" {
		correlation = string(r.CommandID)
	}
	b := CommandBinding{CommandID: r.CommandID, TenantID: r.Change.TenantID, UserID: r.Change.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: identifierOperation(r.Change.Action), PolicyID: s.config.Query.PolicyID, PolicyVersion: s.config.Query.PolicyVersion, SchemaID: "identity-identifier", SchemaVersion: 1, CorrelationID: correlation}
	b.RecordID = string(r.Change.ID)
	spec := IdentifierCommand{Binding: b, Change: r.Change, SessionID: r.SessionID, SessionVersion: r.SessionVersion}
	if !validIdentifierCommandShape(spec) {
		return out, InvalidInputError{Field: "identifier_binding"}
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, now, e := s.admit(ctx, r.Change.TenantID, r.Change.UserID, r.Change.ID, r.Change.Action, r.ActorScope, false)
	if e != nil {
		return out, e
	}
	g, e := s.caps.Verify(ctx, r.Proof, capability.Purpose(b.OperationID), s.config.ProofAudience)
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
	spec.Proof = g
	command, e := NewIdentifierCommand(spec)
	if e != nil {
		return out, ForbiddenError{}
	}
	state, e := s.repo.GetIdentifierState(ctx, IdentifierQuery{TenantID: r.Change.TenantID, UserID: r.Change.UserID, MaximumIdentifiers: 128})
	if ce := readContextError(ctx); ce != nil {
		return out, ce
	}
	if e != nil {
		if errors.Is(e, ErrUserAbsent) {
			return out, ForbiddenError{}
		}
		return out, UnavailableError{}
	}
	if state.validate(r.Change.TenantID, r.Change.UserID, now) != nil {
		return out, UnavailableError{}
	}
	if !state.User.Status.AllowsAuthentication() {
		return out, ForbiddenError{}
	}
	if r.Change.ExpectedUserVersion > state.User.Version || r.Change.ExpectedAuthorityVersion > state.AuthorityVersion {
		return out, ConflictError{r.CommandID}
	}
	if r.Change.ExpectedUserVersion == state.User.Version {
		if _, e := ApplyIdentifierChange(state, r.Change, now); e != nil {
			return out, e
		}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(state.User.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(state.User.Version, 10))
	dc.Request.Resource.Attributes["identity.identifier.authority-version"] = authorization.StringValue(strconv.FormatUint(state.AuthorityVersion, 10))
	if e := s.policy.allow(ctx, dc); e != nil {
		return out, e
	}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	// Keep original shared custody available for configured native reverification;
	// Grant metadata alone cannot establish signed-envelope identity.
	command.identifierProof = &r.Proof
	receipt, e := s.uow.Execute(ctx, command)
	digest, _ := IdentifierIntentDigest(r.Change)
	if !receipt.valid() || receipt.Binding != b || receipt.Outcome == CommitOutcomeCommitted && (receipt.ExpectedVersion != r.Change.ExpectedUserVersion || receipt.Identifier.IdentifierID != r.Change.ID || receipt.Identifier.Action != r.Change.Action || receipt.Identifier.ExpectedAuthorityVersion != r.Change.ExpectedAuthorityVersion || receipt.Identifier.IntentDigest != digest) {
		return out, unknownError(ctx, r.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, e, dc)
}

// RecoverIdentifierChange reads only the exact original receipt under current
// record/action/owner policy; no Execute, proof consumption or challenge runs.
func (s *IdentifierService) RecoverIdentifierChange(ctx context.Context, r IdentifierRecoveryRequest) (out IdentifierResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.IdentifierID = ""
			out.Version = 0
			out.AuthorityVersion = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{r.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "identifier_context"}
	}
	if _, ok := decodeID(string(r.CommandID)); !ok || !validDirectoryID(string(r.IdentifierID)) || identifierOperation(r.Action) == "" {
		return out, InvalidInputError{Field: "identifier_recovery"}
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, _, e := s.admit(ctx, r.TenantID, r.UserID, r.IdentifierID, r.Action, r.ActorScope, true)
	if e != nil {
		return out, e
	}
	q := RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorID: ActorID(r.ActorScope.Request.Subject.ID), ActorKind: r.ActorScope.Request.Subject.Kind, OperationID: identifierOperation(r.Action), RecordID: string(r.IdentifierID)}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Recover(ctx, q)
	if !receipt.valid() || receipt.Binding.OperationID != q.OperationID || receipt.Binding.RecordID != q.RecordID || receipt.Binding.CommandID != q.CommandID || receipt.Binding.TenantID != q.TenantID || receipt.Binding.UserID != q.UserID || receipt.Binding.ActorID != q.ActorID || receipt.Binding.ActorKind != q.ActorKind || receipt.Outcome == CommitOutcomeCommitted && (receipt.Identifier.IdentifierID != r.IdentifierID || receipt.Identifier.Action != r.Action) {
		return out, unknownError(ctx, r.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, e, dc)
}

func (s *IdentifierService) admit(ctx context.Context, tenant TenantID, user UserID, id IdentifierID, action IdentifierAction, scope authorization.DecisionContext, recovery bool) (authorization.DecisionContext, time.Time, error) {
	zero := authorization.DecisionContext{}
	if scope.Request.Subject.Kind != authorization.SubjectUser || string(scope.Request.Subject.ID) != string(user) {
		return zero, time.Time{}, ForbiddenError{}
	}
	if e := validateQueryContext(scope, tenant, string(user), identifierOperation(action), "identity.user", s.config.Query.PolicyVersion); e != nil {
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
	dc.Request.Resource.Attributes["identity.identifier.id"] = authorization.StringValue(string(id))
	dc.Request.Resource.Attributes["identity.identifier.action"] = authorization.StringValue(identifierOperation(action))
	if e := s.policy.allow(ctx, dc); e != nil {
		return zero, time.Time{}, e
	}
	return dc, now, nil
}

func (s *IdentifierService) finish(ctx context.Context, out IdentifierResult, r CommandResult, e error, dc authorization.DecisionContext) (IdentifierResult, error) {
	p := &UserCreationService{policy: s.policy.policy}
	_, err := p.finish(ctx, UserCreateResult{CommandID: out.CommandID, CommitOutcome: out.CommitOutcome}, r, e, dc)
	if err != nil {
		return out, err
	}
	out.IdentifierID = r.Identifier.IdentifierID
	out.Version = r.User.Version
	out.AuthorityVersion = r.Identifier.AuthorityVersion
	return out, nil
}
