package session

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// PreAuthIssueOperation identifies the closed original-flow creation contract.
// It grants no authority and is returned by value for adapter composition.
func PreAuthIssueOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.preauth-issue", SchemaID: "session-preauth-issue-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// PreAuthIssuerConfig freezes one trusted service/action/origin/callback/policy
// profile. Empty callback explicitly disables redirection. Never select these
// values from client input. FlowTTL is 1..10 minutes (reference: five minutes),
// independent of the resolved final-session remember choice. LookupKey must be
// a dedicated retained pre-auth key; TokenSize is 32..64 bytes. Cookie must be
// the validated __Host-identity_flow Lax/Strict policy. MaximumDuration is
// 1ms..30s. Clock must be concurrency-safe, trusted and nonblocking.
type PreAuthIssuerConfig struct {
	ActorID                               identity.ActorID
	Action, Origin, CallbackURL, PolicyID string
	PolicyVersion                         uint64
	Clock                                 IssuerClock
	MaximumDuration, FlowTTL              time.Duration
	LookupKey                             DigestKey
	TokenSize                             int
	Cookie                                CookiePolicy
}

// PreAuthPrepareInput supplies server-selected command, tenant and correlation
// identities plus the already-resolved final session choice. It cannot select
// the flow ID, nonce, cookie, original timeline or trusted profile. Retain the
// returned preparation unchanged; calling Prepare again is not a retry.
type PreAuthPrepareInput struct {
	CommandID     identity.CommandID
	TenantID      identity.TenantID
	CorrelationID string
	Remember      RememberPolicy
	// IdentifierBinding is the workflow owner's original canonical-identifier
	// commitment. It is retained unchanged, not computed or authenticated here.
	IdentifierBinding [32]byte
}

// PreAuthIssuer owns original entropy and commit-gated flow-cookie delivery.
// It authenticates no user and holds no store, journal, lock or goroutine.
// Compose the owned durable executor; dependencies remain borrowed and must
// outlive calls. Preparations retain credentials privately across value copies.
type PreAuthIssuer struct {
	executor PreAuthIssuanceExecutor
	config   PreAuthIssuerConfig
}

// NewPreAuthIssuer validates trusted composition without IO or entropy. The
// durable executor must independently enforce the identical selected profile.
func NewPreAuthIssuer(executor PreAuthIssuanceExecutor, c PreAuthIssuerConfig) (*PreAuthIssuer, error) {
	if issuerNil(executor) || issuerNil(c.Clock) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.FlowTTL < time.Minute || c.FlowTTL > 10*time.Minute || c.LookupKey.state == nil || c.TokenSize < 32 || c.TokenSize > 64 || c.Cookie.name != "__Host-identity_flow" {
		return nil, ErrInvalidIssuer
	}
	c.ActorID = identity.ActorID(strings.Clone(string(c.ActorID)))
	c.Action, c.Origin, c.CallbackURL, c.PolicyID = strings.Clone(c.Action), strings.Clone(c.Origin), strings.Clone(c.CallbackURL), strings.Clone(c.PolicyID)
	s := &PreAuthIssuer{executor: executor, config: c}
	// A non-issuing structural template validates the selected profile without
	// calling the clock or generating credential bytes during construction.
	remember, _ := ResolveRememberPolicy(BrowserSession, LifetimeConfig{Default: BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	input := PreAuthPrepareInput{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "configuration", CorrelationID: "configuration", Remember: remember}
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	command, err := s.original(input, "AQEBAQEBAQEBAQEBAQEBAQ", [32]byte{1}, stamp, TokenDigest{KeyVersion: c.LookupKey.state.version, Sum: [32]byte{1}})
	if err != nil || s.binding(command).ValidateFor(PreAuthIssueOperation()) != nil {
		return nil, ErrInvalidIssuer
	}
	return s, nil
}

// PreparedPreAuthIssuance owns an immutable original command and private bearer.
// Zero is invalid. Copies share one atomic execution attempt, not a durable
// replay authority. Retain Command for outcome-only recovery; no method exposes
// credential bytes before successful new committed issuance.
type PreparedPreAuthIssuance struct{ state *preparedPreAuthState }
type preparedPreAuthState struct {
	owner     *PreAuthIssuer
	command   PreAuthIssueCommand
	token     Token
	attempted atomic.Bool
}

// Prepare validates all supplied input before generating a canonical random
// flow ID, 32-byte nonce and opaque cookie. Original time comes from the trusted
// clock and is never refreshed by retries or final-session remember policy.
// No durable work, authentication, policy callback or proof consumption occurs.
func (s *PreAuthIssuer) Prepare(input PreAuthPrepareInput) (out PreparedPreAuthIssuance, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedPreAuthIssuance{}, ErrIssuerUnavailable
		}
	}()
	if s == nil {
		return out, ErrInvalidIssuance
	}
	now := s.config.Clock.Now().UTC()
	placeholder := TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	command, err := s.original(input, "AQEBAQEBAQEBAQEBAQEBAQ", [32]byte{1}, now, placeholder)
	if err != nil || s.binding(command).ValidateFor(PreAuthIssueOperation()) != nil {
		return out, ErrInvalidIssuance
	}
	id, err := identity.NewPreAuthTransactionID()
	if err != nil {
		return out, ErrIssuerUnavailable
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return out, ErrIssuerUnavailable
	}
	token, err := NewToken(s.config.TokenSize)
	if err != nil {
		return out, err
	}
	command, err = s.original(input, id, nonce, now, placeholder)
	if err != nil {
		return out, err
	}
	spec, _ := command.Record.Bindings()
	spec.Cookie, err = token.PreAuthDigest(s.config.LookupKey, spec.Binding)
	if err != nil {
		return out, err
	}
	command.Record, err = NewPreAuthTransaction(spec)
	if err != nil {
		return out, err
	}
	return PreparedPreAuthIssuance{state: &preparedPreAuthState{owner: s, command: command, token: token}}, nil
}

func (s *PreAuthIssuer) original(i PreAuthPrepareInput, id identity.PreAuthTransactionID, nonce [32]byte, now time.Time, digest TokenDigest) (PreAuthIssueCommand, error) {
	c := s.config
	record, err := NewPreAuthTransaction(PreAuthTransactionSpec{Binding: PreAuthBinding{ID: id, Intent: PreAuthIntent{TenantID: i.TenantID, Action: c.Action, Origin: c.Origin, CallbackURL: c.CallbackURL, Nonce: nonce, Remember: i.Remember, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, IdentifierBinding: i.IdentifierBinding}, IssuedAt: now, ExpiresAt: now.Add(c.FlowTTL)}, Cookie: digest, Version: 1})
	return PreAuthIssueCommand{CommandID: i.CommandID, CorrelationID: strings.Clone(i.CorrelationID), Record: record}, err
}

func (s *PreAuthIssuer) binding(c PreAuthIssueCommand) identity.CommandBinding {
	p, _ := c.Record.Bindings()
	i := p.Binding.Intent
	op := PreAuthIssueOperation()
	return identity.CommandBinding{CommandID: c.CommandID, TenantID: i.TenantID, AnonymousFlowID: string(p.Binding.ID), ActorID: s.config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(p.Binding.ID), PolicyID: i.PolicyID, PolicyVersion: i.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: c.CorrelationID}
}

func (s *PreAuthIssuer) originalProfile(c PreAuthIssueCommand) bool {
	p, err := c.Record.Bindings()
	i := p.Binding.Intent
	return err == nil && p.Version == 1 && i.Action == s.config.Action && i.Origin == s.config.Origin && i.CallbackURL == s.config.CallbackURL && i.PolicyID == s.config.PolicyID && i.PolicyVersion == s.config.PolicyVersion && s.binding(c).ValidateFor(PreAuthIssueOperation()) == nil
}

// Command returns the unchanged private original for durable recovery, without
// exposing bearer bytes or granting execution authority. Zero returns false.
func (p PreparedPreAuthIssuance) Command() (PreAuthIssueCommand, bool) {
	if p.state == nil {
		return PreAuthIssueCommand{}, false
	}
	return p.state.command, true
}

// PreAuthIssueResult preserves durable outcome and original structural metadata.
// Token and credential-free Cookie are populated only on exact new commitment,
// no error/cancellation and at least one second of original flow lifetime.
// Flow is historical metadata, not active state or authentication. Recovery and
// replay return no credential. Token copies share reveal-once custody. HTTP may
// assign Value only when delivering; never log a populated credential cookie.
type PreAuthIssueResult struct {
	CommandID     identity.CommandID
	CommitOutcome identity.CommitOutcome
	Flow          PreAuthTransaction
	Token         Token
	Cookie        http.Cookie
	Replayed      bool
	RetryAfter    time.Duration
}

// Issue attempts one unchanged preparation with an earlier-deadline-preserving
// execution budget. Copies share one local attempt; after Unknown recover the
// original command, never prepare a replacement. A known commitment survives
// delivery failure. Flow cookies expire within original TTL for both remember
// choices; persistent-session choice never extends unauthenticated flow time.
func (s *PreAuthIssuer) Issue(ctx context.Context, p PreparedPreAuthIssuance) (out PreAuthIssueResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.Token, out.Cookie = Token{}, http.Cookie{}
			err = ErrIssuerUnavailable
			if entered && out.CommitOutcome == identity.CommitOutcomeUnknown {
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			}
		}
	}()
	if s == nil || ctx == nil || p.state == nil || p.state.owner != s || !s.originalProfile(p.state.command) {
		return out, ErrInvalidIssuance
	}
	c := p.state.command
	out.CommandID = c.CommandID
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	spec, _ := c.Record.Bindings()
	if err = c.Record.Check(s.config.Clock.Now(), spec.Binding, spec.Cookie); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if !p.state.attempted.CompareAndSwap(false, true) {
		return out, ErrIssuanceAlreadyAttempted
	}
	entered, out.CommitOutcome = true, identity.CommitOutcomeUnknown
	execution, dependencyErr := s.executor.ExecutePreAuthIssuance(ctx, c)
	out, err = s.finishPreAuth(ctx, c, execution, dependencyErr)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
		return out, err
	}
	now := s.config.Clock.Now()
	if err = c.Record.Check(now, spec.Binding, spec.Cookie); err != nil {
		return out, err
	}
	seconds := int(spec.Binding.ExpiresAt.Sub(now) / time.Second)
	if seconds < 1 {
		return out, ErrExpired
	}
	cookie := s.config.Cookie.base()
	cookie.MaxAge = seconds
	cookie.Expires = now.Add(time.Duration(seconds) * time.Second).UTC()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	out.Cookie, out.Token = cookie, p.state.token
	return out, nil
}

// Recover performs current-policy primary outcome lookup for the exact original
// safe command, even after flow expiry. It neither executes nor renews flow
// state and never delivers a credential, including on known commitment.
func (s *PreAuthIssuer) Recover(ctx context.Context, c PreAuthIssueCommand) (out PreAuthIssueResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.Token, out.Cookie = Token{}, http.Cookie{}
			err = ErrIssuerUnavailable
			if entered {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			}
		}
	}()
	if s == nil || ctx == nil || !s.originalProfile(c) {
		return out, ErrInvalidIssuance
	}
	b := s.binding(c)
	out.CommandID = b.CommandID
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	entered, out.CommitOutcome = true, identity.CommitOutcomeUnknown
	receipt, dependencyErr := s.executor.RecoverPreAuthIssue(ctx, q)
	out, err = s.finishPreAuth(ctx, c, PreAuthIssueExecution{Receipt: receipt, Replayed: true}, dependencyErr)
	// Query scope proves the historical outcome, not that a reconstructed caller
	// projection equals the original private persisted flow payload.
	out.Flow = PreAuthTransaction{}
	return out, err
}

func (s *PreAuthIssuer) finishPreAuth(ctx context.Context, c PreAuthIssueCommand, e PreAuthIssueExecution, dependencyErr error) (out PreAuthIssueResult, err error) {
	out.CommandID, out.CommitOutcome = c.CommandID, identity.CommitOutcomeUnknown
	r := e.Receipt
	if r.Validate() != nil || r.Binding != s.binding(c) || r.Feature == nil || r.Feature.Operation != PreAuthIssueOperation() || r.Outcome == identity.CommitOutcomeCommitted && (r.Feature.BeforeVersion != 0 || r.Feature.AfterVersion != 1) {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	out.CommitOutcome, out.Replayed, out.RetryAfter = r.Outcome, e.Replayed, r.RetryAfter
	switch r.Outcome {
	case identity.CommitOutcomeCommitted:
		out.Flow = c.Record
		if err = ctx.Err(); err != nil {
			return out, err
		}
		if dependencyErr != nil {
			return out, ErrIssuerUnavailable
		}
		return out, nil
	case identity.CommitOutcomeNotCommitted:
		return out, identity.NotCommittedError{CommandID: out.CommandID}
	case identity.CommitOutcomeConflict:
		return out, identity.ConflictError{CommandID: out.CommandID}
	case identity.CommitOutcomeInProgress:
		return out, identity.InProgressError{CommandID: out.CommandID, RetryAfter: r.RetryAfter}
	default:
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
}

// Format redacts all original flow, command and bearer custody.
func (PreparedPreAuthIssuance) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreparedPreAuthIssuance(redacted)")
}

// MarshalJSON denies implicit private preparation disclosure.
func (PreparedPreAuthIssuance) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit private preparation disclosure.
func (PreparedPreAuthIssuance) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts original outcome scope and transport custody.
func (PreAuthIssueResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreAuthIssueResult(redacted)")
}

// MarshalJSON denies implicit credential/result export.
func (PreAuthIssueResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit credential/result export.
func (PreAuthIssueResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts trusted profile and digest-key composition.
func (PreAuthIssuerConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreAuthIssuerConfig(redacted)")
}

// MarshalJSON denies implicit runtime configuration export.
func (PreAuthIssuerConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts retained policy, dependencies and key composition.
func (PreAuthIssuer) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreAuthIssuer(redacted)")
}

// MarshalJSON denies implicit runtime composition export.
func (PreAuthIssuer) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts tenant, command and correlation custody.
func (PreAuthPrepareInput) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreAuthPrepareInput(redacted)")
}

// MarshalJSON denies implicit original preparation-input export.
func (PreAuthPrepareInput) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
