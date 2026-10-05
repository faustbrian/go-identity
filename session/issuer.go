package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

var (
	// ErrInvalidIssuer rejects incomplete trusted composition, without IO.
	ErrInvalidIssuer = errors.New("session: invalid issuer configuration")
	// ErrInvalidIssuance rejects zero, substituted or foreign preparation.
	ErrInvalidIssuance = errors.New("session: invalid issuance")
	// ErrIssuanceAlreadyAttempted requires scoped recovery of the same command;
	// it does not assert that the previous attempt committed or rolled back.
	ErrIssuanceAlreadyAttempted = errors.New("session: issuance already attempted")
	// ErrIssuerUnavailable redacts a dependency failure before durable execution.
	ErrIssuerUnavailable = errors.New("session: issuer unavailable")
)

// IssuerClock supplies trusted time. It must be concurrent-safe and nonblocking.
// Neither client timestamps nor a returned receipt may select this clock.
type IssuerClock interface{ Now() time.Time }

// IssueExecutor is the storage-neutral boundary implemented by the owned
// durable adapter, not an application workflow or another command journal.
// ExecuteIssue must validate the original opaque proof, current lifecycle and
// policy, consume required one-time proofs and persist the exact session plus
// required audit/outbox effects under the sole authoritative command owner.
// Replayed is true for any historical terminal observation. RecoverIssue must
// authorize exact scope and read that same command on the primary; it must
// never execute, refresh inputs or infer absence from cancellation. Both methods
// must be concurrent-safe, honor ctx and never return bearer material.
type IssueExecutor interface {
	ExecuteIssue(context.Context, IssueRequest) (IssueExecution, error)
	RecoverIssue(context.Context, IssueRequest) (IssueExecution, error)
}

// IssueExecution carries a durable receipt and exact native historical record.
// Session is present only on committed outcomes. Replayed forbids delivery;
// it cannot change a receipt's outcome. Public reconstruction is structural,
// not authority: only the trusted durable executor establishes these facts.
// Do not mutate a returned value concurrently with its consumer.
type IssueExecution struct {
	Receipt  identity.CommandResult
	Session  Session
	Replayed bool
}

// IssuerConfig freezes cookie issuance composition. Authority is the configured
// private proof authority. MaximumDuration is 1ms..30s; dependencies must honor
// it. TokenSize is 32..64 bytes. LookupKey is independent session-lookup custody.
// Cookie is the validated host-only transport profile. This first owned issuer
// supports authenticated cookie issuance; anonymous and bearer continuations
// require separate native admission and are not silently approximated here.
type IssuerConfig struct {
	Authority       *authentication.AuthorityAuthenticator
	Clock           IssuerClock
	MaximumDuration time.Duration
	LookupKey       DigestKey
	TokenSize       int
	Cookie          CookiePolicy
}

// SessionIssuer owns original-token preparation and commit-gated delivery. It
// holds no durable store, command cache, locks, goroutines or transaction handle.
// Dependencies remain borrowed and must outlive calls. Copies of preparations
// share one execution claim; unrelated preparations can execute concurrently.
type SessionIssuer struct {
	executor IssueExecutor
	config   IssuerConfig
}

// NewSessionIssuer validates and freezes trusted composition without IO. Use
// the owned PostgreSQL execution service, not a consumer-written domain store.
func NewSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	if issuerNil(executor) || issuerNil(c.Clock) || c.Authority == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.LookupKey.state == nil || c.TokenSize < 32 || c.TokenSize > 64 || c.Cookie.name == "" {
		return nil, ErrInvalidIssuer
	}
	return &SessionIssuer{executor: executor, config: c}, nil
}

func issuerNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// PreparedIssuance retains an original bearer privately with its exact command
// and proof. Zero is invalid. It can be copied concurrently; no public operation
// reveals its bearer. One atomic attempt is shared across all copies. It is not
// a durable receipt, a replay store or a replacement for executor idempotency.
// Retain Request for recovery; do not Prepare again to retry an unknown command.
type PreparedIssuance struct{ state *preparedIssuanceState }
type preparedIssuanceState struct {
	owner     *SessionIssuer
	request   IssueRequest
	token     Token
	attempted atomic.Bool
}

// Prepare validates the resolved policy, complete original authentication and
// vector before generating a token. spec.Lookup must be zero: only this issuer
// sets the exact tenant/key-bound digest. All other input, including command ID,
// family lifetime, proof/credential versions and RememberPolicy, is retained.
// It performs no durable IO or proof consumption and grants no authority. A
// successful preparation must be retained unchanged through Issue/recovery.
func (s *SessionIssuer) Prepare(binding identity.CommandBinding, spec SessionSpec, proof authentication.AuthenticatedProof) (out PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			out = PreparedIssuance{}
			err = ErrIssuerUnavailable
		}
	}()
	if s == nil || spec.Lookup != (TokenDigest{}) {
		return out, ErrInvalidIssuance
	}
	// Validate the full structural/proof input before allocating credential bytes.
	spec.Lookup = TokenDigest{KeyVersion: s.config.LookupKey.state.version, Sum: [32]byte{1}}
	record, e := NewSession(spec)
	if e != nil {
		return out, e
	}
	command, e := NewIssueCommand(binding, record)
	if e != nil {
		return out, e
	}
	request, e := NewAuthenticatedIssueRequest(command, proof)
	if e != nil {
		return out, e
	}
	if e = request.Validate(s.config.Authority, s.config.Clock.Now()); e != nil {
		return out, e
	}
	token, e := NewToken(s.config.TokenSize)
	if e != nil {
		return out, e
	}
	spec.Lookup, e = token.Digest(s.config.LookupKey, string(spec.TenantID))
	if e != nil {
		return out, e
	}
	record, e = NewSession(spec)
	if e != nil {
		return out, e
	}
	command, e = NewIssueCommand(binding, record)
	if e != nil {
		return out, e
	}
	request, e = NewAuthenticatedIssueRequest(command, proof)
	if e != nil {
		return out, e
	}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: request, token: token}}, nil
}

// Request returns the original immutable safe command/proof for durable
// recovery, without granting access to bearer bytes. Zero returns false.
func (p PreparedIssuance) Request() (IssueRequest, bool) {
	if p.state == nil {
		return IssueRequest{}, false
	}
	return p.state.request, true
}

// Format redacts every scope and credential for all formatting verbs.
func (PreparedIssuance) Format(f fmt.State, _ rune) {
	io.WriteString(f, "session.PreparedIssuance(redacted)")
}

// MarshalJSON rejects implicit credential/command serialization.
func (PreparedIssuance) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit text or map-key serialization.
func (PreparedIssuance) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// IssueResult preserves the authoritative outcome even when delivery is
// withheld. Session is historical metadata, never current authentication.
// Token and credential-free Cookie are returned only on exact new committed
// execution with no error, cancellation or expired original lifetime. Copies
// share Token's reveal-once permission. Replays and recovery return no token.
// Cookie.Value is always empty; explicitly populate it only at authorized HTTP
// delivery, never in logs or general serialization.
type IssueResult struct {
	CommandID     identity.CommandID
	CommitOutcome identity.CommitOutcome
	Session       Session
	Token         Token
	Cookie        http.Cookie
	Replayed      bool
	RetryAfter    time.Duration
}

// Format redacts all scope and transport metadata.
func (IssueResult) Format(f fmt.State, _ rune) { io.WriteString(f, "session.IssueResult(redacted)") }

// MarshalJSON rejects accidental serialization of issuance custody.
func (IssueResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects accidental text or map-key serialization.
func (IssueResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Issue makes one bounded durable attempt using the original preparation.
// Before executor entry a failure observes no outcome. After entry, panic or
// malformed receipt is Unknown, never inferred rollback. Valid exact receipts
// retain their outcome even alongside cancellation/error; those paths disclose
// no bearer. No dependency error text escapes. The executor, not this in-memory
// claim, owns durable idempotency and atomic proof/session/audit finalization.
func (s *SessionIssuer) Issue(ctx context.Context, p PreparedIssuance) (out IssueResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.Token = Token{}
			out.Cookie = http.Cookie{}
			if attempted && out.CommitOutcome == identity.CommitOutcomeUnknown {
				out.Session = Session{}
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrIssuerUnavailable
			}
		}
	}()
	if s == nil || ctx == nil || p.state == nil || p.state.owner != s {
		return out, ErrInvalidIssuance
	}
	command, _ := p.state.request.Command()
	issue, _ := command.Issue()
	out.CommandID = issue.Binding.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if e := p.state.request.Validate(s.config.Authority, s.config.Clock.Now()); e != nil {
		return out, e
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if !p.state.attempted.CompareAndSwap(false, true) {
		return out, ErrIssuanceAlreadyAttempted
	}
	attempted = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	execution, dependencyErr := s.executor.ExecuteIssue(ctx, p.state.request)
	out, err = s.finish(ctx, p.state.request, execution, dependencyErr)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
		return out, err
	}
	now := s.config.Clock.Now()
	life, e := out.Session.Lifetime(now)
	if e != nil {
		return out, e
	}
	spec, _ := out.Session.Bindings()
	cookie, e := s.config.Cookie.Attributes(spec.Remember, now, life.AbsoluteExpiresAt)
	if e != nil {
		return out, e
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	out.Cookie = cookie
	out.Token = p.state.token
	return out, nil
}

// Recover performs only an authorized, bounded primary outcome lookup for the
// original request. Proof expiry does not prohibit historical recovery; current
// result-access policy belongs to the executor. It never executes, regenerates,
// reveals or redelivers a credential, even when recovery proves Committed.
func (s *SessionIssuer) Recover(ctx context.Context, r IssueRequest) (out IssueResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out = IssueResult{CommandID: out.CommandID}
			if attempted {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrIssuerUnavailable
			}
		}
	}()
	if s == nil || ctx == nil || r.state == nil {
		return out, ErrInvalidIssuance
	}
	issue, _ := r.state.command.Issue()
	out.CommandID = issue.Binding.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return out, e
	}
	attempted = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	execution, e := s.executor.RecoverIssue(ctx, r)
	out, err = s.finish(ctx, r, execution, e)
	out.Replayed = true
	return out, err
}

func (s *SessionIssuer) finish(ctx context.Context, r IssueRequest, e IssueExecution, dependencyErr error) (out IssueResult, err error) {
	issue, _ := r.state.command.Issue()
	out.CommandID = issue.Binding.CommandID
	out.CommitOutcome = identity.CommitOutcomeUnknown
	receipt := e.Receipt
	if receipt.Validate() != nil || receipt.Binding != issue.Binding || receipt.Feature == nil || receipt.Feature.Operation != IssueOperation() || (receipt.Outcome == identity.CommitOutcomeCommitted && (receipt.Feature.BeforeVersion != 0 || receipt.Feature.AfterVersion != 1 || !sameIssuedSession(e.Session, issue.Session))) || (receipt.Outcome != identity.CommitOutcomeCommitted && e.Session != (Session{})) {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	out.CommitOutcome = receipt.Outcome
	out.RetryAfter = receipt.RetryAfter
	out.Replayed = e.Replayed
	switch receipt.Outcome {
	case identity.CommitOutcomeCommitted:
		out.Session = e.Session
		if e := ctx.Err(); e != nil {
			return out, e
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
		return out, identity.InProgressError{CommandID: out.CommandID, RetryAfter: receipt.RetryAfter}
	default:
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
}

func sameIssuedSession(a, b Session) bool {
	x, e := a.Bindings()
	if e != nil {
		return false
	}
	y, e := b.Bindings()
	if e != nil || x.Authority.CompareCurrent(y.Authority) != nil {
		return false
	}
	x.Authority = AuthoritySnapshot{}
	y.Authority = AuthoritySnapshot{}
	normalize := func(s *SessionSpec) {
		s.IssuedAt = s.IssuedAt.UTC().Round(0)
		s.LastActivityAt = s.LastActivityAt.UTC().Round(0)
		s.Authentication.Proof.IssuedAt = s.Authentication.Proof.IssuedAt.UTC().Round(0)
		s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.ExpiresAt.UTC().Round(0)
		s.Authentication.AnonymousAt = s.Authentication.AnonymousAt.UTC().Round(0)
	}
	normalize(&x)
	normalize(&y)
	return x == y
}
