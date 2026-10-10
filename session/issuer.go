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
	// ErrIssuanceAlreadyBound rejects a second bind of original OTP custody.
	ErrIssuanceAlreadyBound = errors.New("session: issuance already bound")
	// ErrIssuerUnavailable redacts a dependency failure before durable execution.
	ErrIssuerUnavailable = errors.New("session: issuer unavailable")
)

// IssuerClock supplies trusted time. It must be concurrent-safe and nonblocking.
// Neither client timestamps nor a returned receipt may select this clock.
type IssuerClock interface{ Now() time.Time }

// IssueExecutor is the storage-neutral boundary implemented by the owned
// durable adapter, not an application workflow or another command journal.
// ExecuteIssue must validate the selected profile's original opaque proof or
// OTP or password/pre-auth custody, current lifecycle and policy, consume required
// one-time proofs and persist the exact session plus
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
// private proof authority for NewSessionIssuer; it must be nil for the explicit
// OTP and password profiles. MaximumDuration is 1ms..30s; dependencies must honor
// it. TokenSize is 32..64 bytes. LookupKey is independent session-lookup custody.
// Cookie is the validated host-only transport profile. OTP pre-auth flows may
// retain anonymous command scope while the native effect resolves the final
// user. Anonymous sessions and bearer continuations require separate admission.
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
	csrfKey  CSRFKey
	otp      bool
	password bool
}

// NewSessionIssuerWithCSRF selects the synchronizer profile with a dedicated
// current issuance key. All original configuration/receipt/lifetime rules still
// apply. The owned executor MUST persist the complete Session, including its
// separate CSRFState, in the issuance transaction; legacy lossy adapters cannot
// be composed with this profile. Retain named verification keys for overlap.
// Original CSRF delivery is retrieved from PreparedIssuance.CSRFToken only after
// successful new Issue. No public configuration/result struct shape changes.
func NewSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, e := NewSessionIssuer(executor, c)
	if e != nil {
		return nil, e
	}
	s.csrfKey = key
	return s, nil
}

// NewSessionIssuer validates and freezes trusted composition without IO. Use
// the owned PostgreSQL execution service, not a consumer-written domain store.
func NewSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	return newSessionIssuer(executor, c, false)
}

func newSessionIssuer(executor IssueExecutor, c IssuerConfig, otp bool) (*SessionIssuer, error) {
	if issuerNil(executor) || issuerNil(c.Clock) || (!otp && c.Authority == nil) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.LookupKey.state == nil || c.TokenSize < 32 || c.TokenSize > 64 || c.Cookie.name == "" {
		return nil, ErrInvalidIssuer
	}
	return &SessionIssuer{executor: executor, config: c, otp: otp}, nil
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
// Retain Request for proof-route recovery; OTP recovery must use separate
// code-free native correlation; password recovery must be password/cookie-free.
// Do not Prepare again to retry an unknown command.
type PreparedIssuance struct{ state *preparedIssuanceState }
type preparedIssuanceState struct {
	owner     *SessionIssuer
	request   IssueRequest
	token     Token
	attempted atomic.Bool
	csrf      CSRFToken
	csrfReady atomic.Bool
	otp       *otpPreparationState
	password  *passwordPreparationState
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
	if s == nil || s.otp || s.password || spec.Lookup != (TokenDigest{}) {
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
	token, record, csrf, e := s.prepareTokenRecord(record)
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
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: request, token: token, csrf: csrf}}, nil
}

func (s *SessionIssuer) prepareTokenRecord(record Session) (Token, Session, CSRFToken, error) {
	fail := func(e error) (Token, Session, CSRFToken, error) { return Token{}, Session{}, CSRFToken{}, e }
	spec, e := record.Bindings()
	if e != nil {
		return fail(e)
	}
	token, e := NewToken(s.config.TokenSize)
	if e != nil {
		return fail(e)
	}
	spec.Lookup, e = token.Digest(s.config.LookupKey, string(spec.TenantID))
	if e != nil {
		return fail(e)
	}
	record, e = newSession(spec, record.OTPAuthentication())
	if e != nil {
		return fail(e)
	}
	var csrf CSRFToken
	if s.csrfKey.key.state != nil {
		csrf, record, e = prepareCSRFRecord(record, s.csrfKey)
		if e != nil {
			return fail(e)
		}
	}
	return token, record, csrf, nil
}

// CSRFToken returns the original reveal-once token only after this preparation
// completes an exact new error-free Issue within delivery bounds. Before that,
// after recovery-only observations, and for tokenless profiles it denies. Copies
// share the same reveal permission; repeated access does not create a new token.
// Holding a returned token does not certify current session authority. An
// earlier successful delivery remains owned even if a later retry is rejected,
// just as an already returned bearer cannot be retracted from its recipient.
func (p PreparedIssuance) CSRFToken() (CSRFToken, error) {
	if p.state == nil || !p.state.csrfReady.Load() || p.state.csrf.token.state == nil {
		return CSRFToken{}, ErrInvalidCSRF
	}
	return p.state.csrf, nil
}

// Request returns the original proof-route command/proof for durable recovery,
// without bearer bytes. Zero, OTP and password preparations deny: secret-bearing
// consuming commands must never be advertised as safe recovery input.
func (p PreparedIssuance) Request() (IssueRequest, bool) {
	if p.state == nil || p.state.otp != nil || p.state.password != nil {
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
	binding, _, _, ok := p.state.request.issuanceScope()
	if !ok {
		return out, ErrInvalidIssuance
	}
	out.CommandID = binding.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if e := s.validateRequestAt(p.state.request, s.config.Clock.Now()); e != nil {
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
	if s.otp {
		if e := validateOTPIssuanceAt(out.Session, now); e != nil {
			return out, e
		}
	}
	if s.password {
		if e := validatePasswordIssuanceAt(out.Session, now); e != nil {
			return out, e
		}
	}
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
	p.state.csrfReady.Store(true)
	return out, nil
}

// Recover performs only an authorized, bounded primary outcome lookup for the
// original request. Proof expiry does not prohibit historical recovery; current
// result-access policy belongs to the executor. It never executes, regenerates,
// reveals or redelivers a credential, even when recovery proves Committed.
// This is proof-profile recovery only. OTP and password requests are rejected;
// consuming native composition must provide separate code-free correlation.
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
	if s == nil || s.otp || s.password || ctx == nil || r.state == nil || r.state.otp != nil || r.state.password != nil {
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
	binding, operation, record, _ := r.issuanceScope()
	out.CommandID = binding.CommandID
	out.CommitOutcome = identity.CommitOutcomeUnknown
	receipt := e.Receipt
	after := uint64(0)
	if operation.RecordRequirement == identity.FeatureRecordRequired {
		after = 1
	}
	if receipt.Validate() != nil || receipt.Binding != binding || receipt.Feature == nil || receipt.Feature.Operation != operation || (receipt.Outcome == identity.CommitOutcomeCommitted && (receipt.Feature.BeforeVersion != 0 || receipt.Feature.AfterVersion != after || !sameIssuedSession(e.Session, record))) || (receipt.Outcome != identity.CommitOutcomeCommitted && e.Session != (Session{})) {
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
	ac, ah := a.CredentialContinuation()
	bc, bh := b.CredentialContinuation()
	if e != nil || x.Authority.CompareCurrent(y.Authority) != nil || csrfSpec(a) != csrfSpec(b) || otpSpec(a) != otpSpec(b) || ah != bh || ac != bc {
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
