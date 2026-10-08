package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// RevokeOneExecutor is the storage-neutral execution boundary implemented by
// the owned durable adapter, not an application domain store. It authenticates
// original request custody, authorizes current policy before reservation and
// atomically compares current source/target owners with mutation, audit and
// lifecycle effects. It must honor ctx, preserve original admission expiry and
// be concurrency-safe. A zero receipt conveys no authoritative observation;
// panic, unavailable or malformed responses never prove rollback. Historical
// recovery belongs to that same durable owner, not a second command journal.
// Requests carrying CSRFToken require the executor's own trusted named-key
// selection and exact original-primary CSRF admission in that same transaction;
// an executor lacking that profile must reject them before reservation.
type RevokeOneExecutor interface {
	ExecuteRevokeOne(context.Context, RevokeOneRequest) (identity.CommandResult, error)
}

// SignOutConfig selects trusted self-service policy and exact host-cookie
// deletion attributes. MaximumDuration is 1ms..30s for the whole operation;
// earlier caller/primary validity deadlines still win. PolicyID and positive
// PolicyVersion must match the owned executor's deployment configuration.
// Cookie must be valid even when bearer transport is selected. Zero is invalid.
type SignOutConfig struct {
	Cookie          CookiePolicy
	PolicyID        string
	PolicyVersion   uint64
	MaximumDuration time.Duration
}

// SignOutService owns bounded self-signout composition through the exact trusted
// reader and durable executor. It starts no goroutines and owns no store, locks,
// command journal or transaction. Dependencies are borrowed, must outlive calls
// and be concurrency-safe. Ordinary signout requires no fresh login. Other
// sessions, family authority and client transports remain unchanged.
type SignOutService struct {
	sessions *SessionService
	executor RevokeOneExecutor
	config   SignOutConfig
}

// NewSignOutService validates immutable composition without IO. Use the owned
// primary SessionService and native executor configured for that exact reader;
// structural records or consumer-written repositories are not authentication.
func NewSignOutService(sessions *SessionService, executor RevokeOneExecutor, c SignOutConfig) (*SignOutService, error) {
	if sessions == nil || sessions.reader == nil || issuerNil(executor) || c.Cookie.name == "" || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, ErrInvalidInput
	}
	// Use the upstream command grammar rather than inventing a second policy-ID
	// validator. These fixed placeholder IDs are validation only, never authority.
	b := signOutBinding(SignOutRequest{TenantID: "validation", CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "validation"}, c, "validation", "validation")
	if b.ValidateFor(RevokeOneOperation()) != nil {
		return nil, ErrInvalidInput
	}
	c.PolicyID = strings.Clone(c.PolicyID)
	return &SignOutService{sessions: sessions, executor: executor, config: c}, nil
}

// SignOutRequest selects one tenant and transport, with optional credential.
// CommandID is caller-generated and retained for ambiguous-outcome recovery;
// CorrelationID is bounded safe correlation, not authority. A zero Credential
// means absent. A present credential must exactly match Transport; HTTP owns
// canonical parsing, mixed-source rejection and cookie origin/CSRF protection.
// The request cannot select a user, target session or policy. Do not mutate it
// concurrently with a call. Zero is invalid.
type SignOutRequest struct {
	TenantID      identity.TenantID
	CommandID     identity.CommandID
	CorrelationID string
	Transport     CredentialKind
	Credential    Credential
}

// SignOutResult distinguishes successful transport removal from a durable
// command observation. SignedOut is true only after absent/primary-denied
// credentials or exact committed execution with no delivery error. Invalid
// CommitOutcome means no authoritative command outcome was observed, including
// already-absent idempotent success; it is not a fabricated NotCommitted result.
// Cookie is empty-valued secure deletion metadata only when ClearCookie is true;
// bearer signout sets ClearBearer and never clears a cookie. CommitOutcome and
// Recovery retain exact metadata even on cancellation or unknown outcome.
// Recovery is a scope locator, not lookup permission or authentication. The
// owned executor's historical query requires current result-access policy.
type SignOutResult struct {
	SignedOut, ClearCookie, ClearBearer bool
	CommandID                           identity.CommandID
	CommitOutcome                       identity.CommitOutcome
	RetryAfter                          time.Duration
	Cookie                              http.Cookie
	Recovery                            identity.RecoveryQuery
}

// SignOut authenticates the presented credential on the primary, prepares an
// exact self-target command and invokes the sole durable owner. Absent,
// inactive and already-revoked credentials succeed without another mutation.
// Reader outages, ambiguity, policy denial and cancellation do not become
// successful logout or cookie deletion. Retries must not mint replacements for
// an unknown command: query its retained Recovery scope first. The adapter
// preserves original caller validity through commit; this service never renews
// it. No raw credential is revealed or stored. All dependency errors are redacted.
func (s *SignOutService) SignOut(ctx context.Context, r SignOutRequest) (out SignOutResult, err error) {
	return s.signOut(ctx, r, CSRFToken{}, nil)
}

func (s *SignOutService) signOut(ctx context.Context, r SignOutRequest, csrf CSRFToken, keys []CSRFKey) (out SignOutResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.SignedOut, out.ClearCookie, out.ClearBearer = false, false, false
			out.Cookie = http.Cookie{}
			if entered {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if s == nil || ctx == nil || s.sessions == nil || issuerNil(s.executor) || (r.Transport != CredentialCookie && r.Transport != CredentialBearer) || (r.Credential != (Credential{}) && (r.Credential.token.state == nil || r.Credential.kind != r.Transport)) {
		return out, ErrInvalidInput
	}
	strict, strictProfile := s.executor.(CSRFRevokeOneExecutor)
	if len(keys) > 0 && (!strictProfile || issuerNil(strict)) {
		return out, ErrInvalidInput
	}
	b := signOutBinding(r, s.config, "validation", "validation")
	if b.ValidateFor(RevokeOneOperation()) != nil {
		return out, ErrInvalidInput
	}
	out.CommandID = r.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if ctx.Err() != nil {
		return out, sessionReadFailure(ctx)
	}
	if r.Credential == (Credential{}) {
		return s.signedOut(out, r.Transport), nil
	}
	caller, err := s.sessions.Get(ctx, GetRequest{TenantID: r.TenantID, Credential: r.Credential})
	if err != nil {
		return out, signOutError(err)
	}
	if ctx.Err() != nil {
		return out, sessionReadFailure(ctx)
	}
	if !caller.Authenticated {
		return s.signedOut(out, r.Transport), nil
	}
	spec, err := caller.Session.Bindings()
	if err != nil {
		return out, ErrUnavailable
	}
	b = signOutBinding(r, s.config, spec.UserID, spec.SessionID)
	command, err := NewRevokeOneCommand(b, caller.Session)
	if err != nil {
		return out, signOutError(err)
	}
	var request RevokeOneRequest
	if len(keys) == 0 {
		request, err = s.sessions.PrepareRevokeOne(caller, command)
	} else {
		state, stateErr := caller.Session.CSRFState().Bindings()
		if stateErr != nil {
			return out, ErrCSRFDenied
		}
		var selected CSRFKey
		for _, key := range keys {
			if key.Version() == state.KeyVersion {
				selected = key
				break
			}
		}
		request, err = s.sessions.PrepareRevokeOneWithCSRF(caller, command, csrf, selected)
	}
	if err != nil {
		return out, signOutError(err)
	}
	out.Recovery = identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	if ctx.Err() != nil {
		return out, sessionReadFailure(ctx)
	}
	entered = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	var receipt identity.CommandResult
	var dependencyErr error
	if len(keys) > 0 {
		receipt, dependencyErr = strict.ExecuteRevokeOneWithCSRF(ctx, request)
	} else {
		receipt, dependencyErr = s.executor.ExecuteRevokeOne(ctx, request)
	}
	// A typed denial with no receipt is the adapter's pre-reservation rejection,
	// not a rollback claim. Other missing or inconsistent replies remain Unknown.
	var forbidden identity.ForbiddenError
	if receipt == (identity.CommandResult{}) && dependencyErr != nil && (errors.As(dependencyErr, &forbidden) || errors.Is(dependencyErr, ErrUnauthenticated) || errors.Is(dependencyErr, ErrInvalidInput) || errors.Is(dependencyErr, ErrCSRFDenied)) {
		out.CommitOutcome = identity.CommitOutcomeInvalid
		return out, signOutError(dependencyErr)
	}
	if receipt.Validate() != nil || receipt.Binding != b || receipt.Feature == nil || receipt.Feature.Operation != RevokeOneOperation() || (receipt.Outcome == identity.CommitOutcomeCommitted && (receipt.Feature.BeforeVersion != spec.Version || receipt.Feature.AfterVersion != spec.Version+1)) {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	out.CommitOutcome, out.RetryAfter = receipt.Outcome, receipt.RetryAfter
	switch receipt.Outcome {
	case identity.CommitOutcomeCommitted:
		if ctx.Err() != nil {
			return out, sessionReadFailure(ctx)
		}
		if dependencyErr != nil {
			return out, signOutError(dependencyErr)
		}
		return s.signedOut(out, r.Transport), nil
	case identity.CommitOutcomeNotCommitted:
		if dependencyErr != nil {
			return out, signOutError(dependencyErr)
		}
		return out, identity.NotCommittedError{CommandID: out.CommandID}
	case identity.CommitOutcomeConflict:
		return out, identity.ConflictError{CommandID: out.CommandID}
	case identity.CommitOutcomeInProgress:
		return out, identity.InProgressError{CommandID: out.CommandID, RetryAfter: out.RetryAfter}
	default:
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
}

func signOutBinding(r SignOutRequest, c SignOutConfig, user identity.UserID, id string) identity.CommandBinding {
	op := RevokeOneOperation()
	return identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: r.CorrelationID, RecordID: id}
}

func (s *SignOutService) signedOut(out SignOutResult, kind CredentialKind) SignOutResult {
	out.SignedOut = true
	if kind == CredentialCookie {
		out.ClearCookie = true
		out.Cookie, _ = s.config.Cookie.DeletionAttributes()
	} else {
		out.ClearBearer = true
	}
	return out
}

func signOutError(err error) error {
	var forbidden identity.ForbiddenError
	var cancelled identity.CancelledError
	var deadline identity.DeadlineExceededError
	switch {
	case errors.As(err, &forbidden):
		return identity.ForbiddenError{}
	case errors.As(err, &cancelled), errors.Is(err, context.Canceled):
		return identity.CancelledError{}
	case errors.As(err, &deadline), errors.Is(err, context.DeadlineExceeded):
		return identity.DeadlineExceededError{}
	case errors.Is(err, ErrUnauthenticated):
		return ErrUnauthenticated
	case errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrCSRFDenied):
		return ErrCSRFDenied
	default:
		return ErrUnavailable
	}
}

// Format redacts correlated transport and command metadata.
func (SignOutRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SignOutRequest(redacted)")
}

// MarshalJSON rejects implicit credential persistence.
func (SignOutRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit credential disclosure.
func (SignOutRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts historical command/transport scope.
func (SignOutResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SignOutResult(redacted)")
}

// MarshalJSON rejects implicit command or transport export.
func (SignOutResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit scope disclosure.
func (SignOutResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts configured policy and cookie metadata.
func (SignOutConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SignOutConfig(redacted)")
}

// MarshalJSON rejects implicit deployment configuration export.
func (SignOutConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts borrowed runtime dependencies.
func (SignOutService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SignOutService(redacted)")
}

// MarshalJSON rejects implicit runtime composition export.
func (SignOutService) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
