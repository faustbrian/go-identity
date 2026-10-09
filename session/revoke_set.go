package session

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// ErrFreshnessRequired denies a sensitive session action after the original
// completed authentication's configured freshness interval. Reading activity,
// copying admission or rotating a session cannot renew that interval.
var ErrFreshnessRequired = errors.New("session: fresh authentication required")

// RevokeSetCommandSpec freezes user-owned bulk revocation with its exact
// authenticating source record. Binding.RecordID is that exact source session ID;
// Binding.UserID fixes the effective owner of the selected set. IncludeCurrent is false for
// revoke-other and explicit for revoke-all. MaximumSessions is an all-or-nothing
// active-row bound of 1..100000, not permission to truncate or paginate mutations.
// The durable owner must lock source/current user authority and serialize with
// issuance, atomically revoke every selected user session (across audiences),
// audit and retain command recovery. Preserve complete historical records and
// never reset lifetime or authentication freshness. When the source survives,
// only its existing session version advances, with its matching snapshot binding;
// a user-wide authority bump must not accidentally invalidate that survivor.
// This structural projection is neither authentication nor an executed workflow.
type RevokeSetCommandSpec struct {
	Binding         identity.CommandBinding
	Caller          Session
	IncludeCurrent  bool
	MaximumSessions uint32
}

// RevokeOtherOperation identifies fresh self-service revocation excluding the
// authenticating source. This is distinct from a family or single-session command.
func RevokeOtherOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.revoke-other", SchemaID: "session-revoke-other", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// RevokeAllOperation identifies fresh self-service set revocation with explicit
// source disposition, not administrative revocation or global account blocking.
func RevokeAllOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.revoke-all", SchemaID: "session-revoke-all", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewRevokeOtherCommand freezes exact self-owned inputs without IO or authority.
// Current custody/freshness, authorization, bounded atomic execution and recovery
// belong to the configured service and durable owner. Zero values are invalid.
func NewRevokeOtherCommand(b identity.CommandBinding, caller Session, maximum uint32) (SessionCommand, error) {
	return newRevokeSetCommand(b, caller, false, maximum, RevokeOtherOperation())
}

// NewRevokeAllCommand freezes exact self-owned inputs and explicit current
// disposition without IO or authority. It cannot select another user's sessions.
// The durable owner must retain per-session tombstones and protect a survivor's
// lifetime while invalidating older source-version projections. Zero is invalid.
func NewRevokeAllCommand(b identity.CommandBinding, caller Session, includeCurrent bool, maximum uint32) (SessionCommand, error) {
	return newRevokeSetCommand(b, caller, includeCurrent, maximum, RevokeAllOperation())
}

func newRevokeSetCommand(b identity.CommandBinding, caller Session, includeCurrent bool, maximum uint32, op identity.FeatureOperation) (SessionCommand, error) {
	spec, err := caller.Bindings()
	if err != nil || b.ValidateFor(op) != nil || b.TenantID != spec.TenantID || b.UserID != spec.UserID || b.RecordID != spec.SessionID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(spec.UserID) || spec.Version == ^uint64(0) || maximum < 1 || maximum > 100000 {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	return SessionCommand{revokeSet: &RevokeSetCommandSpec{Binding: cloneCommandBinding(b), Caller: caller, IncludeCurrent: includeCurrent, MaximumSessions: maximum}}, nil
}

// RevokeSet returns a scalar caller-owned projection; copies cannot change the
// original command. False means zero or another closed variant. The projection
// loses private caller admission and never grants permission or proves a commit.
func (c SessionCommand) RevokeSet() (RevokeSetCommandSpec, bool) {
	if c.revokeSet == nil || c.issue != nil || c.revokeOne != nil || c.revokeFamily != nil {
		return RevokeSetCommandSpec{}, false
	}
	return *c.revokeSet, true
}

// RevokeSetRequest binds an immutable bulk command to the original opaque Get
// admission from one exact configured reader. Zero is invalid. Copies cannot
// renew authority or authentication freshness. This is not permission: the owned
// executor must authorize and recheck source/current owner state in the sole
// transaction before revocation, audit, lifecycle effects and commit.
type RevokeSetRequest struct{ state *revokeSetRequestState }

type revokeSetRequestState struct {
	command SessionCommand
	caller  GetResult
	until   time.Time
}

// PrepareRevokeSet requires positive, currently fresh caller admission from this
// exact service and the entire unchanged authenticating record in the command.
// It performs no IO/mutation and never accepts caller-built principal metadata.
// Its effective exclusive deadline is the earlier original admission expiry or
// authentication freshness boundary. Clock failures are redacted.
func (s *SessionService) PrepareRevokeSet(caller GetResult, command SessionCommand) (out RevokeSetRequest, err error) {
	defer func() {
		if recover() != nil {
			out, err = RevokeSetRequest{}, ErrUnavailable
		}
	}()
	if s == nil || s.reader == nil {
		return out, ErrInvalidInput
	}
	now := s.config.Clock.Now()
	if caller.validity == nil || caller.validity.owner != s || caller.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	set, ok := command.RevokeSet()
	if !ok {
		return out, ErrInvalidSessionCommand
	}
	if !sameIssuedSession(set.Caller, caller.Session) {
		return out, ErrUnauthenticated
	}
	lifetime, e := caller.Session.Lifetime(now)
	if e != nil {
		return out, ErrUnauthenticated
	}
	if !lifetime.Fresh {
		return out, ErrFreshnessRequired
	}
	spec, _ := caller.Session.Bindings()
	freshUntil := caller.Session.authenticatedAt().Add(spec.Remember.fresh)
	if !validTime(freshUntil) {
		return out, ErrUnavailable
	}
	until := caller.ValidUntil()
	if freshUntil.Before(until) {
		until = freshUntil
	}
	return RevokeSetRequest{state: &revokeSetRequestState{command: command, caller: caller, until: until.UTC()}}, nil
}

// Validate checks original private provenance and exclusive authority/freshness
// deadlines at trusted now. The owned executor calls it before reservation and
// final commit; mapped fields or Caller are never substitutes for this custody.
// It does not reread authority, renew admission, authorize or mutate a store.
func (r RevokeSetRequest) Validate(service *SessionService, now time.Time) error {
	if r.state == nil || service == nil || r.state.caller.validity == nil || r.state.caller.validity.owner != service {
		return ErrUnauthenticated
	}
	if err := r.state.caller.ValidateAt(now); err != nil {
		return err
	}
	lifetime, err := r.state.caller.Session.Lifetime(now)
	if err != nil {
		return ErrUnauthenticated
	}
	if !lifetime.Fresh {
		return ErrFreshnessRequired
	}
	if !now.Before(r.state.until) {
		return ErrUnauthenticated
	}
	return nil
}

// Command returns the immutable structural projection; zero returns false.
// It does not transfer opaque caller custody or authorize execution.
func (r RevokeSetRequest) Command() (SessionCommand, bool) {
	if r.state == nil {
		return SessionCommand{}, false
	}
	return r.state.command, true
}

// Caller returns historical source metadata; zero returns zero. The exact
// service-bound request, not this projection, is required for execution.
func (r RevokeSetRequest) Caller() Session {
	if r.state == nil {
		return Session{}
	}
	return r.state.caller.Session
}

// ValidUntil returns the earlier original authority/freshness deadline; zero
// returns zero. The timestamp itself cannot authenticate a source or renew it.
func (r RevokeSetRequest) ValidUntil() time.Time {
	if r.state == nil {
		return time.Time{}
	}
	return r.state.until
}

// Format redacts correlated command and caller custody for every diagnostic verb.
func (RevokeSetRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeSetRequest(redacted)")
}

// MarshalJSON denies implicit custody persistence/export.
func (RevokeSetRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit text/map-key export.
func (RevokeSetRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts structural user/source projections.
func (RevokeSetCommandSpec) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeSetCommandSpec(redacted)")
}

// MarshalJSON denies implicit structural projection export.
func (RevokeSetCommandSpec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
