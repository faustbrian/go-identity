package session

import (
	"errors"
	"fmt"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"io"
	"time"
)

// ErrRotationDeferred means the original policy's refresh interval has not
// elapsed. No token, command reservation or accepted-activity update is made.
var ErrRotationDeferred = errors.New("session: rotation deferred")

// RotationCommandSpec fixes an original record and one exact successor.
// Only lookup digest, synchronizer state, activity and session version may change. Family,
// owner, authentication, remember policy and all other authority are preserved.
// These are structural projections, never proof of authentication or commitment.
type RotationCommandSpec struct {
	Binding           identity.CommandBinding
	Source, Successor Session
}

// RotateOperation identifies the exact refresh/rotation command. Ordinary token
// rotation is distinct from family revocation and does not renew authentication.
func RotateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.refresh", SchemaID: "session-refresh", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewRotateCommand freezes an exact self-owned single-version transition. The
// source must be live and refresh-due at the successor's accepted-activity time;
// a representable version successor and a different nonzero digest are required.
// It grants no authority. The owned executor must preserve original opaque
// admission, compare all current owners, atomically retire the old digest without
// a reuse window, persist the successor/audit/lifecycle/receipt, and handle
// retired-token reuse through the same family/command owner.
func NewRotateCommand(b identity.CommandBinding, source, successor Session) (SessionCommand, error) {
	old, err := source.Bindings()
	next, e := successor.Bindings()
	if err != nil || e != nil || b.ValidateFor(RotateOperation()) != nil || b.TenantID != old.TenantID || b.UserID != old.UserID || b.RecordID != old.SessionID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(old.UserID) || old.Version == ^uint64(0) || next.Version != old.Version+1 || next.Lookup.Sum == old.Lookup.Sum {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	life, err := source.Lifetime(next.LastActivityAt)
	if err != nil {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	if !life.RefreshDue {
		return SessionCommand{}, ErrRotationDeferred
	}
	expected := old
	expected.Lookup, expected.LastActivityAt, expected.Version = next.Lookup, next.LastActivityAt, next.Version
	vector, _ := old.Authority.Bindings()
	vector.Session.Version = next.Version
	expected.Authority, err = NewAuthoritySnapshot(vector)
	if err != nil {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	record, err := rebuildSession(expected, source, CSRFState{})
	if successor.CSRFState().state != nil {
		if source.CSRFState().state != nil && csrfSpec(source).Digest == csrfSpec(successor).Digest {
			return SessionCommand{}, ErrInvalidSessionCommand
		}
		record, err = rebuildSession(expected, source, successor.CSRFState())
	}
	if err != nil || !sameIssuedSession(record, successor) {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	return SessionCommand{rotation: &RotationCommandSpec{cloneCommandBinding(b), source, successor}}, nil
}

// Rotation returns the exact immutable structural projection. False means a
// zero or different variant; this value loses private authenticated custody.
func (c SessionCommand) Rotation() (RotationCommandSpec, bool) {
	if c.rotation == nil || c.issue != nil || c.revokeFamily != nil || c.revokeOne != nil || c.revokeSet != nil {
		return RotationCommandSpec{}, false
	}
	return *c.rotation, true
}

// ValidateRotationAt rechecks original exclusive lifetime and rejects a future
// prepared activity time. It performs no IO and neither authenticates a source
// nor refreshes current authority; the original admission deadline also applies.
func (c SessionCommand) ValidateRotationAt(now time.Time) error {
	r, ok := c.Rotation()
	if !ok {
		return ErrInvalidSessionCommand
	}
	next, _ := r.Successor.Bindings()
	if _, err := r.Source.Lifetime(now); err != nil {
		return err
	}
	if next.LastActivityAt.After(now) {
		return ErrInvalidTime
	}
	_, err := r.Successor.Lifetime(now)
	return err
}

// RotationRequest retains the exact command and original opaque same-reader
// caller/transport admission. Zero is invalid; copies never renew its deadline.
// No credential or caller-built principal can substitute this custody.
type RotationRequest struct{ state *rotationRequestState }
type rotationRequestState struct {
	command SessionCommand
	caller  GetResult
}

// PrepareRotation binds only the authenticating session's exact original record
// to its structurally valid successor. Original lifetime and admission must be
// live; ordinary rotation does not require a fresh login or unexpired historical
// sign-in proof. Current policy/owner comparison and atomic effects remain owned
// executor obligations. No IO, consumption, durable command or reveal occurs.
func (s *SessionService) PrepareRotation(caller GetResult, command SessionCommand) (out RotationRequest, err error) {
	defer func() {
		if recover() != nil {
			out, err = RotationRequest{}, ErrUnavailable
		}
	}()
	if s == nil || s.reader == nil {
		return out, ErrInvalidInput
	}
	now := s.config.Clock.Now()
	if caller.validity == nil || caller.validity.owner != s || caller.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	r, ok := command.Rotation()
	if !ok {
		return out, ErrInvalidSessionCommand
	}
	if !sameIssuedSession(r.Source, caller.Session) {
		return out, ErrUnauthenticated
	}
	if err = command.ValidateRotationAt(now); err != nil {
		return out, err
	}
	return RotationRequest{state: &rotationRequestState{command, caller}}, nil
}

// Validate checks original private caller custody against the trusted service
// and current time before reservation and commit. The owner must additionally
// compare all current primary authorities; this does not renew or replace them.
func (r RotationRequest) Validate(s *SessionService, now time.Time) error {
	if r.state == nil || s == nil || r.state.caller.validity == nil || r.state.caller.validity.owner != s {
		return ErrUnauthenticated
	}
	if err := r.state.caller.ValidateAt(now); err != nil {
		return err
	}
	return r.state.command.ValidateRotationAt(now)
}

// Command returns the exact structural intent, never private caller authority.
func (r RotationRequest) Command() (SessionCommand, bool) {
	if r.state == nil {
		return SessionCommand{}, false
	}
	return r.state.command, true
}

// ValidUntil preserves the original exclusive source admission deadline.
func (r RotationRequest) ValidUntil() time.Time {
	if r.state == nil {
		return time.Time{}
	}
	return r.state.caller.ValidUntil()
}

// Transport returns the original admitted credential transport, never a caller
// override or permission to change cookie/header profile. Zero returns zero.
func (r RotationRequest) Transport() CredentialKind {
	if r.state == nil || r.state.caller.validity == nil {
		return 0
	}
	return r.state.caller.validity.transport
}

// Format redacts source, successor and admission linkage.
func (RotationRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RotationRequest(redacted)")
}

// MarshalJSON rejects implicit request serialization.
func (RotationRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit text/map-key disclosure.
func (RotationRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
