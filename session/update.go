package session

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// UpdateCommandSpec freezes a self-session metadata CAS. DeviceLabel is
// untrusted display text, at most128 UTF-8 bytes without control runes; empty
// clears it. Successor changes only the session version and its exact authority
// binding. Labels are not authentication, device trust or authorization facts.
// The projection grants no custody, permission or commitment.
type UpdateCommandSpec struct {
	Binding           identity.CommandBinding
	Source, Successor Session
	DeviceLabel       string
}

// UpdateOperation identifies the native session metadata mutation. The sole
// durable coordinator must atomically retain label, CAS, audit/lifecycle and
// recovery receipt; core neither imports an adapter nor opens a transaction.
func UpdateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.update", SchemaID: "session-update", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewUpdateCommand prepares the exact self-owned source-version transition.
// Binding.RecordID must be the source session, with the effective user also
// the actor. A checked version successor invalidates old session projections;
// lookup, activity, authentication, remember policy and all unrelated authority
// remain unchanged. It performs no IO and cannot authenticate a caller. The
// separately bound synchronizer state is cleared, never carried into the new
// version or replaced without original credential-delivery ownership. Protected
// cookie work must deny until an owned authorized flow issues replacement state.
// source's version is the expected CAS; overflow, malformed labels, foreign
// scope and zero fail with ErrInvalidSessionCommand before copying input.
func NewUpdateCommand(b identity.CommandBinding, source Session, label string) (SessionCommand, error) {
	old, err := source.Bindings()
	if err != nil || !validListLabel(label) || b.ValidateFor(UpdateOperation()) != nil || b.TenantID != old.TenantID || b.UserID != old.UserID || b.RecordID != old.SessionID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(old.UserID) || old.Version == ^uint64(0) {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	next := old
	next.Version++
	vector, _ := old.Authority.Bindings()
	vector.Session.Version = next.Version
	next.Authority, err = NewAuthoritySnapshot(vector)
	if err != nil {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	successor, err := rebuildSession(next, source, CSRFState{})
	if err != nil {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	return SessionCommand{update: &UpdateCommandSpec{Binding: cloneCommandBinding(b), Source: source, Successor: successor, DeviceLabel: strings.Clone(label)}}, nil
}

// Update returns a scalar caller-owned projection; changing it cannot mutate
// the command. Zero or another variant returns false. Source and Successor
// remain immutable records, not evidence of active state or caller admission.
func (c SessionCommand) Update() (UpdateCommandSpec, bool) {
	if c.update == nil || c.issue != nil || c.rotation != nil || c.revokeOne != nil || c.revokeFamily != nil || c.revokeSet != nil {
		return UpdateCommandSpec{}, false
	}
	return *c.update, true
}

// ValidateUpdateAt checks only original session lifetime at trusted now.
// Ordinary display metadata does not require fresh login and never refreshes
// accepted activity. Current authorization and every authority comparison must
// still be established by the executor, with original private caller custody.
func (c SessionCommand) ValidateUpdateAt(now time.Time) error {
	u, ok := c.Update()
	if !ok {
		return ErrInvalidSessionCommand
	}
	_, err := u.Source.Lifetime(now)
	return err
}

// UpdateCommandRequest binds an immutable native update to original opaque
// admission from one exact SessionService. Zero is invalid; copies preserve
// the exclusive source deadline. No raw credential or caller-built principal
// can replace this custody. Durable policy/owner validation remains required.
type UpdateCommandRequest struct{ state *updateRequestState }
type updateRequestState struct {
	command SessionCommand
	caller  GetResult
}

// PrepareUpdate admits only the exact currently authenticating source record,
// not another same-user device. It does no IO, mutation or authorization. A
// forged, modified, foreign-service or expired caller fails closed. Freshness
// for safe display metadata is not renewed or required. Clock panics redact.
func (s *SessionService) PrepareUpdate(caller GetResult, command SessionCommand) (out UpdateCommandRequest, err error) {
	defer func() {
		if recover() != nil {
			out, err = UpdateCommandRequest{}, ErrUnavailable
		}
	}()
	if s == nil || s.reader == nil {
		return out, ErrInvalidInput
	}
	now := s.config.Clock.Now()
	if caller.validity == nil || caller.validity.owner != s || caller.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	u, ok := command.Update()
	if !ok {
		return out, ErrInvalidSessionCommand
	}
	if !sameIssuedSession(u.Source, caller.Session) {
		return out, ErrUnauthenticated
	}
	if err = command.ValidateUpdateAt(now); err != nil {
		return out, err
	}
	return UpdateCommandRequest{state: &updateRequestState{command, caller}}, nil
}

// Validate checks original custody and exclusive deadline at trusted now;
// the owned executor must call it before reservation and final commit and
// independently compare current primary state and operation policy. It does
// not extend freshness, authenticate structural fields or mutate any store.
func (r UpdateCommandRequest) Validate(s *SessionService, now time.Time) error {
	if r.state == nil || s == nil || r.state.caller.validity == nil || r.state.caller.validity.owner != s {
		return ErrUnauthenticated
	}
	if err := r.state.caller.ValidateAt(now); err != nil {
		return err
	}
	return r.state.command.ValidateUpdateAt(now)
}

// Command returns structural intent without transferring caller custody.
// Zero returns false. Restoring a command cannot reconstruct this request.
func (r UpdateCommandRequest) Command() (SessionCommand, bool) {
	if r.state == nil {
		return SessionCommand{}, false
	}
	return r.state.command, true
}

// ValidUntil returns the original exclusive admission deadline; zero returns
// zero. Reading, copying or retrying this request cannot move that deadline.
func (r UpdateCommandRequest) ValidUntil() time.Time {
	if r.state == nil {
		return time.Time{}
	}
	return r.state.caller.ValidUntil()
}

// Transport returns the admitted cookie/bearer transport, never a caller
// override. Zero returns zero. Updating metadata cannot change transport.
func (r UpdateCommandRequest) Transport() CredentialKind {
	if r.state == nil || r.state.caller.validity == nil {
		return 0
	}
	return r.state.caller.validity.transport
}

// Format redacts labels, source records, scope and authority for all verbs.
func (UpdateCommandSpec) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.UpdateCommandSpec(redacted)")
}

// MarshalJSON denies implicit label and structural record disclosure.
func (UpdateCommandSpec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit label and structural record disclosure.
func (UpdateCommandSpec) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated mutation and caller custody.
func (UpdateCommandRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.UpdateCommandRequest(redacted)")
}

// MarshalJSON denies implicit request persistence and custody export.
func (UpdateCommandRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit text and map-key custody disclosure.
func (UpdateCommandRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
