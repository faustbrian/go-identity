package session

import (
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization"
)

// RevokeOneRequest retains an exact target command and the original opaque
// authenticated caller admission. Zero is invalid. Copies preserve the original
// exclusive deadline; no constructor accepts caller-built principal fields.
// This is authentication custody, not policy permission, durable execution or
// evidence that the target is still active. The owned executor must recheck
// original caller and target owners, policy and deadline in its sole transaction.
type RevokeOneRequest struct{ state *revokeOneRequestState }

type revokeOneRequestState struct {
	command SessionCommand
	caller  GetResult
}

// PrepareRevokeOne freezes a target command with a positive Get result from
// this exact configured service. It performs no IO, reservation or mutation and
// never renews admission. The target must share the caller's tenant, effective
// user and audience; the command actor must be that user. A same-ID target must
// retain the entire original caller record, not just its version. Independent
// sibling targets remain distinct from the authenticating source session.
// Ordinary logout does not require fresh login. Policy authorization, current
// owner locks and idempotent absent/revoked handling remain executor obligations.
// Clock failures are redacted. Dependencies must remain alive through execution.
func (s *SessionService) PrepareRevokeOne(caller GetResult, command SessionCommand) (out RevokeOneRequest, err error) {
	defer func() {
		if recover() != nil {
			out, err = RevokeOneRequest{}, ErrUnavailable
		}
	}()
	if s == nil || s.reader == nil {
		return out, ErrInvalidInput
	}
	if caller.validity == nil || caller.validity.owner != s || caller.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrUnauthenticated
	}
	target, ok := command.RevokeOne()
	if !ok {
		return out, ErrInvalidSessionCommand
	}
	source, _ := caller.Session.Bindings()
	destination, _ := target.Session.Bindings()
	if destination.TenantID != source.TenantID || destination.UserID != source.UserID || destination.Audience != source.Audience || target.Binding.ActorKind != authorization.SubjectUser || string(target.Binding.ActorID) != string(source.UserID) || (destination.SessionID == source.SessionID && !sameIssuedSession(target.Session, caller.Session)) {
		return out, ErrUnauthenticated
	}
	return RevokeOneRequest{state: &revokeOneRequestState{command: command, caller: caller}}, nil
}

// Validate checks private caller provenance against trusted configured service
// and time, not request-selected dependencies. The original exclusive deadline,
// backward-clock and lifetime checks apply. It does not refresh authority or
// require fresh authentication. The durable owner must call this before
// reservation and final commit, and atomically compare current source/target
// owner bindings and policy; a structural Command or Caller cannot replace it.
func (r RevokeOneRequest) Validate(service *SessionService, now time.Time) error {
	if r.state == nil || service == nil || r.state.caller.validity == nil || r.state.caller.validity.owner != service {
		return ErrUnauthenticated
	}
	return r.state.caller.ValidateAt(now)
}

// Command returns the immutable exact target projection; zero returns false.
// This loses private caller custody and cannot independently authorize execution.
func (r RevokeOneRequest) Command() (SessionCommand, bool) {
	if r.state == nil {
		return SessionCommand{}, false
	}
	return r.state.command, true
}

// Caller returns the original authenticating source record, not the target.
// Zero returns zero. This is historical metadata only; the executor must use
// original opaque request admission and recheck this source's active owners.
func (r RevokeOneRequest) Caller() Session {
	if r.state == nil {
		return Session{}
	}
	return r.state.caller.Session
}

// ValidUntil returns the preserved original exclusive admission deadline.
// Zero returns zero. The timestamp alone cannot establish caller provenance.
func (r RevokeOneRequest) ValidUntil() time.Time {
	if r.state == nil {
		return time.Time{}
	}
	return r.state.caller.ValidUntil()
}

// Format prevents scope, credential and caller linkage disclosure.
func (RevokeOneRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeOneRequest(redacted)")
}

// MarshalJSON rejects implicit authentication request persistence/export.
func (RevokeOneRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects text and map-key disclosure of caller custody.
func (RevokeOneRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
