package otp

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ErrInvalidAuthorization rejects absent, mixed or unsupported continuation
// context without disclosing identifiers. It is not an existence lookup result.
var ErrInvalidAuthorization = errors.New("otp: invalid authorization context")

// FlowAuthorizationKind explicitly selects one disjoint context. Neither
// value proves authenticated status or current authorization; zero is invalid.
type FlowAuthorizationKind uint8

const (
	// FlowAuthorizationAuthenticatedSession selects an already authenticated
	// session, independently re-authorized by the protected operation owner.
	FlowAuthorizationAuthenticatedSession FlowAuthorizationKind = iota + 1
	// FlowAuthorizationPreAuthTransaction selects a purpose-bound, single-use
	// pre-auth transaction; it must never be treated as authenticated authority.
	FlowAuthorizationPreAuthTransaction
)

// FlowAuthorizationSpec is an explicit tagged union. Exactly the selected
// member must be nonzero; the other must be absent. Session IDs follow session's
// existing 1..128 visible ASCII contract. Pre-auth IDs use identity's canonical
// nonzero 128-bit ID contract. This is trusted structural data, not a proof.
type FlowAuthorizationSpec struct {
	Kind                   FlowAuthorizationKind
	AuthenticatedSessionID string
	PreAuthTransactionID   identity.PreAuthTransactionID
}

func (FlowAuthorizationSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.FlowAuthorizationSpec(redacted)")
}
func (FlowAuthorizationSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (FlowAuthorizationSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// FlowAuthorization freezes the validated discriminant and selected ID.
// Zero is invalid; immutable copies are safe for concurrent reads. Construction
// does not look up a session, verify authentication or reserve a pre-auth flow.
type FlowAuthorization struct{ spec FlowAuthorizationSpec }

// NewFlowAuthorization validates before copying and never infers Kind from
// subject, remember policy or a nonzero nullable member. No IO is performed.
func NewFlowAuthorization(s FlowAuthorizationSpec) (FlowAuthorization, error) {
	switch s.Kind {
	case FlowAuthorizationAuthenticatedSession:
		if len(s.AuthenticatedSessionID) < 1 || len(s.AuthenticatedSessionID) > 128 || s.PreAuthTransactionID != "" {
			return FlowAuthorization{}, ErrInvalidAuthorization
		}
		for _, r := range s.AuthenticatedSessionID {
			if r < 33 || r > 126 {
				return FlowAuthorization{}, ErrInvalidAuthorization
			}
		}
	case FlowAuthorizationPreAuthTransaction:
		if s.AuthenticatedSessionID != "" {
			return FlowAuthorization{}, ErrInvalidAuthorization
		}
		if _, e := identity.ParsePreAuthTransactionID(string(s.PreAuthTransactionID)); e != nil {
			return FlowAuthorization{}, ErrInvalidAuthorization
		}
	default:
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	s.AuthenticatedSessionID = strings.Clone(s.AuthenticatedSessionID)
	s.PreAuthTransactionID = identity.PreAuthTransactionID(strings.Clone(string(s.PreAuthTransactionID)))
	return FlowAuthorization{spec: s}, nil
}

// Bindings returns an owned structural projection, not authority. Zero returns
// ErrInvalidAuthorization. The owner must check tenant, active status, purpose,
// expiry and current authorization against primary state at consumption.
func (a FlowAuthorization) Bindings() (FlowAuthorizationSpec, error) {
	if a.spec.Kind == 0 {
		return FlowAuthorizationSpec{}, ErrInvalidAuthorization
	}
	return a.spec, nil
}

func (FlowAuthorization) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.FlowAuthorization(redacted)")
}
func (FlowAuthorization) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (FlowAuthorization) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ContinuationBindings is an explicit trusted persistence projection. Scope
// includes derived authorization binding; RememberPolicy is copied unchanged.
// It contains PII and is not a wire format, bearer or current validity proof.
type ContinuationBindings struct {
	Scope          DigestScopeSpec
	Authorization  FlowAuthorization
	RememberPolicy session.RememberPolicy
}

func (ContinuationBindings) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.ContinuationBindings(redacted)")
}
func (ContinuationBindings) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ContinuationBindings) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Continuation owns immutable exact scope and explicit authorization context.
// It is safe for concurrent use, but supplies no authority or durable state.
// Zero is invalid. Copies retain destination PII; release them after use.
type Continuation struct{ state *continuationState }
type continuationState struct {
	bindings ContinuationBindings
	scope    DigestScope
}

// NewContinuation derives the authorization binding; s.AuthorizationBinding
// must be zero, not caller-selected. Signin requires pre-auth context and a
// resolved session RememberPolicy. Pre-auth MFA carries the same policy;
// all other purposes require zero remember policy and never acquire persistence
// by fallback. Authenticated-session signin is forbidden. The owning workflow
// must verify the original context/policy against primary state; this constructor
// cannot certify provenance. No defaults, timestamps or lifetimes are renewed.
func NewContinuation(s DigestScopeSpec, a FlowAuthorization, remember session.RememberPolicy) (Continuation, error) {
	flow, e := a.Bindings()
	if e != nil || s.AuthorizationBinding != ([32]byte{}) {
		return Continuation{}, ErrInvalidAuthorization
	}
	needsRemember := s.Purpose == PurposeSignin || (s.Purpose == PurposeMFA && flow.Kind == FlowAuthorizationPreAuthTransaction)
	if s.Purpose == PurposeSignin && flow.Kind != FlowAuthorizationPreAuthTransaction {
		return Continuation{}, ErrInvalidAuthorization
	}
	var policy session.RememberPolicySpec
	if needsRemember {
		policy, e = remember.Bindings()
		if e != nil {
			return Continuation{}, ErrInvalidAuthorization
		}
	} else if remember != (session.RememberPolicy{}) {
		return Continuation{}, ErrInvalidAuthorization
	}
	b := []byte("identity-otp-authorization-v1\x00")
	b = append(b, byte(flow.Kind))
	for _, value := range []string{flow.AuthenticatedSessionID, string(flow.PreAuthTransactionID)} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
		b = append(b, value...)
	}
	b = append(b, byte(policy.Choice))
	for _, duration := range []int64{int64(policy.AbsoluteTTL), int64(policy.IdleTTL), int64(policy.RefreshAfter), int64(policy.FreshFor)} {
		b = binary.BigEndian.AppendUint64(b, uint64(duration))
	}
	s.AuthorizationBinding = sha256.Sum256(b)
	clear(b)
	scope, e := NewDigestScope(s)
	if e != nil {
		return Continuation{}, e
	}
	s.TenantID = strings.Clone(s.TenantID)
	s.SubjectID = strings.Clone(s.SubjectID)
	s.ChallengeID = strings.Clone(s.ChallengeID)
	s.TargetID = strings.Clone(s.TargetID)
	return Continuation{state: &continuationState{bindings: ContinuationBindings{Scope: s, Authorization: a, RememberPolicy: remember}, scope: scope}}, nil
}

// Bindings returns the exact immutable declaration; it does not authenticate
// or renew the flow. Zero returns ErrInvalidAuthorization. The returned struct
// is caller-owned; destination and authority remain immutable opaque values.
func (c Continuation) Bindings() (ContinuationBindings, error) {
	if c.state == nil {
		return ContinuationBindings{}, ErrInvalidAuthorization
	}
	return c.state.bindings, nil
}

// DigestScope returns the validated, authorization-bound digest scope. Zero
// returns ErrInvalidAuthorization. A code match remains non-authoritative.
func (c Continuation) DigestScope() (DigestScope, error) {
	if c.state == nil {
		return DigestScope{}, ErrInvalidAuthorization
	}
	return c.state.scope, nil
}

func (Continuation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.Continuation(redacted)")
}
func (Continuation) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (Continuation) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
