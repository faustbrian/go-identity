package otp

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

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

// FlowAuthorization freezes the validated discriminant and selected ID, plus
// complete original flow custody when explicitly bound.
// Zero is invalid; immutable copies are safe for concurrent reads. Construction
// does not look up a session, verify authentication or reserve a pre-auth flow.
type FlowAuthorization struct {
	spec    FlowAuthorizationSpec
	preAuth session.PreAuthTransaction
}

// NewBoundPreAuthAuthorization retains the complete immutable original flow,
// not just its ID. It grants no authentication, cookie-possession, current
// primary-state or one-use authority. The native owner must independently
// derive the submitted cookie digest and compare the full original record after
// primary locking at every consuming phase. Zero is invalid; no IO occurs.
// Legacy NewFlowAuthorization remains unchanged and never fabricates this data.
func NewBoundPreAuthAuthorization(record session.PreAuthTransaction) (FlowAuthorization, error) {
	spec, err := record.Bindings()
	if err != nil {
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	flow, err := NewFlowAuthorization(FlowAuthorizationSpec{Kind: FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: spec.Binding.ID})
	if err != nil {
		return FlowAuthorization{}, err
	}
	flow.preAuth = record
	return flow, nil
}

// PreAuthTransaction returns the immutable original private projection and
// true only for the explicit complete-binding profile. Legacy ID-only and
// authenticated-session contexts return zero/false. It never proves active
// state, cookie possession or a reservation; never log or export the projection.
func (a FlowAuthorization) PreAuthTransaction() (session.PreAuthTransaction, bool) {
	return a.preAuth, a.preAuth != (session.PreAuthTransaction{})
}

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
// Explicit NewBoundPreAuthAuthorization uses the v2 complete-record profile:
// tenant must match and signin/pre-auth MFA must preserve original Remember.
// Legacy ID-only context retains exact v1 framing and grants no full-flow proof.
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
	if record, bound := a.PreAuthTransaction(); bound {
		original, err := record.Bindings()
		if err != nil || original.Binding.Intent.TenantID != identity.TenantID(s.TenantID) || needsRemember && original.Binding.Intent.Remember != remember {
			return Continuation{}, ErrInvalidAuthorization
		}
		b = []byte("identity-otp-authorization-v2\x00")
	}
	b = append(b, byte(flow.Kind))
	for _, value := range []string{flow.AuthenticatedSessionID, string(flow.PreAuthTransactionID)} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
		b = append(b, value...)
	}
	b = append(b, byte(policy.Choice))
	for _, duration := range []int64{int64(policy.AbsoluteTTL), int64(policy.IdleTTL), int64(policy.RefreshAfter), int64(policy.FreshFor)} {
		b = binary.BigEndian.AppendUint64(b, uint64(duration))
	}
	if record, bound := a.PreAuthTransaction(); bound {
		original, _ := record.Bindings()
		i := original.Binding.Intent
		for _, value := range []string{string(original.Binding.ID), string(i.TenantID), i.Action, i.Origin, i.CallbackURL, i.PolicyID, original.Binding.IssuedAt.UTC().Format(time.RFC3339Nano), original.Binding.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
			b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
			b = append(b, value...)
		}
		b = append(b, i.Nonce[:]...)
		b = binary.BigEndian.AppendUint64(b, i.PolicyVersion)
		resolved, _ := i.Remember.Bindings()
		b = append(b, byte(resolved.Choice))
		for _, duration := range []time.Duration{resolved.AbsoluteTTL, resolved.IdleTTL, resolved.RefreshAfter, resolved.FreshFor} {
			b = binary.BigEndian.AppendUint64(b, uint64(duration))
		}
		b = binary.BigEndian.AppendUint32(b, original.Cookie.KeyVersion)
		b = append(b, original.Cookie.Sum[:]...)
		b = binary.BigEndian.AppendUint64(b, original.Version)
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
