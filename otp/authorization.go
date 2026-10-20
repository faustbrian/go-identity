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
	// FlowAuthorizationMFAContinuation retains original consumed-primary custody
	// for an explicitly selected second factor. It is neither a pending pre-auth
	// flow nor a completed session; unsupported owners must reject this arm.
	FlowAuthorizationMFAContinuation
)

// FlowAuthorizationSpec is an explicit tagged union. Exactly the selected
// identity must be nonzero; all others must be absent. Session IDs follow
// session's existing 1..128 visible ASCII contract. Pre-auth and MFA child IDs
// use identity's canonical nonzero 128-bit ID contract. NewFlowAuthorization
// accepts only ordinary scalar contexts; NewMFAFlowAuthorization additionally
// requires complete original custody for its arm. This is structure, not proof.
type FlowAuthorizationSpec struct {
	Kind                   FlowAuthorizationKind
	AuthenticatedSessionID string
	PreAuthTransactionID   identity.PreAuthTransactionID
	MFAContinuationID      identity.CommandID
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
	session session.Session
	mfa     *mfaFlowAuthorization
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
// authenticated-session and MFA contexts return zero/false. It never proves active
// state, cookie possession or a reservation; never log or export the projection.
func (a FlowAuthorization) PreAuthTransaction() (session.PreAuthTransaction, bool) {
	return a.preAuth, a.preAuth != (session.PreAuthTransaction{})
}

// NewFlowAuthorization validates before copying and never infers Kind from
// subject, remember policy or a nonzero nullable member. No IO is performed.
func NewFlowAuthorization(s FlowAuthorizationSpec) (FlowAuthorization, error) {
	switch s.Kind {
	case FlowAuthorizationAuthenticatedSession:
		if len(s.AuthenticatedSessionID) < 1 || len(s.AuthenticatedSessionID) > 128 || s.PreAuthTransactionID != "" || s.MFAContinuationID != "" {
			return FlowAuthorization{}, ErrInvalidAuthorization
		}
		for _, r := range s.AuthenticatedSessionID {
			if r < 33 || r > 126 {
				return FlowAuthorization{}, ErrInvalidAuthorization
			}
		}
	case FlowAuthorizationPreAuthTransaction:
		if s.AuthenticatedSessionID != "" || s.MFAContinuationID != "" {
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
// Explicit NewBoundSessionAuthorization uses the v3 tokenless-session profile
// or v4 when the original session carries synchronizer CSRF state:
// tenant/subject must match the original verified record. Original session policy,
// lookup digest, full authority and authentication timeline are committed without
// renewal; this remains structural custody, not authenticated admission.
// Explicit NewMFAFlowAuthorization uses a disjoint v5 consumed-primary frame,
// accepts only PurposeMFA and binds the exact subject/child target and original
// remember policy. It neither exposes nor renews an ordinary pending flow.
// Explicit sessionless phone recovery uses v6, requires password-reset/SMS
// and a known subject, and binds the original recovery purpose and keyed target
// commitment without a remember choice. No other operation may reuse that flow.
func NewContinuation(s DigestScopeSpec, a FlowAuthorization, remember session.RememberPolicy) (Continuation, error) {
	flow, e := a.Bindings()
	if e != nil || s.AuthorizationBinding != ([32]byte{}) {
		return Continuation{}, ErrInvalidAuthorization
	}
	needsRemember := s.Purpose == PurposeSignin || (s.Purpose == PurposeMFA && (flow.Kind == FlowAuthorizationPreAuthTransaction || flow.Kind == FlowAuthorizationMFAContinuation))
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
	var recoveryIntent *session.PreAuthIntent
	if record, bound := a.PreAuthTransaction(); bound {
		original, err := record.Bindings()
		if err != nil || original.Binding.Intent.TenantID != identity.TenantID(s.TenantID) || needsRemember && original.Binding.Intent.Remember != remember {
			return Continuation{}, ErrInvalidAuthorization
		}
		b = []byte("identity-otp-authorization-v2\x00")
		if original.Binding.Intent.Purpose == session.PreAuthPhonePasswordRecovery {
			if s.Purpose != PurposePasswordReset || s.Channel != ChannelSMS || s.SubjectID == "" {
				return Continuation{}, ErrInvalidAuthorization
			}
			b = []byte("identity-otp-authorization-v6\x00")
			recoveryIntent = &original.Binding.Intent
		}
	}
	if record, bound := a.AuthenticatedSession(); bound {
		original, err := record.Bindings()
		if err != nil || string(original.TenantID) != s.TenantID || string(original.UserID) != s.SubjectID {
			return Continuation{}, ErrInvalidAuthorization
		}
		b = []byte("identity-otp-authorization-v3\x00")
		if _, err := record.CSRFState().Bindings(); err == nil {
			b = []byte("identity-otp-authorization-v4\x00")
		}
	}
	if record, binding, bound := a.MFAContinuation(); bound {
		original, err := record.Bindings()
		if err != nil || flow.Kind != FlowAuthorizationMFAContinuation || s.Purpose != PurposeMFA ||
			original.Binding.Intent.TenantID != identity.TenantID(s.TenantID) ||
			s.SubjectID != string(binding.SubjectID) || s.TargetID != string(binding.ContinuationID) ||
			original.Binding.Intent.Remember != remember {
			return Continuation{}, ErrInvalidAuthorization
		}
		b = []byte("identity-otp-authorization-v5\x00")
	}
	b = append(b, byte(flow.Kind))
	for _, value := range []string{flow.AuthenticatedSessionID, string(flow.PreAuthTransactionID)} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
		b = append(b, value...)
	}
	if recoveryIntent != nil {
		b = append(b, byte(recoveryIntent.Purpose))
		b = append(b, recoveryIntent.IdentifierBinding[:]...)
	} else {
		b = append(b, byte(policy.Choice))
		for _, duration := range []int64{int64(policy.AbsoluteTTL), int64(policy.IdleTTL), int64(policy.RefreshAfter), int64(policy.FreshFor)} {
			b = binary.BigEndian.AppendUint64(b, uint64(duration))
		}
	}
	if record, bound := a.PreAuthTransaction(); bound {
		b = appendPreAuthAuthorization(b, record)
	}
	if record, bound := a.AuthenticatedSession(); bound {
		b = appendSessionAuthorization(b, record)
	}
	if record, binding, bound := a.MFAContinuation(); bound {
		b = appendPreAuthAuthorization(b, record)
		for _, value := range []string{string(binding.PrimaryCommandID), string(binding.ContinuationID), string(binding.SubjectID)} {
			b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
			b = append(b, value...)
		}
		b = append(b, binding.ScopeDigest[:]...)
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

// The ordinary v2 frame is preserved byte-for-byte. MFA's distinct v5 frame
// reuses only this structural encoding, never ordinary pre-auth admission.
func appendPreAuthAuthorization(b []byte, record session.PreAuthTransaction) []byte {
	original, _ := record.Bindings()
	i := original.Binding.Intent
	for _, value := range []string{string(original.Binding.ID), string(i.TenantID), i.Action, i.Origin, i.CallbackURL, i.PolicyID, original.Binding.IssuedAt.UTC().Format(time.RFC3339Nano), original.Binding.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
		b = append(b, value...)
	}
	b = append(b, i.Nonce[:]...)
	b = binary.BigEndian.AppendUint64(b, i.PolicyVersion)
	if i.Purpose != session.PreAuthPhonePasswordRecovery {
		resolved, _ := i.Remember.Bindings()
		b = append(b, byte(resolved.Choice))
		for _, duration := range []time.Duration{resolved.AbsoluteTTL, resolved.IdleTTL, resolved.RefreshAfter, resolved.FreshFor} {
			b = binary.BigEndian.AppendUint64(b, uint64(duration))
		}
	}
	b = binary.BigEndian.AppendUint32(b, original.Cookie.KeyVersion)
	b = append(b, original.Cookie.Sum[:]...)
	return binary.BigEndian.AppendUint64(b, original.Version)
}
