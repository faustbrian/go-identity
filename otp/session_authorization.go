package otp

import (
	"encoding/binary"
	"time"

	"github.com/faustbrian/go-identity/session"
)

// NewBoundSessionAuthorization freezes the complete original verified-session
// projection, including its lookup digest, authority vector and authentication
// timestamps, and separate digest-only synchronizer CSRF state when present.
// Anonymous and zero records return ErrInvalidAuthorization.
// Construction performs no IO and proves neither possession nor authentication,
// freshness, active status or permission. Native admission must independently
// authenticate the submitted credential and compare every applicable primary
// owner against this exact original; retry must never replace it with a lookup.
// Legacy NewFlowAuthorization retains its ID-only behavior and framing.
func NewBoundSessionAuthorization(record session.Session) (FlowAuthorization, error) {
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Kind != session.AuthenticationVerified {
		return FlowAuthorization{}, ErrInvalidAuthorization
	}
	flow, err := NewFlowAuthorization(FlowAuthorizationSpec{Kind: FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: spec.SessionID})
	if err != nil {
		return FlowAuthorization{}, err
	}
	flow.session = record
	return flow, nil
}

// AuthenticatedSession returns immutable original structural custody only for
// the complete-session profile. Legacy ID-only and pre-auth contexts return
// zero/false. It is not a successful authentication or validity lease. Never
// export or log the correlated projection; release custody after bounded use.
func (a FlowAuthorization) AuthenticatedSession() (session.Session, bool) {
	return a.session, a.session != (session.Session{})
}

// All inputs have already passed the session owner's bounds. Length framing
// and nanosecond UTC timestamps make each original field unambiguous without
// adding serialization authority to the opaque session or proof contracts.
func appendSessionAuthorization(out []byte, record session.Session) []byte {
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	p, _ := s.Remember.Bindings()
	m := s.Authentication
	proof := m.Proof
	for _, value := range []string{s.SessionID, s.FamilyID, string(s.TenantID), string(s.UserID), s.Audience, a.ActiveOrganizationID, m.CredentialID,
		string(proof.ID), proof.Tenant, proof.Subject, proof.Method, string(proof.Purpose), proof.Audience,
		s.IssuedAt.UTC().Format(time.RFC3339Nano), s.LastActivityAt.UTC().Format(time.RFC3339Nano),
		proof.IssuedAt.UTC().Format(time.RFC3339Nano), proof.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
		out = append(out, value...)
	}
	for _, value := range []uint64{s.Version, s.FamilyVersion, m.ProofVersion, m.CredentialVersion} {
		out = binary.BigEndian.AppendUint64(out, value)
	}
	out = append(out, byte(m.Kind), byte(proof.Assurance), byte(p.Choice))
	for _, value := range []time.Duration{p.AbsoluteTTL, p.IdleTTL, p.RefreshAfter, p.FreshFor} {
		out = binary.BigEndian.AppendUint64(out, uint64(value))
	}
	out = binary.BigEndian.AppendUint32(out, s.Lookup.KeyVersion)
	out = append(out, s.Lookup.Sum[:]...)
	for _, b := range []session.AuthorityBinding{a.Global, a.Tenant, a.User, a.Identifier, a.Credential, a.SessionFamily, a.Session, a.Authorization} {
		out = appendSessionAuthority(out, b)
	}
	for _, optional := range []session.OptionalAuthorityBinding{a.Organization, a.Factor, a.Passkey} {
		present := byte(0)
		if optional.Present {
			present = 1
		}
		out = append(out, present)
		out = appendSessionAuthority(out, optional.Binding)
	}
	if state, err := record.CSRFState().Bindings(); err == nil {
		// The session constructor binds the CSRF tuple to tenant/session/version
		// already encoded above. The distinct v4 domain plus this fixed-width
		// suffix commits presence, named key and digest without altering v3.
		out = binary.BigEndian.AppendUint32(out, state.KeyVersion)
		out = append(out, state.Digest[:]...)
	}
	if factor, err := record.MFAAuthentication().Bindings(); err == nil {
		// The v7/v8 domains bind the original completed factor as well as its
		// account epoch. Omitting it would let different historical completions
		// share one OTP authorization digest. Remember is already bound above.
		for _, value := range []string{string(factor.CommandID), string(factor.PrimaryCommandID), string(factor.ContinuationID), factor.Method, factor.FactorID, string(factor.RecoverySetID)} {
			out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
			out = append(out, value...)
		}
		out = append(out, factor.ContinuationScopeDigest[:]...)
		for _, value := range []uint64{factor.EnrollmentVersion, factor.FactorAuthorityVersion, factor.ContinuationVersion, factor.RecoverySetVersion} {
			out = binary.BigEndian.AppendUint64(out, value)
		}
		for _, at := range []time.Time{factor.VerifiedAt, factor.ValidUntil} {
			text := at.UTC().Format(time.RFC3339Nano)
			out = binary.BigEndian.AppendUint16(out, uint16(len(text)))
			out = append(out, text...)
		}
	}
	return out
}

func appendSessionAuthority(out []byte, b session.AuthorityBinding) []byte {
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.ScopeKey)))
	out = append(out, b.ScopeKey...)
	return binary.BigEndian.AppendUint64(out, b.Version)
}
