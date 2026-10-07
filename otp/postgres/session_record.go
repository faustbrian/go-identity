package postgres

import (
	"encoding/binary"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Private encrypted custody only: this never serializes a bearer, opaque proof
// or validity lease and cannot replace the session owner's admission/storage.
func appendSessionRecord(out []byte, record session.Session) []byte {
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	p, _ := s.Remember.Bindings()
	m, proof := s.Authentication, s.Authentication.Proof
	for _, text := range []string{s.SessionID, s.FamilyID, string(s.TenantID), string(s.UserID), s.Audience, a.ActiveOrganizationID, m.CredentialID,
		string(proof.ID), proof.Tenant, proof.Subject, proof.Method, string(proof.Purpose), proof.Audience,
		s.IssuedAt.UTC().Format(time.RFC3339Nano), s.LastActivityAt.UTC().Format(time.RFC3339Nano),
		proof.IssuedAt.UTC().Format(time.RFC3339Nano), proof.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		out = appendAuthorityText(out, text)
	}
	for _, n := range []uint64{s.Version, s.FamilyVersion, m.ProofVersion, m.CredentialVersion} {
		out = binary.BigEndian.AppendUint64(out, n)
	}
	out = append(out, byte(m.Kind), byte(proof.Assurance), byte(p.Choice))
	for _, d := range []time.Duration{p.AbsoluteTTL, p.IdleTTL, p.RefreshAfter, p.FreshFor} {
		out = binary.BigEndian.AppendUint64(out, uint64(d))
	}
	out = binary.BigEndian.AppendUint32(out, s.Lookup.KeyVersion)
	out = append(out, s.Lookup.Sum[:]...)
	for _, b := range []session.AuthorityBinding{a.Global, a.Tenant, a.User, a.Identifier, a.Credential, a.SessionFamily, a.Session, a.Authorization} {
		out = appendSessionAuthorityRecord(out, b)
	}
	for _, o := range []session.OptionalAuthorityBinding{a.Organization, a.Factor, a.Passkey} {
		present := byte(0)
		if o.Present {
			present = 1
		}
		out = append(out, present)
		out = appendSessionAuthorityRecord(out, o.Binding)
	}
	return out
}

func appendSessionAuthorityRecord(out []byte, b session.AuthorityBinding) []byte {
	out = appendAuthorityText(out, b.ScopeKey)
	return binary.BigEndian.AppendUint64(out, b.Version)
}

func readSessionRecord(r *recordReader) (session.Session, error) {
	s := session.SessionSpec{}
	a := session.AuthoritySnapshotSpec{}
	m := &s.Authentication
	proof := &m.Proof
	s.SessionID, s.FamilyID = r.text(128), r.text(128)
	s.TenantID, s.UserID = identity.TenantID(r.text(128)), identity.UserID(r.text(128))
	s.Audience, a.ActiveOrganizationID, m.CredentialID = r.text(256), r.text(128), r.text(128)
	proof.ID = auth.ProofID(r.text(256))
	proof.Tenant, proof.Subject, proof.Method = r.text(256), r.text(256), r.text(256)
	proof.Purpose, proof.Audience = auth.Purpose(r.text(256)), r.text(256)
	for _, target := range []*time.Time{&s.IssuedAt, &s.LastActivityAt, &proof.IssuedAt, &proof.ExpiresAt} {
		text := r.text(35)
		value, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || value.UTC().Format(time.RFC3339Nano) != text {
			return session.Session{}, ErrInvalidCommand
		}
		*target = value
	}
	s.Version, s.FamilyVersion, m.ProofVersion, m.CredentialVersion = r.u64(), r.u64(), r.u64(), r.u64()
	m.Kind, proof.Assurance = session.AuthenticationKind(r.u8()), auth.Assurance(r.u8())
	p := session.RememberPolicySpec{Choice: session.RememberChoice(r.u8()), AbsoluteTTL: time.Duration(r.u64()), IdleTTL: time.Duration(r.u64()), RefreshAfter: time.Duration(r.u64()), FreshFor: time.Duration(r.u64())}
	s.Lookup.KeyVersion = r.u32()
	copy(s.Lookup.Sum[:], r.take(32))
	for _, b := range []*session.AuthorityBinding{&a.Global, &a.Tenant, &a.User, &a.Identifier, &a.Credential, &a.SessionFamily, &a.Session, &a.Authorization} {
		b.ScopeKey, b.Version = r.text(256), r.u64()
	}
	for _, o := range []*session.OptionalAuthorityBinding{&a.Organization, &a.Factor, &a.Passkey} {
		present := r.u8()
		if present > 1 {
			return session.Session{}, ErrInvalidCommand
		}
		o.Present = present == 1
		o.Binding.ScopeKey, o.Binding.Version = r.text(256), r.u64()
	}
	if !r.ok || m.Kind != session.AuthenticationVerified {
		return session.Session{}, ErrInvalidCommand
	}
	var err error
	s.Remember, err = session.NewRememberPolicy(p)
	if err != nil {
		return session.Session{}, ErrInvalidCommand
	}
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		return session.Session{}, ErrInvalidCommand
	}
	record, err := session.NewSession(s)
	if err != nil {
		return session.Session{}, ErrInvalidCommand
	}
	return record, nil
}
