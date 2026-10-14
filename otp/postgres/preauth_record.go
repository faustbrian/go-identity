package postgres

import (
	"encoding/binary"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// This bounded scalar projection is private encrypted command custody, not a
// second pre-auth store or admission proof. The canonical primary row and every
// active-state/cookie/reservation comparison remain owned by session/postgres.
func appendPreAuthRecord(out []byte, record session.PreAuthTransaction) []byte {
	s, _ := record.Bindings()
	b, i := s.Binding, s.Binding.Intent
	for _, value := range []string{string(b.ID), string(i.TenantID), i.Action, i.Origin, i.CallbackURL, i.PolicyID, b.IssuedAt.UTC().Format(time.RFC3339Nano), b.ExpiresAt.UTC().Format(time.RFC3339Nano)} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
		out = append(out, value...)
	}
	out = append(out, i.Nonce[:]...)
	out = binary.BigEndian.AppendUint64(out, i.PolicyVersion)
	remember, _ := i.Remember.Bindings()
	out = append(out, byte(remember.Choice))
	for _, duration := range []time.Duration{remember.AbsoluteTTL, remember.IdleTTL, remember.RefreshAfter, remember.FreshFor} {
		out = binary.BigEndian.AppendUint64(out, uint64(duration))
	}
	out = binary.BigEndian.AppendUint32(out, s.Cookie.KeyVersion)
	out = append(out, s.Cookie.Sum[:]...)
	return binary.BigEndian.AppendUint64(out, s.Version)
}

func readPreAuthRecord(r *recordReader) (session.PreAuthTransaction, error) {
	s := session.PreAuthTransactionSpec{}
	b, i := &s.Binding, &s.Binding.Intent
	b.ID = identity.PreAuthTransactionID(r.text(22))
	i.TenantID = identity.TenantID(r.text(128))
	i.Action, i.Origin, i.CallbackURL, i.PolicyID = r.text(128), r.text(2048), r.text(2048), r.text(128)
	issued, expires := r.text(35), r.text(35)
	var err error
	b.IssuedAt, err = time.Parse(time.RFC3339Nano, issued)
	if err != nil || b.IssuedAt.UTC().Format(time.RFC3339Nano) != issued {
		return session.PreAuthTransaction{}, ErrInvalidCommand
	}
	b.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil || b.ExpiresAt.UTC().Format(time.RFC3339Nano) != expires {
		return session.PreAuthTransaction{}, ErrInvalidCommand
	}
	copy(i.Nonce[:], r.take(32))
	i.PolicyVersion = r.u64()
	i.Remember, err = session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.RememberChoice(r.u8()), AbsoluteTTL: time.Duration(r.u64()), IdleTTL: time.Duration(r.u64()), RefreshAfter: time.Duration(r.u64()), FreshFor: time.Duration(r.u64())})
	if err != nil {
		return session.PreAuthTransaction{}, ErrInvalidCommand
	}
	s.Cookie.KeyVersion = r.u32()
	copy(s.Cookie.Sum[:], r.take(32))
	s.Version = r.u64()
	if !r.ok {
		return session.PreAuthTransaction{}, ErrInvalidCommand
	}
	record, err := session.NewPreAuthTransaction(s)
	if err != nil {
		return session.PreAuthTransaction{}, ErrInvalidCommand
	}
	return record, nil
}
