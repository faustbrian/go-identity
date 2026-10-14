package postgres

import (
	"encoding/binary"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// This is code-free metadata inside existing authenticated encrypted custody,
// not another journal, primary-state read or MFA continuation authority owner.
// Reusing the tokenless original snapshot encoding never reopens its state.
func appendMFAFlowRecord(out []byte, original session.PreAuthTransaction, b otp.MFAFlowBinding) []byte {
	out = appendPreAuthRecord(out, original)
	for _, text := range []string{string(b.PrimaryCommandID), string(b.ContinuationID), string(b.SubjectID)} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(text)))
		out = append(out, text...)
	}
	return append(out, b.ScopeDigest[:]...)
}

func readMFAFlowRecord(r *recordReader) (otp.FlowAuthorization, error) {
	original, err := readPreAuthRecord(r)
	if err != nil {
		return otp.FlowAuthorization{}, ErrInvalidCommand
	}
	b := otp.MFAFlowBinding{PrimaryCommandID: identity.CommandID(r.text(22)),
		ContinuationID: identity.CommandID(r.text(22)), SubjectID: identity.UserID(r.text(128))}
	copy(b.ScopeDigest[:], r.take(32))
	if !r.ok {
		return otp.FlowAuthorization{}, ErrInvalidCommand
	}
	a, err := otp.NewMFAFlowAuthorization(original, b)
	if err != nil {
		return otp.FlowAuthorization{}, ErrInvalidCommand
	}
	return a, nil
}
