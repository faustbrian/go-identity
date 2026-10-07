package postgres

import (
	"bytes"
	"encoding/binary"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

const recordPrefix = "identity-otp-attempt-custody-v1\x00"
const boundRecordPrefix = "identity-otp-attempt-custody-v2\x00"

// Only this closed private projection enters the encrypted envelope. Command
// scope is supplied by the exact authenticated AAD and verified core MAC, not
// duplicated as an unauthenticated parser choice. No raw code is encoded.
func encodeAttemptRecord(r otp.CommandAttemptRecord) []byte {
	a := r.Attempt
	b, _ := a.Continuation.Bindings()
	flow, _ := b.Authorization.Bindings()
	remember, _ := b.RememberPolicy.Bindings()
	out := []byte(recordPrefix)
	fullFlow, bound := b.Authorization.PreAuthTransaction()
	if bound {
		out = []byte(boundRecordPrefix)
	}
	for _, s := range []string{string(a.AttemptID), string(a.Fingerprint), b.Scope.TenantID, string(b.Scope.Purpose), b.Scope.SubjectID, string(b.Scope.Channel), b.Scope.Destination.Value(), b.Scope.ChallengeID, b.Scope.TargetID} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s)))
		out = append(out, s...)
	}
	out = binary.BigEndian.AppendUint32(out, a.FingerprintKeyVersion)
	out = append(out, byte(a.Mode))
	out = binary.BigEndian.AppendUint64(out, a.ExpectedVersion)
	out = binary.BigEndian.AppendUint64(out, b.Scope.PolicyVersion)
	out = binary.BigEndian.AppendUint64(out, b.Scope.Generation)
	out = append(out, byte(flow.Kind))
	for _, s := range []string{flow.AuthenticatedSessionID, string(flow.PreAuthTransactionID)} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s)))
		out = append(out, s...)
	}
	out = append(out, byte(remember.Choice))
	for _, d := range []time.Duration{remember.AbsoluteTTL, remember.IdleTTL, remember.RefreshAfter, remember.FreshFor} {
		out = binary.BigEndian.AppendUint64(out, uint64(d))
	}
	if bound {
		out = appendPreAuthRecord(out, fullFlow)
	}
	out = append(out, r.Signature[:]...)
	return out
}

func decodeAttemptRecord(data []byte, binding identity.CommandBinding, operation identity.FeatureOperation) (otp.CommandAttemptRecord, error) {
	bad := func() (otp.CommandAttemptRecord, error) { return otp.CommandAttemptRecord{}, ErrInvalidCommand }
	bound := bytes.HasPrefix(data, []byte(boundRecordPrefix))
	if len(data) > 8192 || !bound && (len(data) > 4096 || !bytes.HasPrefix(data, []byte(recordPrefix))) {
		return bad()
	}
	prefix := recordPrefix
	if bound {
		prefix = boundRecordPrefix
	}
	r := recordReader{data: data[len(prefix):], ok: true}
	id, fp := r.text(22), r.text(43)
	s := otp.DigestScopeSpec{TenantID: r.text(256), Purpose: otp.Purpose(r.text(32)), SubjectID: r.text(256), Channel: otp.Channel(r.text(5))}
	dest := r.text(320)
	s.ChallengeID = r.text(256)
	s.TargetID = r.text(256)
	issuer := r.u32()
	mode := otp.AttemptMode(r.u8())
	expected := r.u64()
	s.PolicyVersion = r.u64()
	s.Generation = r.u64()
	flowSpec := otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationKind(r.u8()), AuthenticatedSessionID: r.text(128), PreAuthTransactionID: identity.PreAuthTransactionID(r.text(22))}
	rememberSpec := session.RememberPolicySpec{Choice: session.RememberChoice(r.u8()), AbsoluteTTL: time.Duration(r.u64()), IdleTTL: time.Duration(r.u64()), RefreshAfter: time.Duration(r.u64()), FreshFor: time.Duration(r.u64())}
	var original session.PreAuthTransaction
	if bound {
		var err error
		original, err = readPreAuthRecord(&r)
		if err != nil {
			return bad()
		}
	}
	var signature [32]byte
	copy(signature[:], r.take(32))
	if !r.ok || len(r.data) != 0 {
		return bad()
	}
	var err error
	s.Destination, err = otp.NewDestinationInput(dest)
	if err != nil {
		return bad()
	}
	flow, err := otp.NewFlowAuthorization(flowSpec)
	if err != nil {
		return bad()
	}
	if bound {
		originalSpec, _ := original.Bindings()
		if flowSpec.Kind != otp.FlowAuthorizationPreAuthTransaction || flowSpec.PreAuthTransactionID != originalSpec.Binding.ID {
			return bad()
		}
		flow, err = otp.NewBoundPreAuthAuthorization(original)
		if err != nil {
			return bad()
		}
	}
	var remember session.RememberPolicy
	if rememberSpec != (session.RememberPolicySpec{}) {
		remember, err = session.NewRememberPolicy(rememberSpec)
		if err != nil {
			return bad()
		}
	}
	continuation, err := otp.NewContinuation(s, flow, remember)
	if err != nil {
		return bad()
	}
	return otp.CommandAttemptRecord{Attempt: otp.AttemptBindings{CommandID: binding.CommandID, AttemptID: otp.AttemptID(id), Fingerprint: otp.AttemptFingerprint(fp), FingerprintKeyVersion: issuer, Continuation: continuation, Mode: mode, ExpectedVersion: expected}, Binding: binding, Operation: operation, Signature: signature}, nil
}

type recordReader struct {
	data []byte
	ok   bool
}

func (r *recordReader) take(n int) []byte {
	if !r.ok || n < 0 || n > len(r.data) {
		r.ok = false
		return nil
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}
func (r *recordReader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *recordReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *recordReader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *recordReader) text(max int) string {
	b := r.take(2)
	if b == nil {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > max {
		r.ok = false
		return ""
	}
	return string(r.take(n))
}
