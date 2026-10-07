package postgres

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

const issuanceRecordPrefix = "identity-otp-issuance-record-v1\x00"

// Only initial digest-only custody is encoded. Codes and submitted bearers have
// no field in this closed frame. Recovery must not synthesize or renew them.
func encodeIssuanceRecord(challenge otp.Challenge) []byte {
	s, _ := challenge.Bindings()
	p, checks, _ := s.Policy.Bindings()
	out := appendSendContinuation([]byte(issuanceRecordPrefix), s.Continuation)
	out = appendAuthorityText(out, p.Alphabet)
	out = binary.BigEndian.AppendUint32(out, uint32(p.Length))
	for _, d := range []time.Duration{p.TTL, p.ResendInterval, checks.LockoutAfter} {
		out = binary.BigEndian.AppendUint64(out, uint64(d))
	}
	for _, n := range []uint32{p.MaximumSends, p.Attempts, checks.MaximumChecks, s.Digest.KeyVersion} {
		out = binary.BigEndian.AppendUint32(out, n)
	}
	out = append(out, byte(p.Replacement))
	if checks.Enabled {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, s.Digest.Value[:]...)
	out = appendAuthorityText(out, s.IssuedAt.UTC().Format(time.RFC3339Nano))
	return appendAuthorityText(out, s.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

// Shared declaration framing preserves the released issuance bytes while the
// pre-generation request carries no fabricated challenge or code digest.
func appendSendContinuation(out []byte, continuation otp.Continuation) []byte {
	b, _ := continuation.Bindings()
	for _, text := range []string{b.Scope.TenantID, string(b.Scope.Purpose), b.Scope.SubjectID, string(b.Scope.Channel), b.Scope.Destination.Value(), b.Scope.ChallengeID, b.Scope.TargetID} {
		out = appendAuthorityText(out, text)
	}
	out = binary.BigEndian.AppendUint64(out, b.Scope.PolicyVersion)
	out = binary.BigEndian.AppendUint64(out, b.Scope.Generation)
	remember, _ := b.RememberPolicy.Bindings()
	out = append(out, byte(remember.Choice))
	for _, d := range []time.Duration{remember.AbsoluteTTL, remember.IdleTTL, remember.RefreshAfter, remember.FreshFor} {
		out = binary.BigEndian.AppendUint64(out, uint64(d))
	}
	if original, ok := b.Authorization.PreAuthTransaction(); ok {
		out = append(out, byte(otp.FlowAuthorizationPreAuthTransaction))
		out = appendPreAuthRecord(out, original)
	} else {
		original, _ := b.Authorization.AuthenticatedSession()
		out = append(out, byte(otp.FlowAuthorizationAuthenticatedSession))
		out = appendSessionRecord(out, original)
	}
	return out
}

func decodeIssuanceRecord(data []byte) (otp.Challenge, error) {
	bad := func() (otp.Challenge, error) { return otp.Challenge{}, ErrInvalidCommand }
	if len(data) > 8192 || !bytes.HasPrefix(data, []byte(issuanceRecordPrefix)) {
		return bad()
	}
	r := recordReader{data: data[len(issuanceRecordPrefix):], ok: true}
	continuation, err := readSendContinuation(&r)
	if err != nil {
		return bad()
	}
	b, _ := continuation.Bindings()
	alphabet, length := r.text(94), r.u32()
	if length < 4 || length > 128 {
		return bad()
	}
	profileSpec := otp.CodeProfileSpec{Purpose: b.Scope.Purpose, Alphabet: alphabet, Length: int(length), TTL: time.Duration(r.u64()), ResendInterval: time.Duration(r.u64())}
	checks := otp.CheckPolicySpec{LockoutAfter: time.Duration(r.u64())}
	profileSpec.MaximumSends, profileSpec.Attempts, checks.MaximumChecks = r.u32(), r.u32(), r.u32()
	stored := otp.StoredCodeDigest{KeyVersion: r.u32()}
	profileSpec.Replacement = otp.ReplacementPolicy(r.u8())
	switch r.u8() {
	case 0:
	case 1:
		checks.Enabled = true
	default:
		return bad()
	}
	copy(stored.Value[:], r.take(32))
	issued, expires := r.text(35), r.text(35)
	issuedAt, e1 := time.Parse(time.RFC3339Nano, issued)
	expiresAt, e2 := time.Parse(time.RFC3339Nano, expires)
	if !r.ok || len(r.data) != 0 || e1 != nil || e2 != nil || issuedAt.UTC().Format(time.RFC3339Nano) != issued || expiresAt.UTC().Format(time.RFC3339Nano) != expires {
		return bad()
	}
	profile, err := otp.NewCodeProfile(profileSpec)
	if err != nil {
		return bad()
	}
	policy, err := otp.NewAttemptPolicy(profile, checks)
	if err != nil {
		return bad()
	}
	challenge, err := otp.NewChallenge(otp.ChallengeSpec{Continuation: continuation, Policy: policy, Digest: stored, IssuedAt: issuedAt, ExpiresAt: expiresAt, State: otp.ChallengeIssued, Version: 1})
	if err != nil {
		return bad()
	}
	return challenge, nil
}

func readSendContinuation(r *recordReader) (otp.Continuation, error) {
	bad := func() (otp.Continuation, error) { return otp.Continuation{}, ErrInvalidCommand }
	scope := otp.DigestScopeSpec{TenantID: r.text(256), Purpose: otp.Purpose(r.text(32)), SubjectID: r.text(256), Channel: otp.Channel(r.text(5))}
	destination, err := otp.NewDestinationInput(r.text(320))
	if err != nil {
		return bad()
	}
	scope.Destination, scope.ChallengeID, scope.TargetID = destination, r.text(256), r.text(256)
	scope.PolicyVersion, scope.Generation = r.u64(), r.u64()
	rememberSpec := session.RememberPolicySpec{Choice: session.RememberChoice(r.u8()), AbsoluteTTL: time.Duration(r.u64()), IdleTTL: time.Duration(r.u64()), RefreshAfter: time.Duration(r.u64()), FreshFor: time.Duration(r.u64())}
	var remember session.RememberPolicy
	if rememberSpec != (session.RememberPolicySpec{}) {
		remember, err = session.NewRememberPolicy(rememberSpec)
		if err != nil {
			return bad()
		}
	}
	var flow otp.FlowAuthorization
	switch otp.FlowAuthorizationKind(r.u8()) {
	case otp.FlowAuthorizationPreAuthTransaction:
		original, e := readPreAuthRecord(r)
		if e != nil {
			return bad()
		}
		flow, err = otp.NewBoundPreAuthAuthorization(original)
	case otp.FlowAuthorizationAuthenticatedSession:
		original, e := readSessionRecord(r)
		if e != nil {
			return bad()
		}
		flow, err = otp.NewBoundSessionAuthorization(original)
	default:
		return bad()
	}
	if err != nil {
		return bad()
	}
	continuation, err := otp.NewContinuation(scope, flow, remember)
	if err != nil {
		return bad()
	}
	return continuation, nil
}
