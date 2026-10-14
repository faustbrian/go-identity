package postgres

import (
	"bytes"
	"encoding/binary"
	"github.com/faustbrian/go-identity/otp"
	"testing"
	"time"
)

func TestIssuanceRecordRetainsOriginalWireProfile(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		_, challenge, _, _, _ := issuanceCustodyFixture(t, authenticated)
		if !bytes.Equal(encodeIssuanceRecord(challenge), legacyIssuanceRecord(challenge)) {
			t.Fatal("shared request framing changed original issuance bytes")
		}
	}
}

// Independent byte oracle copied unchanged from source 0f74387. Keep its
// framing independent of new shared helpers so a coordinated codec change
// cannot silently reinterpret retained encrypted issuance.
func legacyIssuanceRecord(challenge otp.Challenge) []byte {
	s, _ := challenge.Bindings()
	b, _ := s.Continuation.Bindings()
	p, checks, _ := s.Policy.Bindings()
	out := []byte(issuanceRecordPrefix)
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
