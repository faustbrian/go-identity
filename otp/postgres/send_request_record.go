package postgres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

const sendRequestRecordPrefix = "identity-otp-send-request-v1\x00"

// Original declaration before entropy. This invocation-memory profile has no
// challenge digest, submitted bearer or generated delivery. The coordinator
// fingerprints fields with its secret key; raw declarations are not persisted.
// It is not current authority and is not a public request/clearance API.
type sendRequestRecord struct {
	continuation otp.Continuation
	policy       otp.AttemptPolicy
	authority    AttemptAuthority
	issuedAt     time.Time
	expiresAt    time.Time
}

func (sendRequestRecord) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.sendRequest(redacted)"))
}
func (sendRequestRecord) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (sendRequestRecord) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

func (s sendRequestRecord) validate(binding identity.CommandBinding) error {
	b, err := s.continuation.Bindings()
	p, _, policyErr := s.policy.Bindings()
	subject := identity.FeatureSubjectUser
	if binding.UserID == "" {
		subject = identity.FeatureSubjectAnonymousFlow
	}
	if err != nil || policyErr != nil || binding.ValidateFor(issuanceOperation(subject)) != nil || s.authority.validate(binding) != nil ||
		b.Scope.TenantID != string(binding.TenantID) || b.Scope.SubjectID != string(binding.UserID) || b.Scope.ChallengeID != binding.RecordID ||
		p.Purpose != b.Scope.Purpose || !nativeTime(s.issuedAt) || !nativeTime(s.expiresAt) ||
		!s.expiresAt.After(s.issuedAt) || s.expiresAt.Sub(s.issuedAt) > p.TTL || p.TTL%time.Microsecond != 0 || p.ResendInterval%time.Microsecond != 0 {
		return ErrInvalidCommand
	}
	if original, ok := b.Authorization.PreAuthTransaction(); ok {
		flow, err := original.Bindings()
		if err != nil || binding.UserID == "" && binding.AnonymousFlowID != string(flow.Binding.ID) {
			return ErrInvalidCommand
		}
		return nil
	}
	if _, ok := b.Authorization.AuthenticatedSession(); !ok || binding.UserID == "" {
		return ErrInvalidCommand
	}
	return nil
}

func encodeSendRequestRecord(s sendRequestRecord, binding identity.CommandBinding) ([]byte, error) {
	if err := s.validate(binding); err != nil {
		return nil, err
	}
	out := appendSendContinuation([]byte(sendRequestRecordPrefix), s.continuation)
	p, checks, _ := s.policy.Bindings()
	out = appendAuthorityText(out, p.Alphabet)
	out = binary.BigEndian.AppendUint32(out, uint32(p.Length))
	for _, duration := range []time.Duration{p.TTL, p.ResendInterval, checks.LockoutAfter} {
		out = binary.BigEndian.AppendUint64(out, uint64(duration))
	}
	for _, n := range []uint32{p.MaximumSends, p.Attempts, checks.MaximumChecks} {
		out = binary.BigEndian.AppendUint32(out, n)
	}
	out = append(out, byte(p.Replacement))
	if checks.Enabled {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = appendAuthorityText(out, s.issuedAt.UTC().Format(time.RFC3339Nano))
	out = appendAuthorityText(out, s.expiresAt.UTC().Format(time.RFC3339Nano))
	wire := encodeAuthorityRecord(out, s.authority)
	clear(out)
	if len(wire) > 8192 {
		clear(wire)
		return nil, ErrInvalidCommand
	}
	return wire, nil
}

func decodeSendRequestRecord(wire []byte, binding identity.CommandBinding) (sendRequestRecord, error) {
	bad := func() (sendRequestRecord, error) { return sendRequestRecord{}, ErrInvalidCommand }
	if len(wire) == 0 || len(wire) > 8192 {
		return bad()
	}
	data, authority, err := decodeAuthorityProfile(wire, binding, sendRequestRecordPrefix)
	if err != nil || authority == nil || !bytes.HasPrefix(data, []byte(sendRequestRecordPrefix)) {
		return bad()
	}
	r := recordReader{data: data[len(sendRequestRecordPrefix):], ok: true}
	continuation, err := readSendContinuation(&r)
	if err != nil {
		return bad()
	}
	b, _ := continuation.Bindings()
	alphabet, length := r.text(94), r.u32()
	if length < 4 || length > 128 {
		return bad()
	}
	p := otp.CodeProfileSpec{Purpose: b.Scope.Purpose, Alphabet: alphabet, Length: int(length), TTL: time.Duration(r.u64()), ResendInterval: time.Duration(r.u64())}
	checks := otp.CheckPolicySpec{LockoutAfter: time.Duration(r.u64())}
	p.MaximumSends, p.Attempts, checks.MaximumChecks = r.u32(), r.u32(), r.u32()
	p.Replacement = otp.ReplacementPolicy(r.u8())
	switch r.u8() {
	case 0:
	case 1:
		checks.Enabled = true
	default:
		return bad()
	}
	issued, expires := r.text(35), r.text(35)
	issuedAt, e1 := time.Parse(time.RFC3339Nano, issued)
	expiresAt, e2 := time.Parse(time.RFC3339Nano, expires)
	if !r.ok || len(r.data) != 0 || e1 != nil || e2 != nil || issuedAt.UTC().Format(time.RFC3339Nano) != issued || expiresAt.UTC().Format(time.RFC3339Nano) != expires {
		return bad()
	}
	profile, err := otp.NewCodeProfile(p)
	if err != nil {
		return bad()
	}
	policy, err := otp.NewAttemptPolicy(profile, checks)
	if err != nil {
		return bad()
	}
	s := sendRequestRecord{continuation: continuation, policy: policy, authority: *authority, issuedAt: issuedAt, expiresAt: expiresAt}
	if s.validate(binding) != nil {
		return bad()
	}
	return s, nil
}
