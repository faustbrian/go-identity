package postgres

import (
	"fmt"
	"math"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// OTPAttemptMode keeps separately metered checks distinct from consuming use.
// Zero and unknown modes are invalid; this tag conveys no verification result.
type OTPAttemptMode uint8

const (
	// OTPCheck counts a non-consuming comparison and never grants a reservation.
	OTPCheck OTPAttemptMode = iota + 1
	// OTPConsume selects counted verification and generation-bound reservation.
	OTPConsume
)

// OTPAttemptPlan freezes one server-prepared logical submission. AttemptID is
// random128 canonical base64url, not a client idempotency key. The native OTP
// owner must authenticate/reconstruct the complete attempt against immutable
// command custody and current configuration before SQL. AttemptFingerprint is
// its keyed submission binding, NOT the coordinator's authoritative fingerprint.
// ScopeDigest binds the complete purpose/subject/channel/workflow/authorization
// scope; no destination, code, pepper or authorization bearer is stored here.
// Every version is positive. ChallengeID is bounded to 256 UTF-8 bytes without
// controls. Changes mean different command intent, never a retry of this one.
//
// These are declarations, not proof, current authority or durable outcomes.
// Native counted denial/reservation and domain phases remain mandatory and are
// not activated by this plan. Copies own all scalars; do not mutate caller input
// concurrently with preparation. Formatting redacts and serialization rejects.
type OTPAttemptPlan struct {
	AttemptID             string
	AttemptFingerprint    [32]byte
	FingerprintKeyVersion uint32
	ChallengeID           string
	ScopeDigest           [32]byte
	DigestKeyVersion      uint32
	ExpectedVersion       uint64
	Mode                  OTPAttemptMode
}

// Format hides private attempt/challenge linkage for every format verb.
func (OTPAttemptPlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPAttemptPlan(redacted)"))
}

// MarshalJSON prevents accidentally exporting private attempt custody.
func (OTPAttemptPlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }

// MarshalText rejects implicit wire conversion of private attempt custody.
func (OTPAttemptPlan) MarshalText() ([]byte, error) { return nil, invalidPlan() }

func otpDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}
}

func validateOTPPlan(p CommandPlan) error {
	s := p.OTP
	if s == nil {
		return nil
	}
	if p.Feature == nil || p.SubjectType == "" || p.CaptchaReplayReservation ||
		s.AttemptFingerprint == ([32]byte{}) || s.FingerprintKeyVersion == 0 || s.ScopeDigest == ([32]byte{}) || s.DigestKeyVersion == 0 || s.ExpectedVersion == 0 ||
		(s.Mode != OTPCheck && s.Mode != OTPConsume) || len(s.ChallengeID) == 0 || len(s.ChallengeID) > 256 || !utf8.ValidString(s.ChallengeID) {
		return invalidPlan()
	}
	if _, err := identity.ParseCommandID(s.AttemptID); err != nil {
		return invalidPlan()
	}
	for _, r := range s.ChallengeID {
		if unicode.IsControl(r) {
			return invalidPlan()
		}
	}
	return nil
}

func cloneOTPPlan(p *OTPAttemptPlan) *OTPAttemptPlan {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func encodeOTPPlan(p *OTPAttemptPlan) []byte {
	return cborMap(map[string][]byte{
		"attempt_id": cborText(p.AttemptID), "attempt_fingerprint": cborBytes(p.AttemptFingerprint[:]),
		"fingerprint_key_version": cborUint(uint64(p.FingerprintKeyVersion)), "challenge_id": cborText(p.ChallengeID),
		"scope_digest": cborBytes(p.ScopeDigest[:]), "digest_key_version": cborUint(uint64(p.DigestKeyVersion)),
		"expected_version": cborUint(p.ExpectedVersion), "mode": cborUint(uint64(p.Mode)),
	})
}

func readOTPPlan(r *planReader) *OTPAttemptPlan {
	p := &OTPAttemptPlan{}
	r.expect(5, 8)
	for range 8 {
		switch r.string(32) {
		case "attempt_id":
			p.AttemptID = r.string(22)
		case "attempt_fingerprint":
			r.digest(&p.AttemptFingerprint)
		case "fingerprint_key_version":
			p.FingerprintKeyVersion = uint32(r.number(math.MaxUint32))
		case "challenge_id":
			p.ChallengeID = r.string(256)
		case "scope_digest":
			r.digest(&p.ScopeDigest)
		case "digest_key_version":
			p.DigestKeyVersion = uint32(r.number(math.MaxUint32))
		case "expected_version":
			p.ExpectedVersion = r.number(math.MaxUint64)
		case "mode":
			p.Mode = OTPAttemptMode(r.number(math.MaxUint8))
		default:
			r.ok = false
			return p
		}
	}
	return p
}
