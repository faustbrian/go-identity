package password

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// PhoneResetBinding is original trusted phone-recovery issuance scope, not
// proof that an OTP, independent factor or risk decision has been accepted.
// IdentifierID/IdentifierVersion in ResetGrantSpec select the verified phone;
// VerificationVersion fixes its separate verification predecessor. NumberDigest
// is an owning workflow's domain-separated keyed digest, never a bare hash of
// the small phone-number space; NumberKeyVersion identifies its retained key.
// PreAuthTransaction, OTPChallengeID and AttemptID identify original custody.
// FactorID/FactorVersion select a current independent TOTP credential; the
// aggregate MFA authority generation is ResetGrantSpec.FactorVersion. Other
// factor methods are not selected by this profile. Native admission must fence
// every owner and atomically consume all proofs with password/session effects.
// Values contain only comparable scalars, own no resources and may be copied.
type PhoneResetBinding struct {
	PreAuthTransaction, OTPChallengeID string
	AttemptID                          identity.CommandID
	NumberDigest                       [32]byte
	NumberKeyVersion                   uint32
	VerificationVersion                uint64
	FactorID                           string
	FactorVersion, RiskPolicyVersion   uint64
}

func (b PhoneResetBinding) valid() bool {
	_, err := identity.ParseCommandID(string(b.AttemptID))
	return err == nil && resetVisible(b.PreAuthTransaction, 128) && len(b.PreAuthTransaction) >= 16 &&
		resetVisible(b.OTPChallengeID, 128) && len(b.OTPChallengeID) >= 16 &&
		b.NumberDigest != ([32]byte{}) && b.NumberKeyVersion != 0 && b.VerificationVersion != 0 &&
		resetVisible(b.FactorID, 128) && b.FactorVersion != 0 && b.RiskPolicyVersion != 0
}

// Format redacts original phone/factor and pre-authentication custody.
func (PhoneResetBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("password.PhoneResetBinding(redacted)"))
}

// MarshalJSON denies implicit sensitive metadata export.
func (PhoneResetBinding) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit export and map-key use.
func (PhoneResetBinding) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// NewPhoneResetProfile explicitly selects canonical reset capability scope for
// phone recovery with a current independent TOTP. NewResetProfile remains the
// unchanged email-only profile; neither accepts the other's grants. This pure
// constructor enables no workflow, endpoint, issuer or recovery authority.
// Capability signature/provenance, one-use phone OTP, distinct initiation and
// completion risk evidence, TOTP consumption, HIBP and atomic session revocation
// remain mandatory owning-workflow responsibilities. Zero profiles deny.
func NewPhoneResetProfile(c ResetProfileConfig) (ResetProfile, error) {
	return newResetProfile(c, auth.RecoveryPathPhone)
}

func (b PhoneResetBinding) caveats() map[string]string {
	// Capability's default contract permits 16 caveats, each at most512 bytes.
	// Six bounded tuples plus the unchanged nine reset caveats fit that actual
	// boundary. Split only the fixed prefix: factor IDs may themselves use ':'.
	return map[string]string{
		"phone.preauth":   b.PreAuthTransaction,
		"phone.challenge": b.OTPChallengeID,
		"phone.attempt":   string(b.AttemptID),
		"phone.number":    strconv.FormatUint(uint64(b.NumberKeyVersion), 10) + ":" + hex.EncodeToString(b.NumberDigest[:]),
		"phone.factor":    "totp:" + strconv.FormatUint(b.FactorVersion, 10) + ":" + b.FactorID,
		"phone.policy":    strconv.FormatUint(b.VerificationVersion, 10) + ":" + strconv.FormatUint(b.RiskPolicyVersion, 10),
	}
}

func phoneResetBinding(caveats map[string]string) (PhoneResetBinding, error) {
	b := PhoneResetBinding{PreAuthTransaction: caveats["phone.preauth"], OTPChallengeID: caveats["phone.challenge"], AttemptID: identity.CommandID(caveats["phone.attempt"])}
	number := strings.SplitN(caveats["phone.number"], ":", 2)
	factor := strings.SplitN(caveats["phone.factor"], ":", 3)
	policy := strings.SplitN(caveats["phone.policy"], ":", 2)
	if len(number) != 2 || len(factor) != 3 || factor[0] != "totp" || len(policy) != 2 || len(number[1]) != 64 {
		return PhoneResetBinding{}, ErrInvalidReset
	}
	numberVersion, err := strconv.ParseUint(number[0], 10, 32)
	if err != nil {
		return PhoneResetBinding{}, ErrInvalidReset
	}
	b.NumberKeyVersion = uint32(numberVersion)
	digest, err := hex.DecodeString(number[1])
	if err != nil {
		return PhoneResetBinding{}, ErrInvalidReset
	}
	copy(b.NumberDigest[:], digest)
	b.FactorID = factor[2]
	for _, item := range []struct {
		text   string
		target *uint64
	}{{factor[1], &b.FactorVersion}, {policy[0], &b.VerificationVersion}, {policy[1], &b.RiskPolicyVersion}} {
		value, err := strconv.ParseUint(item.text, 10, 64)
		if err != nil {
			return PhoneResetBinding{}, ErrInvalidReset
		}
		*item.target = value
	}
	if !b.valid() {
		return PhoneResetBinding{}, ErrInvalidReset
	}
	return b, nil
}
