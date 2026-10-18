package phonehttp

import (
	"bytes"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
)

// VerificationRecovery explicitly projects the original code-free correlation.
// It is neither secret-safe logging data nor permission to compare a code,
// generate a replacement command, or infer that an original outcome committed.
type VerificationRecovery struct {
	SendCommandID    identity.CommandID `json:"sendCommandID"`
	Attempt          RecoveryAttempt    `json:"attempt"`
	ExpectedVersion  uint64             `json:"expectedVersion"`
	DigestKeyVersion uint32             `json:"digestKeyVersion"`
	ScopeDigest      [32]byte           `json:"scopeDigest"`
}

// RecoveryAttempt identifies the original server-owned logical comparison and
// fingerprint generation. It contains no submitted code or bearer credential.
type RecoveryAttempt struct {
	TenantID              identity.TenantID      `json:"tenantID"`
	CommandID             identity.CommandID     `json:"commandID"`
	AttemptID             otp.AttemptID          `json:"attemptID"`
	Fingerprint           otp.AttemptFingerprint `json:"fingerprint"`
	FingerprintKeyVersion uint32                 `json:"fingerprintKeyVersion"`
}

// MarshalJSON explicitly projects code-free attempt correlation. The native
// AttemptID and AttemptFingerprint intentionally reject implicit serialization;
// this selected HTTP response, like the OTP transport, owns their wire export.
func (r RecoveryAttempt) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		TenantID              identity.TenantID  `json:"tenantID"`
		CommandID             identity.CommandID `json:"commandID"`
		AttemptID             string             `json:"attemptID"`
		Fingerprint           string             `json:"fingerprint"`
		FingerprintKeyVersion uint32             `json:"fingerprintKeyVersion"`
	}{r.TenantID, r.CommandID, string(r.AttemptID), string(r.Fingerprint), r.FingerprintKeyVersion})
}

func closedFields(input map[string]json.RawMessage, fields map[string]any) bool {
	if len(input) != len(fields) {
		return false
	}
	for key, target := range fields {
		wire, found := input[key]
		if !found || bytes.Equal(bytes.TrimSpace(wire), []byte("null")) || json.Unmarshal(wire, target) != nil {
			return false
		}
	}
	return true
}

func decodeRecovery(input map[string]json.RawMessage) (phone.VerificationRecovery, error) {
	// encoding/json accepts base64 strings for []byte. This wire contract is
	// an exact 32-item integer array, matching the explicit response projection.
	digest := bytes.TrimSpace(input["scopeDigest"])
	if len(digest) == 0 || digest[0] != '[' {
		return phone.VerificationRecovery{}, identityhttp.ErrInvalidInput
	}
	var scope []json.RawMessage
	var attempt map[string]json.RawMessage
	var b otp.CheckRecoveryBindings
	if !closedFields(input, map[string]any{"sendCommandID": &b.SendCommandID, "attempt": &attempt, "expectedVersion": &b.ExpectedVersion, "digestKeyVersion": &b.DigestKeyVersion, "scopeDigest": &scope}) || len(scope) != 32 {
		return phone.VerificationRecovery{}, identityhttp.ErrInvalidInput
	}
	for i, item := range scope {
		if bytes.Equal(bytes.TrimSpace(item), []byte("null")) || json.Unmarshal(item, &b.ScopeDigest[i]) != nil {
			return phone.VerificationRecovery{}, identityhttp.ErrInvalidInput
		}
	}
	if !closedFields(attempt, map[string]any{"tenantID": &b.Attempt.TenantID, "commandID": &b.Attempt.CommandID, "attemptID": &b.Attempt.AttemptID, "fingerprint": &b.Attempt.Fingerprint, "fingerprintKeyVersion": &b.Attempt.FingerprintKeyVersion}) {
		return phone.VerificationRecovery{}, identityhttp.ErrInvalidInput
	}
	return phone.NewVerificationRecovery(b)
}

func recoveryWire(b otp.CheckRecoveryBindings) VerificationRecovery {
	return VerificationRecovery{SendCommandID: b.SendCommandID, Attempt: RecoveryAttempt{TenantID: b.Attempt.TenantID, CommandID: b.Attempt.CommandID, AttemptID: b.Attempt.AttemptID, Fingerprint: b.Attempt.Fingerprint, FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion}, ExpectedVersion: b.ExpectedVersion, DigestKeyVersion: b.DigestKeyVersion, ScopeDigest: b.ScopeDigest}
}

func outcome(value identity.CommitOutcome) string {
	switch value {
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	default:
		return "none"
	}
}
