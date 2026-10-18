package phonehttp

import (
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-identity/otp"
)

func TestRecoveryResponseExplicitProjectionRoundTrip(t *testing.T) {
	original := otp.CheckRecoveryBindings{SendCommandID: "AgICAgICAgICAgICAgICAg", Attempt: otp.AttemptRecoveryIdentity{TenantID: "tenant-a", CommandID: "AwMDAwMDAwMDAwMDAwMDAw", AttemptID: "BAQEBAQEBAQEBAQEBAQEBA", Fingerprint: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU", FingerprintKeyVersion: 1}, ExpectedVersion: 1, DigestKeyVersion: 1, ScopeDigest: [32]byte{1}}
	for _, outcome := range []string{"not_committed", "committed", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			projection := recoveryWire(original)
			wire, err := json.Marshal(VerificationResponse{CommitOutcome: outcome, Recovery: &projection})
			if err != nil {
				t.Fatal("explicit phone response cannot serialize original recovery")
			}
			var response struct {
				CommitOutcome string                     `json:"commitOutcome"`
				Recovery      map[string]json.RawMessage `json:"recovery"`
			}
			if err := json.Unmarshal(wire, &response); err != nil || response.CommitOutcome != outcome {
				t.Fatal("phone response lost original outcome")
			}
			restored, err := decodeRecovery(response.Recovery)
			bindings, bindingErr := restored.Bindings()
			if err != nil || bindingErr != nil || bindings != original {
				t.Fatal("explicit phone recovery projection changed original custody")
			}
		})
	}
}

func TestRecoveryDigestRequiresExactArrayWire(t *testing.T) {
	base := `{"sendCommandID":"AgICAgICAgICAgICAgICAg","attempt":{"tenantID":"tenant-a","commandID":"AwMDAwMDAwMDAwMDAwMDAw","attemptID":"BAQEBAQEBAQEBAQEBAQEBA","fingerprint":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU","fingerprintKeyVersion":1},"expectedVersion":1,"digestKeyVersion":1,"scopeDigest":`
	for _, row := range []struct {
		name, digest string
		valid        bool
	}{
		{"array", `[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]`, true},
		{"base64", `"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, false},
		{"mixed-null", `[1,null,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]`, false},
		{"short", `[1]`, false},
		{"long", `[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]`, false},
		{"null", `null`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var input map[string]json.RawMessage
			if err := json.Unmarshal([]byte(base+row.digest+`}`), &input); err != nil {
				t.Fatal(err)
			}
			_, err := decodeRecovery(input)
			if (err == nil) != row.valid {
				t.Fatal("recovery digest wire accepted an alternate representation or rejected the exact array")
			}
		})
	}
}
