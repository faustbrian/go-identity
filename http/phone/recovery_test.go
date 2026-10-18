package phonehttp

import (
	"encoding/json"
	"testing"
)

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
