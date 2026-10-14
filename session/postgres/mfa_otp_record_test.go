package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestOTPCompletionRecordCannotAdoptHistoricalTOTPProfile(t *testing.T) {
	for _, password := range []bool{false, true} {
		for _, csrf := range []bool{false, true} {
			_, record := mfaCompletionMappingMethod(t, csrf, password, "otp")
			wire, _, err := encodeRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			var projection struct{ Schema uint32 }
			if json.Unmarshal(wire, &projection) != nil {
				t.Fatal("invalid native record")
			}
			want := uint32(17)
			if password {
				want = 19
			}
			if csrf {
				want++
			}
			if projection.Schema != want {
				t.Fatal("secondary OTP was encoded as another factor profile", projection.Schema, want)
			}
			if _, err := decodeRecord(wire); err != nil {
				t.Fatal("selected OTP record did not restore", err)
			}
			old := uint32(9)
			if password {
				old = 11
			}
			if csrf {
				old++
			}
			var data map[string]any
			if json.Unmarshal(wire, &data) != nil {
				t.Fatal("invalid fixture")
			}
			data["Schema"] = old
			changed, _ := json.Marshal(data)
			if _, err := decodeRecord(changed); err == nil {
				t.Fatal("OTP silently adopted a historical TOTP schema")
			}
			_, totp := mfaCompletionMappingProfile(t, csrf, password)
			prior, _, err := encodeRecord(totp)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeRecord(prior); err != nil {
				t.Fatal("historical TOTP no longer restores", err)
			}
			if _, err := decodeRecord(bytes.Replace(prior, []byte(`"Method":"totp"`), []byte(`"Method":"otp"`), 1)); err == nil {
				t.Fatal("method-tag substitution upgraded old TOTP custody")
			}
		}
	}
}
