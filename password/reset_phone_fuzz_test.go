package password

import (
	"strings"
	"testing"
)

func FuzzPhoneResetBinding(f *testing.F) {
	f.Add("2:"+strings.Repeat("01", 32), "totp:5:factor:opaque", "3:6", "original-phone-preauth", "original-phone-challenge", "AAAAAAAAAAAAAAAAAAAAAQ")
	f.Add("", "", "", "", "", "")
	f.Fuzz(func(t *testing.T, number, factor, policy, preauth, challenge, attempt string) {
		// The capability owner bounds every signed caveat to512 bytes before
		// this parser can receive it. Keep that actual hostile-input boundary.
		for _, value := range []string{number, factor, policy, preauth, challenge, attempt} {
			if len(value) > 512 {
				t.Skip()
			}
		}
		b, err := phoneResetBinding(map[string]string{"phone.number": number, "phone.factor": factor, "phone.policy": policy, "phone.preauth": preauth, "phone.challenge": challenge, "phone.attempt": attempt})
		if err != nil {
			return
		}
		if !b.valid() {
			t.Fatal("parser returned invalid scope")
		}
		roundTrip, err := phoneResetBinding(b.caveats())
		if err != nil || roundTrip != b {
			t.Fatal("canonical scope round trip changed original identity", err)
		}
	})
}
