package identity_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// Issuing a challenge authenticates original flow possession but has no code
// submission. Fabricating one would confuse issuance with attempted consumption.
func TestFeatureFlowBearerWithoutCode(t *testing.T) {
	for _, session := range []bool{false, true} {
		construct := identity.NewFeaturePreAuthCommand
		if session {
			construct = identity.NewFeatureSessionCommand
		}
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
		spec := featureCommandSpec()
		command, err := construct(spec, auth.NewBearerCredential(wire))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := command.OneTimeCode(); ok {
			t.Fatal("issuance fabricated submitted code")
		}
		assert := func() {
			cookie, hasCookie := command.PreAuthCookie()
			token, hasToken := command.SessionToken()
			if session {
				if !hasToken || token.Token() != wire || hasCookie {
					t.Error("session custody lost or mixed")
				}
			} else if !hasCookie || cookie.Token() != wire || hasToken {
				t.Error("cookie custody lost or mixed")
			}
		}
		assert()
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(assert)
		}
		wg.Wait()
		spec.Fields[2].Value.Bytes[0] = 99
		projection, ok := command.Feature()
		if !ok {
			t.Fatal("feature projection missing")
		}
		for _, field := range projection.Fields {
			if field.Name == "proof.record-digest" && field.Value.Bytes[0] != 1 {
				t.Fatal("command did not own fields")
			}
		}
		reconstructed, err := identity.NewFeatureCommand(projection)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reconstructed.PreAuthCookie(); ok {
			t.Fatal("projection restored cookie")
		}
		if _, ok := reconstructed.SessionToken(); ok {
			t.Fatal("projection restored session token")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(format, command), wire) {
				t.Fatal("bearer disclosed")
			}
		}
		if _, err := json.Marshal(command); err == nil {
			t.Fatal("bearer command serialized")
		}
		for _, size := range []int{32, 33, 63, 64} {
			valid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, size))
			if _, err := construct(featureCommandSpec(), auth.NewBearerCredential(valid)); err != nil {
				t.Fatal("bounded valid bearer rejected", size, err)
			}
		}
		for _, invalid := range []string{"", wire + "=", wire + "\n", " " + wire, wire[:42] + "B", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 65))} {
			failed, err := construct(featureCommandSpec(), auth.NewBearerCredential(invalid))
			if err == nil {
				t.Fatal("invalid bearer accepted")
			}
			var invalidInput identity.InvalidInputError
			if !errors.As(err, &invalidInput) || invalid != "" && strings.Contains(err.Error(), invalid) {
				t.Fatal("invalid input error not typed/redacted")
			}
			if _, ok := failed.Feature(); ok {
				t.Fatal("failure retained usable command")
			}
		}
		if _, err := construct(featureCommandSpec(), auth.NewBearerCredential(strings.Repeat("A", 1<<16))); err == nil {
			t.Fatal("oversized bearer admitted")
		}
		if _, err := construct(identity.FeatureCommandSpec{}, auth.NewBearerCredential(wire)); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
}

func FuzzFeatureFlowBearer(f *testing.F) {
	for _, size := range []int{31, 32, 64, 65} {
		f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, size)), true)
	}
	f.Add("", false)
	f.Fuzz(func(t *testing.T, wire string, session bool) {
		construct := identity.NewFeaturePreAuthCommand
		if session {
			construct = identity.NewFeatureSessionCommand
		}
		command, err := construct(featureCommandSpec(), auth.NewBearerCredential(wire))
		if err != nil {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
		if err != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
			t.Fatal("noncanonical bearer accepted")
		}
		if _, ok := command.OneTimeCode(); ok {
			t.Fatal("generated code custody")
		}
		cookie, hasCookie := command.PreAuthCookie()
		token, hasToken := command.SessionToken()
		if session {
			if !hasToken || token.Token() != wire || hasCookie {
				t.Fatal("wrong custody")
			}
		} else if !hasCookie || cookie.Token() != wire || hasToken {
			t.Fatal("wrong custody")
		}
	})
}
