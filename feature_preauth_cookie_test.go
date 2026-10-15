package identity_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestFeatureCodeRetainsSeparatePreAuthCookie(t *testing.T) {
	code, _ := auth.NewOneTimeCode("123456")
	wire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	c, err := identity.NewFeatureOneTimeCodePreAuthCommand(featureCommandSpec(), code, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	cookie, ok := c.PreAuthCookie()
	if !ok || cookie.Token() != wire {
		t.Fatal("original cookie custody lost")
	}
	if _, ok := c.OneTimeCode(); !ok {
		t.Fatal("code custody lost")
	}
	plain, _ := identity.NewFeatureOneTimeCodeCommand(featureCommandSpec(), code)
	if _, ok := plain.PreAuthCookie(); ok {
		t.Fatal("legacy command fabricated cookie")
	}
	if _, ok := (identity.Command{}).PreAuthCookie(); ok {
		t.Fatal("zero command fabricated cookie")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, c), wire) {
			t.Fatal("cookie disclosed")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("cookie command serialized")
	}
	s, _ := c.Feature()
	withoutSecrets, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withoutSecrets.PreAuthCookie(); ok {
		t.Fatal("scalar projection reconstructed cookie")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			cookie, ok := c.PreAuthCookie()
			if !ok || cookie.Token() != wire {
				t.Error("concurrent custody changed")
			}
		})
	}
	wg.Wait()
}

func FuzzFeaturePreAuthCookieCustody(f *testing.F) {
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 64)))
	f.Add("")
	f.Fuzz(func(t *testing.T, wire string) {
		if len(wire) > 128 {
			return
		}
		code, _ := auth.NewOneTimeCode("123456")
		c, err := identity.NewFeatureOneTimeCodePreAuthCommand(featureCommandSpec(), code, auth.NewBearerCredential(wire))
		if err != nil {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
		if err != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
			t.Fatal("noncanonical token accepted")
		}
		cookie, ok := c.PreAuthCookie()
		if !ok || cookie.Token() != wire {
			t.Fatal("accepted token bytes changed")
		}
	})
}

func TestFeatureCodeRejectsMalformedPreAuthCookies(t *testing.T) {
	code, _ := auth.NewOneTimeCode("123456")
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, wire := range []string{"", valid + "=", " " + valid, valid + "\n", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 65)), valid[:42] + "B"} {
		c, err := identity.NewFeatureOneTimeCodePreAuthCommand(featureCommandSpec(), code, auth.NewBearerCredential(wire))
		if err == nil {
			t.Fatal("malformed cookie accepted")
		}
		if _, ok := c.PreAuthCookie(); ok {
			t.Fatal("failed constructor retained cookie")
		}
	}
	if _, err := identity.NewFeatureOneTimeCodePreAuthCommand(featureCommandSpec(), auth.OneTimeCode{}, auth.NewBearerCredential(valid)); err == nil {
		t.Fatal("zero code accepted")
	}
	if _, err := identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{}, code, auth.NewBearerCredential(valid)); err == nil {
		t.Fatal("zero spec accepted")
	}
}
