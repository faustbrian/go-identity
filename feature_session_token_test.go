package identity_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

func TestFeatureCodeRetainsDisjointSessionToken(t *testing.T) {
	code, _ := auth.NewOneTimeCode("123456")
	wire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	c, err := identity.NewFeatureOneTimeCodeSessionCommand(featureCommandSpec(), code, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	credential, ok := c.SessionToken()
	if !ok || credential.Token() != wire {
		t.Fatal("original session token lost")
	}
	if _, ok := c.PreAuthCookie(); ok {
		t.Fatal("session token became pre-auth cookie")
	}
	if _, ok := c.OneTimeCode(); !ok {
		t.Fatal("original code lost")
	}
	spec, _ := c.Feature()
	reconstructed, _ := identity.NewFeatureCommand(spec)
	if _, ok := reconstructed.SessionToken(); ok {
		t.Fatal("scalar projection fabricated session token")
	}
	preauth, _ := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, auth.NewBearerCredential(wire))
	if _, ok := preauth.SessionToken(); ok {
		t.Fatal("pre-auth cookie became session token")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, c), wire) {
			t.Fatal("session token disclosed")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("session command serialized")
	}
	for _, bad := range []string{"", wire + "=", wire + "\n", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 65)), wire[:42] + "B"} {
		failed, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, auth.NewBearerCredential(bad))
		if err == nil {
			t.Fatal("noncanonical session token accepted")
		}
		if _, ok := failed.SessionToken(); ok {
			t.Fatal("failed constructor retained session token")
		}
	}
	if _, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, auth.OneTimeCode{}, auth.NewBearerCredential(wire)); err == nil {
		t.Fatal("zero code accepted")
	}
	if _, err := identity.NewFeatureOneTimeCodeSessionCommand(identity.FeatureCommandSpec{}, code, auth.NewBearerCredential(wire)); err == nil {
		t.Fatal("zero scope accepted")
	}
}
