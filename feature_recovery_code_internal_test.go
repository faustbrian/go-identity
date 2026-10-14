package identity

import (
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication"
)

func TestRecoveryFeatureMixedCustodyDeniesEveryBorrow(t *testing.T) {
	code, _ := auth.NewRecoveryCode("synthetic-recovery-code")
	otp, _ := auth.NewOneTimeCode("123456")
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	for _, corrupt := range []func(*Command){
		func(c *Command) { c.feature.code = &otp },
		func(c *Command) { c.feature.sessionToken = &cookie },
		func(c *Command) { c.feature.passwordHash = func() string { return "synthetic" } },
		func(c *Command) { c.create = &CreateUserCommand{} },
	} {
		c := Command{feature: &featureCommandState{recovery: &code, preAuthCookie: &cookie}}
		corrupt(&c)
		_, feature := c.Feature()
		_, recovery := c.RecoveryCode()
		_, oneTime := c.OneTimeCode()
		_, browser := c.PreAuthCookie()
		_, session := c.SessionToken()
		if feature || recovery || oneTime || browser || session {
			t.Fatal("mixed recovery command retained secret custody")
		}
	}
}
