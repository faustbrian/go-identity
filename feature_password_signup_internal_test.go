package identity

import (
	"github.com/faustbrian/go-authentication"
	primitive "github.com/faustbrian/go-password"
	"testing"
)

func TestPasswordSignupMixedVariantsDenyAllCustody(t *testing.T) {
	b := authentication.NewBearerCredential("synthetic-cookie")
	p, _ := primitive.NewSecret([]byte("synthetic-password"))
	defer p.Destroy()
	code, _ := authentication.NewOneTimeCode("123456")
	for _, corrupt := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.update = &UpdateUserCommand{} },
		func(c *Command) { c.profile = &ProfileUpdateCommand{} },
		func(c *Command) { c.status = &UserStatusCommand{} },
		func(c *Command) { c.unlink = &AccountUnlinkCommand{} },
		func(c *Command) { c.link = &AccountLinkCommand{} },
		func(c *Command) { c.identifier = &IdentifierCommand{} },
		func(c *Command) { c.privacy = &PrivacyExportRequestCommand{} },
		func(c *Command) { c.feature.code = &code },
		func(c *Command) { c.feature.preAuthCookie = &b },
		func(c *Command) { c.feature.sessionToken = &b },
		func(c *Command) { c.feature.passwordHash = func() string { return "synthetic" } },
		func(c *Command) {
			c.feature.passwordChange = func() (string, authentication.BearerCredential, authentication.ReauthenticationProof) {
				return "synthetic", b, authentication.ReauthenticationProof{}
			}
		},
		func(c *Command) {
			c.feature.passwordSignin = func() (primitive.Secret, authentication.BearerCredential) { return p, b }
		},
	} {
		c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: FeatureRecordOmitted}}, passwordSignup: func() (string, authentication.BearerCredential) { return "synthetic", b }}}
		corrupt(&c)
		_, sm := c.PasswordSignupFeature()
		h, cookie, sc := c.PasswordSignupCustody()
		_, f := c.Feature()
		_, hc := c.PasswordHash()
		_, hm := c.PasswordHashFeature()
		_, cm := c.PasswordChangeFeature()
		_, _, _, cc := c.PasswordChangeCustody()
		_, im := c.PasswordSigninFeature()
		_, _, ic := c.PasswordSigninCustody()
		_, otp := c.OneTimeCode()
		_, pc := c.PreAuthCookie()
		_, st := c.SessionToken()
		if sm || sc || h != "" || cookie.Token() != "" || f || hc || hm || cm || cc || im || ic || otp || pc || st {
			t.Fatal("mixed signup disclosed partial custody")
		}
	}
}
