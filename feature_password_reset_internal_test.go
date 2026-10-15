package identity

import (
	"testing"

	"github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability/v2"
	primitive "github.com/faustbrian/go-password"
)

func TestFeaturePasswordResetMixedVariantsDenyAllCustody(t *testing.T) {
	b := authentication.NewBearerCredential("synthetic")
	p, _ := primitive.NewSecret([]byte("synthetic"))
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
		func(c *Command) {
			c.feature.passwordSignup = func() (string, authentication.BearerCredential) { return "synthetic", b }
		},
		func(c *Command) {
			c.feature.passwordSignupInput = func() (primitive.Secret, authentication.BearerCredential) { return p, b }
		},
	} {
		c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-complete", SchemaID: "password-reset-complete", SchemaVersion: 1, RecordRequirement: FeatureRecordRequired}}, passwordReset: func() (string, capability.Proof) { return "synthetic", capability.Proof{} }}}
		if _, ok := c.PasswordResetFeature(); !ok {
			t.Fatal("uncorrupted reset descriptor rejected")
		}
		if hash, _, ok := c.PasswordResetCustody(); !ok || hash != "synthetic" {
			t.Fatal("uncorrupted reset custody rejected")
		}
		corrupt(&c)
		_, reset := c.PasswordResetFeature()
		hash, _, custody := c.PasswordResetCustody()
		_, feature := c.Feature()
		_, hm := c.PasswordHashFeature()
		_, hc := c.PasswordHash()
		_, cm := c.PasswordChangeFeature()
		_, _, _, cc := c.PasswordChangeCustody()
		_, si := c.PasswordSigninFeature()
		_, _, sic := c.PasswordSigninCustody()
		_, su := c.PasswordSignupFeature()
		_, _, suc := c.PasswordSignupCustody()
		_, sui := c.PasswordSignupInputFeature()
		_, _, suic := c.PasswordSignupInputCustody()
		_, otp := c.OneTimeCode()
		_, cookie := c.PreAuthCookie()
		_, session := c.SessionToken()
		if reset || custody || hash != "" || feature || hm || hc || cm || cc || si || sic || su || suc || sui || suic || otp || cookie || session {
			t.Fatal("mixed reset disclosed partial custody")
		}
	}
}
