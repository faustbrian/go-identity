package identity

import (
	"testing"

	"github.com/faustbrian/go-authentication/v2"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestPasswordSignupInputMixedCustodyDeniesAllVariants(t *testing.T) {
	p, _ := primitive.NewSecret([]byte("synthetic-original"))
	defer p.Destroy()
	b := authentication.NewBearerCredential("synthetic-cookie")
	code, _ := authentication.NewOneTimeCode("123456")
	for _, corrupt := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.feature.code = &code },
		func(c *Command) { c.feature.preAuthCookie = &b },
		func(c *Command) { c.feature.sessionToken = &b },
		func(c *Command) { c.feature.passwordHash = func() string { return "synthetic" } },
		func(c *Command) {
			c.feature.passwordSignup = func() (string, authentication.BearerCredential) { return "synthetic", b }
		},
		func(c *Command) {
			c.feature.passwordSignin = func() (primitive.Secret, authentication.BearerCredential) { return p, b }
		},
		func(c *Command) {
			c.feature.passwordChange = func() (string, authentication.BearerCredential, authentication.ReauthenticationProof) {
				return "synthetic", b, authentication.ReauthenticationProof{}
			}
		},
	} {
		c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: FeatureRecordOmitted, SubjectRequirement: FeatureSubjectAnonymousFlow}}, passwordSignupInput: func() (primitive.Secret, authentication.BearerCredential) { return p, b }}}
		corrupt(&c)
		_, input := c.PasswordSignupInputFeature()
		_, _, custody := c.PasswordSignupInputCustody()
		_, generated := c.PasswordSignupFeature()
		_, _, verifier := c.PasswordSignupCustody()
		_, signin := c.PasswordSigninFeature()
		_, _, signinCustody := c.PasswordSigninCustody()
		_, feature := c.Feature()
		_, hash := c.PasswordHash()
		_, change := c.PasswordChangeFeature()
		_, cookie := c.PreAuthCookie()
		_, token := c.SessionToken()
		_, otp := c.OneTimeCode()
		if input || custody || generated || verifier || signin || signinCustody || feature || hash || change || cookie || token || otp {
			t.Fatal("mixed input disclosed partial custody")
		}
	}
}
