package identity

import (
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestPhonePasswordResetMixedVariantsDenyEveryAccessor(t *testing.T) {
	secret, _ := primitive.NewSecret([]byte("synthetic"))
	defer secret.Destroy()
	code, _ := auth.NewOneTimeCode("123456")
	bearer := auth.NewBearerCredential("synthetic")
	recovery, _ := auth.NewRecoveryCode("synthetic-recovery-code")
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
		func(c *Command) { c.feature.recovery = &recovery },
		func(c *Command) { c.feature.preAuthCookie = &bearer },
		func(c *Command) { c.feature.sessionToken = &bearer },
		func(c *Command) { c.feature.passwordHash = func() string { return "synthetic" } },
		func(c *Command) {
			c.feature.passwordReset = func() (string, capability.Proof) { return "synthetic", capability.Proof{} }
		},
		func(c *Command) {
			c.feature.passwordResetInput = func() (primitive.Secret, capability.Proof) { return secret, capability.Proof{} }
		},
		func(c *Command) {
			c.feature.passwordSignin = func() (primitive.Secret, auth.BearerCredential) { return secret, bearer }
		},
		func(c *Command) {
			c.feature.passwordSignup = func() (string, auth.BearerCredential) { return "synthetic", bearer }
		},
		func(c *Command) {
			c.feature.passwordSignupInput = func() (primitive.Secret, auth.BearerCredential) { return secret, bearer }
		},
		func(c *Command) {
			c.feature.passwordChange = func() (string, auth.BearerCredential, auth.ReauthenticationProof) {
				return "synthetic", bearer, auth.ReauthenticationProof{}
			}
		},
	} {
		for _, input := range []bool{true, false} {
			c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: FeatureRecordRequired}}, phonePasswordReset: func() phonePasswordResetCommandState { return phonePasswordResetCommandState{input: input} }}}
			if _, ok := c.phonePasswordResetState(input); !ok {
				t.Fatal("original joint variant denied")
			}
			corrupt(&c)
			_, a := c.PhonePasswordResetInputFeature()
			_, b := c.PhonePasswordResetFeature()
			_, _, _, _, d := c.PhonePasswordResetInputCustody()
			_, _, _, _, e := c.PhonePasswordResetCustody()
			_, f := c.Feature()
			_, g := c.PasswordResetFeature()
			_, h := c.PasswordResetInputFeature()
			_, i := c.OneTimeCode()
			_, j := c.RecoveryCode()
			_, k := c.PreAuthCookie()
			_, l := c.SessionToken()
			if a || b || d || e || f || g || h || i || j || k || l {
				t.Fatal("mixed joint recovery exposed partial custody")
			}
		}
	}
}
