package identity

import (
	"testing"

	"github.com/faustbrian/go-authentication"
)

func TestFeatureCommandMixedUnionIsInvalid(t *testing.T) {
	for _, add := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.update = &UpdateUserCommand{} },
		func(c *Command) { c.profile = &ProfileUpdateCommand{} },
		func(c *Command) { c.status = &UserStatusCommand{} },
		func(c *Command) { c.unlink = &AccountUnlinkCommand{} },
		func(c *Command) { c.link = &AccountLinkCommand{} },
		func(c *Command) { c.identifier = &IdentifierCommand{} },
	} {
		// Internal corruption fixture: public constructors cannot create two
		// variants. Each accessor must still deny a mixed internal value.
		c := Command{feature: &featureCommandState{}}
		add(&c)
		_, feature := c.Feature()
		_, create := c.CreateUser()
		_, update := c.UpdateUser()
		_, profile := c.UpdateProfile()
		_, status := c.UserStatus()
		_, unlink := c.UnlinkAccount()
		_, link := c.LinkAccount()
		_, identifier := c.ChangeIdentifier()
		if feature || create || update || profile || status || unlink || link || identifier {
			t.Fatal("mixed command accepted")
		}
	}
}

func TestFeatureOneTimeCodeMixedVariantDenied(t *testing.T) {
	code, _ := authentication.NewOneTimeCode("123456")
	c := Command{feature: &featureCommandState{code: &code}, create: &CreateUserCommand{}}
	if _, ok := c.OneTimeCode(); ok {
		t.Fatal("mixed command disclosed custody")
	}
}

func TestFeaturePreAuthCookieMixedVariantDenied(t *testing.T) {
	code, _ := authentication.NewOneTimeCode("123456")
	cookie := authentication.NewBearerCredential("private-cookie")
	c := Command{feature: &featureCommandState{code: &code, preAuthCookie: &cookie}, create: &CreateUserCommand{}}
	if _, ok := c.PreAuthCookie(); ok {
		t.Fatal("mixed command disclosed cookie custody")
	}
}
