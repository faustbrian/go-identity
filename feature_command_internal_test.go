package identity

import (
	"testing"

	"github.com/faustbrian/go-authentication"
	primitive "github.com/faustbrian/go-password"
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

func TestPasswordSigninMixedVariantsDenyEveryAccessor(t *testing.T) {
	p, _ := primitive.NewSecret([]byte("candidate"))
	defer p.Destroy()
	b := authentication.NewBearerCredential("opaque-cookie")
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
	} {
		c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, RecordRequirement: FeatureRecordOmitted}}, passwordSignin: func() (primitive.Secret, authentication.BearerCredential) { return p, b }}}
		corrupt(&c)
		_, metadata := c.PasswordSigninFeature()
		secret, bearer, custody := c.PasswordSigninCustody()
		_, feature := c.Feature()
		_, hash := c.PasswordHash()
		_, hm := c.PasswordHashFeature()
		_, change := c.PasswordChangeFeature()
		_, _, _, cc := c.PasswordChangeCustody()
		_, otp := c.OneTimeCode()
		_, cookie := c.PreAuthCookie()
		_, session := c.SessionToken()
		if metadata || custody || secret.Len() != 0 || bearer.Token() != "" || feature || hash || hm || change || cc || otp || cookie || session {
			t.Fatal("mixed signin custody admitted")
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

func TestFeatureMixedBearerCustodyDenied(t *testing.T) {
	code, _ := authentication.NewOneTimeCode("123456")
	token := authentication.NewBearerCredential("private-token")
	c := Command{feature: &featureCommandState{code: &code, preAuthCookie: &token, sessionToken: &token}}
	_, feature := c.Feature()
	_, hasCode := c.OneTimeCode()
	_, hasCookie := c.PreAuthCookie()
	_, hasToken := c.SessionToken()
	if feature || hasCode || hasCookie || hasToken {
		t.Fatal("mixed bearer custody admitted")
	}
}

func TestFeatureCodeFreeMixedBearerCustodyDenied(t *testing.T) {
	token := authentication.NewBearerCredential("private-token")
	for _, command := range []Command{
		{feature: &featureCommandState{preAuthCookie: &token, sessionToken: &token}},
		{feature: &featureCommandState{preAuthCookie: &token}, create: &CreateUserCommand{}},
		{feature: &featureCommandState{sessionToken: &token}, create: &CreateUserCommand{}},
	} {
		_, feature := command.Feature()
		_, code := command.OneTimeCode()
		_, cookie := command.PreAuthCookie()
		_, session := command.SessionToken()
		if feature || code || cookie || session {
			t.Fatal("mixed no-code custody disclosed")
		}
	}
}

func TestFeaturePasswordHashMixedVariantsDenyEveryAccessor(t *testing.T) {
	code, _ := authentication.NewOneTimeCode("123456")
	bearer := authentication.NewBearerCredential("private-token")
	for _, mutate := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.update = &UpdateUserCommand{} },
		func(c *Command) { c.profile = &ProfileUpdateCommand{} },
		func(c *Command) { c.status = &UserStatusCommand{} },
		func(c *Command) { c.link = &AccountLinkCommand{} },
		func(c *Command) { c.unlink = &AccountUnlinkCommand{} },
		func(c *Command) { c.identifier = &IdentifierCommand{} },
		func(c *Command) { c.privacy = &PrivacyExportRequestCommand{} },
		func(c *Command) { c.feature.code = &code },
		func(c *Command) { c.feature.preAuthCookie = &bearer },
		func(c *Command) { c.feature.sessionToken = &bearer },
		func(c *Command) {
			c.feature.passwordChange = func() (string, authentication.BearerCredential, authentication.ReauthenticationProof) {
				return "synthetic", bearer, authentication.ReauthenticationProof{}
			}
		},
	} {
		c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", RecordRequirement: FeatureRecordRequired}}, passwordHash: func() string { return "synthetic" }}}
		mutate(&c)
		_, feature := c.Feature()
		_, material := c.PasswordHash()
		_, metadata := c.PasswordHashFeature()
		_, hasCode := c.OneTimeCode()
		_, hasCookie := c.PreAuthCookie()
		_, hasSession := c.SessionToken()
		if feature || material || metadata || hasCode || hasCookie || hasSession {
			t.Fatal("mixed hash variant disclosed custody or intent")
		}
	}
}

func TestFeaturePasswordChangeMixedVariantsDenyEveryAccessor(t *testing.T) {
	code, _ := authentication.NewOneTimeCode("123456")
	bearer := authentication.NewBearerCredential("private-token")
	for _, mutate := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.update = &UpdateUserCommand{} },
		func(c *Command) { c.profile = &ProfileUpdateCommand{} },
		func(c *Command) { c.status = &UserStatusCommand{} },
		func(c *Command) { c.link = &AccountLinkCommand{} },
		func(c *Command) { c.unlink = &AccountUnlinkCommand{} },
		func(c *Command) { c.identifier = &IdentifierCommand{} },
		func(c *Command) { c.privacy = &PrivacyExportRequestCommand{} },
		func(c *Command) { c.feature.code = &code },
		func(c *Command) { c.feature.preAuthCookie = &bearer },
		func(c *Command) { c.feature.sessionToken = &bearer },
		func(c *Command) { c.feature.passwordHash = func() string { return "synthetic" } },
	} {
		c := Command{feature: &featureCommandState{spec: FeatureCommandSpec{Operation: FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: FeatureRecordRequired}}, passwordChange: func() (string, authentication.BearerCredential, authentication.ReauthenticationProof) {
			return "synthetic", bearer, authentication.ReauthenticationProof{}
		}}}
		mutate(&c)
		_, feature := c.Feature()
		_, material := c.PasswordHash()
		_, metadata := c.PasswordHashFeature()
		_, change := c.PasswordChangeFeature()
		_, _, _, custody := c.PasswordChangeCustody()
		_, hasCode := c.OneTimeCode()
		_, hasCookie := c.PreAuthCookie()
		_, hasSession := c.SessionToken()
		if feature || material || metadata || change || custody || hasCode || hasCookie || hasSession {
			t.Fatal("mixed change command admitted")
		}
	}
}
