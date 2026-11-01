package identity

import (
	"testing"

	"github.com/faustbrian/go-capability/v2"
)

func TestAccountLinkPreparationMixedVariantsExposeNoPartialCommand(t *testing.T) {
	for _, mix := range []func(*Command){
		func(c *Command) { c.create = &CreateUserCommand{} },
		func(c *Command) { c.update = &UpdateUserCommand{} },
		func(c *Command) { c.profile = &ProfileUpdateCommand{} },
		func(c *Command) { c.status = &UserStatusCommand{} },
		func(c *Command) { c.unlink = &AccountUnlinkCommand{} },
		func(c *Command) { c.link = &AccountLinkCommand{} },
		func(c *Command) { c.linkCounters = &AccountLinkCounterContext{} },
		func(c *Command) { c.identifier = &IdentifierCommand{} },
		func(c *Command) { c.identifierProof = &capability.Proof{} },
		func(c *Command) { c.privacy = &PrivacyExportRequestCommand{} },
		func(c *Command) { c.privacyProof = &capability.Proof{} },
		func(c *Command) { c.feature = &featureCommandState{} },
	} {
		command := Command{linkPreparation: &accountLinkPreparationState{}}
		mix(&command)
		_, _, _, preparation := command.AccountLinkPreparationInput()
		_, create := command.CreateUser()
		_, update := command.UpdateUser()
		_, profile := command.UpdateProfile()
		_, status := command.UserStatus()
		_, unlink := command.UnlinkAccount()
		_, link := command.LinkAccount()
		_, _, counters := command.AccountLinkCounterCommand()
		_, identifier := command.ChangeIdentifier()
		_, privacy := command.RequestPrivacyExport()
		_, feature := command.Feature()
		if preparation || create || update || profile || status || unlink || link || counters || identifier || privacy || feature {
			t.Fatal("mixed preparation exposes partial command or custody")
		}
	}
}
