package reference

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestOneTapSelectionDoesNotDisappearInAnUnrelatedGraph(t *testing.T) {
	selected := func(alter func(*StoreConfiguration)) StoreConfiguration {
		c := StoreConfiguration{
			OneTap: &OneTapConfiguration{}, OTP: &OTPSendConfiguration{},
			PasswordSignup: &PasswordSignupConfiguration{}, PasswordSignin: &PasswordSigninConfiguration{}, Session: &SessionConfiguration{},
		}
		alter(&c)
		return c
	}
	for _, test := range []struct {
		name   string
		config StoreConfiguration
	}{
		{"HTTP without its native owner", StoreConfiguration{HTTPOneTap: &HTTPOneTapConfiguration{EnableStart: true}}},
		{"recovery only", StoreConfiguration{OneTap: &OneTapConfiguration{}}},
		{"public discovery", selected(func(c *StoreConfiguration) { c.ProviderDiscovery = &ProviderDiscoveryConfiguration{} })},
		{"machine workload", selected(func(c *StoreConfiguration) { c.OAuthWorkload = &OAuthWorkloadConfiguration{} })},
		{"standalone Passkey", selected(func(c *StoreConfiguration) {
			c.Passkey = &PasskeyConfiguration{Standalone: &PasskeyStandaloneConfiguration{}}
		})},
		{"HTTP without original pre-auth", selected(func(c *StoreConfiguration) { c.HTTPOneTap = &HTTPOneTapConfiguration{EnableStart: true} })},
	} {
		t.Run(test.name, func(t *testing.T) {
			var state storeState
			var invalid identity.InvalidInputError
			if err := state.composeFeatureStores(test.config, ReferenceDependencies{}); !errors.As(err, &invalid) || invalid.Field != oneTapReferenceField || state.features != nil {
				t.Fatalf("foreign graph did not reject One Tap selection before composing: %v", err)
			}
		})
	}
}
