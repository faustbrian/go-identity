package delivery_test

import (
	"fmt"
	"strings"

	"github.com/faustbrian/go-identity/delivery"
)

func ExampleMessage_Validate() {
	message := delivery.Message{
		Purpose: "email-verification", Channel: delivery.ChannelEmail,
		Recipient: delivery.Recipient{
			Channel: delivery.ChannelEmail, Address: "person@example.invalid",
			ScopeDigest: strings.Repeat("a", 64), // synthetic; workflow derives real binding
		},
		TemplateID: "verify", TemplateVersion: 1, LocaleChain: []string{"en"},
		Variables: []delivery.TemplateVariable{{Name: "name", Kind: "text", TextValue: "synthetic"}},
	}
	fmt.Println(message.Validate() == nil)
	fmt.Println(message)
	// Output:
	// true
	// delivery(redacted)
}
