package postgres

import (
	"context"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type oneTapCallbackAccountParticipant struct{ scopeFeatureParticipant }

func (*oneTapCallbackAccountParticipant) Descriptor() ContributorDescriptor {
	return oneTapCallbackDescriptor()
}

func oneTapCallbackAccountSpec(t *testing.T, expected ProviderAccountAdmission) identity.FeatureCommandSpec {
	t.Helper()
	s, _ := signinAccountCommand(t, expected)
	s.Operation = OneTapCallbackOperation()
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.RecordID = s.Binding.AnonymousFlowID
	return s
}

func TestOneTapCallbackAccountRequiresExactGoogleAndBrowserScope(t *testing.T) {
	expected := signinAccountFixture()
	expected.Account.Provider, expected.Account.Issuer = "google", "https://accounts.google.com"
	_, ordinary := signinAccountCommand(t, expected)
	s := oneTapCallbackAccountSpec(t, expected)
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	newCallback := func(t *testing.T, input identity.FeatureCommandSpec) identity.Command {
		t.Helper()
		command, err := identity.NewFeaturePreAuthCommand(input, bearer)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := newCallback(t, s)
	if got, err := OneTapCallbackAccount(command); err != nil || got != expected {
		t.Fatal("verified Google account snapshot lost from exact One Tap scope", err)
	}
	if got, err := OAuthSigninAccount(command); err == nil || got != (ProviderAccountAdmission{}) {
		t.Fatal("generic OAuth opened One Tap account custody")
	}
	if got, err := OneTapCallbackAccount(ordinary); err == nil || got != (ProviderAccountAdmission{}) {
		t.Fatal("One Tap opened generic OAuth account custody")
	}
	metadata, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OneTapCallbackAccount(metadata); err == nil || got != (ProviderAccountAdmission{}) {
		t.Fatal("metadata alone admitted a provider account")
	}
	for _, mode := range []string{"record", "provider", "issuer", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			candidate, source := s, expected
			switch mode {
			case "record":
				candidate.Binding.RecordID = "substituted-flow"
			case "provider":
				source.Account.Provider = "other"
			case "issuer":
				source.Account.Issuer = "https://other.example"
			case "tenant":
				source.Account.TenantID, source.Credential.Credential.TenantID = "other", "other"
			}
			fields, err := OAuthSigninAccountFields(source)
			if err != nil {
				t.Fatal(err)
			}
			candidate.Fields = fields
			if got, err := OneTapCallbackAccount(newCallback(t, candidate)); err == nil || got != (ProviderAccountAdmission{}) {
				t.Fatal("substituted scope acquired Google account custody")
			}
		})
	}
	if got, err := (Work{}).RequireOneTapCallbackAccount(context.Background(), &oneTapCallbackAccountParticipant{}, command); err == nil || !got.IsZero() {
		t.Fatal("account metadata authorized an invocation without original Work")
	}
}
