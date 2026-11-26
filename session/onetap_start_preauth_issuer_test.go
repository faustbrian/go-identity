package session

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestOneTapStartPreAuthIssuerRequiresGoogle(t *testing.T) {
	legacy, _, executor, _ := preAuthIssuerFixture(t)
	config := legacy.config
	config.Action, config.CallbackURL = "identity.oauth.onetap-start", ""
	other := PreAuthProviderBinding{ProviderID: "other", ProviderVersion: 7, ClientID: "fixture-client", Mode: PreAuthProviderCallback}
	if actual, err := NewProviderPreAuthIssuer(executor, config, other); err != nil || actual == nil {
		t.Fatal("legacy provider-bound constructor changed its accepted profiles", err)
	}
	if actual, err := NewOneTapStartPreAuthIssuer(executor, config, other); !errors.Is(err, ErrInvalidIssuer) || actual != nil {
		t.Fatal("exact Google start selected a different provider", err)
	}
}

func TestOneTapStartPreAuthIssuerRequiresItsOwnCommit(t *testing.T) {
	operation := identity.FeatureOperation{
		Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-start", SchemaID: "oauth-onetap-start-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
	for _, profile := range []struct {
		name  string
		exact bool
	}{
		{"generic receipt cannot deliver", false},
		{"exact start commit delivers once", true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			legacy, _, executor, _ := preAuthIssuerFixture(t)
			config := legacy.config
			config.Action, config.CallbackURL = operation.OperationID, ""
			provider := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "fixture-client", Mode: PreAuthProviderCallback}
			issuer, err := NewOneTapStartPreAuthIssuer(executor, config, provider)
			if err != nil {
				t.Fatal(err)
			}
			_, _, existing := preAuthFixture(t)
			prepared, err := issuer.Prepare(PreAuthPrepareInput{
				CommandID: "AgICAgICAgICAgICAgICAg", CorrelationID: "onetap-start-receipt",
				TenantID: existing.Binding.Intent.TenantID, Remember: existing.Binding.Intent.Remember,
			})
			if err != nil {
				t.Fatal(err)
			}
			original, ok := prepared.Command()
			if !ok {
				t.Fatal("missing original")
			}
			selected, err := original.Record.ProviderBindings()
			if err != nil || selected.Provider != provider || selected.Transaction.Binding.Intent.Remember != existing.Binding.Intent.Remember {
				t.Fatal("start changed configured provider or original Remember choice", err)
			}
			ordinaryRecord, err := NewPreAuthTransaction(selected.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			observation := preAuthCommitted(PreAuthIssueCommand{CommandID: original.CommandID, CorrelationID: original.CorrelationID, Record: ordinaryRecord})
			if profile.exact {
				observation.Receipt.Binding.OperationID = operation.OperationID
				observation.Receipt.Binding.SchemaID = operation.SchemaID
				observation.Receipt.Feature = &identity.FeatureReceipt{Operation: operation, AfterVersion: 1}
			}
			executor.execute = func(_ context.Context, command PreAuthIssueCommand) (PreAuthIssueExecution, error) {
				if command != original {
					t.Fatal("changed original issuance command")
				}
				return observation, nil
			}
			out, err := issuer.Issue(t.Context(), prepared)
			if !profile.exact {
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || out.CommitOutcome != identity.CommitOutcomeUnknown {
					t.Fatal("generic receipt asserted exact One Tap start", err)
				}
				noPreAuthDelivery(t, out)
				return
			}
			if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed || out.Flow != original.Record || out.Cookie.Name != "__Host-identity_flow" {
				t.Fatal("exact One Tap start did not deliver the original flow", err)
			}
			wire, err := out.Token.Reveal()
			if err != nil {
				t.Fatal("exact commit did not deliver original cookie", err)
			}
			token, err := ParseToken(wire)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := token.ProviderPreAuthDigest(config.LookupKey, selected.Transaction.Binding, provider)
			if err != nil || digest != selected.Transaction.Cookie {
				t.Fatal("delivered cookie did not bind the exact One Tap flow", err)
			}
			again, err := issuer.Issue(t.Context(), prepared)
			if !errors.Is(err, ErrIssuanceAlreadyAttempted) {
				t.Fatal("exact start was attempted again", err)
			}
			noPreAuthDelivery(t, again)
			executor.recover = func(_ context.Context, query identity.RecoveryQuery) (identity.CommandResult, error) {
				if query.CommandID != original.CommandID || query.OperationID != operation.OperationID || query.RecordID != string(selected.Transaction.Binding.ID) {
					t.Fatal("recovery queried unrelated command custody")
				}
				return observation.Receipt, nil
			}
			recovered, err := issuer.Recover(t.Context(), original)
			if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Flow != (PreAuthTransaction{}) {
				t.Fatal("recovery did not return the known outcome alone", err)
			}
			noPreAuthDelivery(t, recovered)
		})
	}
}
