package session

import (
	"context"
	"errors"
	"testing"

	authorization "github.com/faustbrian/go-authorization/v3"
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

func TestOneTapStartPreAuthIssuerPreparesExactBoundFlow(t *testing.T) {
	legacy, _, executor, _ := preAuthIssuerFixture(t)
	config := legacy.config
	op := OneTapStartPreAuthOperation()
	config.Action, config.CallbackURL = op.OperationID, ""
	provider := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "fixture-client", Mode: PreAuthProviderCallback}
	selected, err := NewOneTapStartPreAuthIssuer(executor, config, provider)
	if err != nil {
		t.Fatal(err)
	}
	generic, err := NewProviderPreAuthIssuer(executor, config, provider)
	if err != nil {
		t.Fatal(err)
	}
	_, _, existing := preAuthFixture(t)
	intent := existing.Binding.Intent
	const flowID = "AwMDAwMDAwMDAwMDAwMDAw"
	binding := identity.CommandBinding{
		CommandID: "AgICAgICAgICAgICAgICAg", TenantID: intent.TenantID, AnonymousFlowID: flowID, RecordID: flowID,
		ActorID: config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID,
		SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion,
		CorrelationID: "onetap-start-bound-flow",
	}
	for _, tc := range []struct {
		name   string
		issuer *PreAuthIssuer
		alter  func(*identity.CommandBinding)
	}{
		{name: "ordinary issuer", issuer: legacy},
		{name: "generic provider issuer", issuer: generic},
		{name: "wrong actor", issuer: selected, alter: func(b *identity.CommandBinding) { b.ActorID = "other-service" }},
		{name: "wrong policy", issuer: selected, alter: func(b *identity.CommandBinding) { b.PolicyVersion++ }},
		{name: "wrong operation", issuer: selected, alter: func(b *identity.CommandBinding) { b.OperationID = PreAuthIssueOperation().OperationID }},
		{name: "invalid canonical flow", issuer: selected, alter: func(b *identity.CommandBinding) { b.AnonymousFlowID, b.RecordID = "noncanonical", "noncanonical" }},
		{name: "different record", issuer: selected, alter: func(b *identity.CommandBinding) { b.RecordID = string(b.CommandID) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := binding
			if tc.alter != nil {
				tc.alter(&bad)
			}
			prepared, err := tc.issuer.PrepareOneTapStart(bad, intent.Remember)
			if _, ok := prepared.Command(); ok || !errors.Is(err, ErrInvalidIssuance) {
				t.Fatal("invalid One Tap selection produced a deliverable preparation", err)
			}
		})
	}
	prepared, err := selected.PrepareOneTapStart(binding, intent.Remember)
	if err != nil {
		t.Fatal(err)
	}
	original, ok := prepared.Command()
	profile, profileErr := original.Record.ProviderBindings()
	flow := profile.Transaction.Binding
	if !ok || profileErr != nil || string(flow.ID) != flowID || flow.Intent.Nonce == ([32]byte{}) || flow.Intent.Remember != intent.Remember ||
		profile.Provider != provider || selected.binding(original) != binding {
		t.Fatal("preparation changed the coordinator's exact original One Tap binding", profileErr)
	}
	executor.execute = func(_ context.Context, command PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		if command != original {
			t.Fatal("execution changed the one prepared browser record")
		}
		ordinary, err := NewPreAuthTransaction(profile.Transaction)
		if err != nil {
			t.Fatal(err)
		}
		confirmed := preAuthCommitted(PreAuthIssueCommand{CommandID: original.CommandID, CorrelationID: original.CorrelationID, Record: ordinary})
		confirmed.Receipt.Binding = binding
		confirmed.Receipt.Feature = &identity.FeatureReceipt{Operation: op, AfterVersion: 1}
		return confirmed, nil
	}
	issued, err := selected.Issue(t.Context(), prepared)
	if err != nil || issued.Flow != original.Record || issued.Cookie.Name != "__Host-identity_flow" {
		t.Fatal("exact bound commitment did not release the original session-owned cookie", err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal("missing exact cookie token", err)
	}
	token, err := ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.ProviderPreAuthDigest(config.LookupKey, flow, provider)
	if err != nil || digest != profile.Transaction.Cookie {
		t.Fatal("cookie was not bound to the selected provider and original flow", err)
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
