package session

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestProviderPreAuthIssuerDeliversOnlyOriginalCommittedCallback(t *testing.T) {
	legacy, _, executor, clock := preAuthIssuerFixture(t)
	config := legacy.config
	config.Action = "identity.oauth.onetap-start"
	config.CallbackURL = ""
	selected := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "fixture-client", Mode: PreAuthProviderCallback}
	issuer, err := NewProviderPreAuthIssuer(executor, config, selected)
	if err != nil {
		t.Fatal(err)
	}
	_, _, fixture := preAuthFixture(t)
	input := PreAuthPrepareInput{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: fixture.Binding.Intent.TenantID,
		CorrelationID: "provider-flow-original", Remember: fixture.Binding.Intent.Remember}
	prepared, err := issuer.Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	command, ok := prepared.Command()
	bound, err := command.Record.ProviderBindings()
	if err != nil || !ok || bound.Provider != selected || bound.Transaction.Binding.Intent.Remember != input.Remember ||
		bound.Transaction.Binding.IssuedAt != clock.now || bound.Transaction.Binding.ExpiresAt.Sub(clock.now) != 5*time.Minute {
		t.Fatal("preparation did not retain the exact original provider and flow", err)
	}
	if _, err := command.Record.Bindings(); err == nil {
		t.Fatal("selected flow can still leave through the legacy projection")
	}
	ordinaryFixture, err := NewPreAuthTransaction(bound.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	// Build a receipt independently of the issuer under test. The durable
	// command's authorized identity fields are unchanged by the new profile.
	receipt := preAuthCommitted(PreAuthIssueCommand{CommandID: command.CommandID, CorrelationID: command.CorrelationID, Record: ordinaryFixture})
	executor.execute = func(_ context.Context, actual PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		if actual != command {
			t.Fatal("execution did not get the unchanged original command")
		}
		clock.now = clock.now.Add(1500 * time.Millisecond)
		return receipt, nil
	}
	out, err := issuer.Issue(t.Context(), prepared)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed || out.Flow != command.Record ||
		out.Cookie.Name != "__Host-identity_flow" || out.Cookie.Value != "" || out.Cookie.MaxAge != 298 ||
		out.Cookie.Expires.After(bound.Transaction.Binding.ExpiresAt) {
		t.Fatal("new commit did not return only the exact original flow and bounded cookie", err)
	}
	wire, err := out.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	token, err := ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.ProviderPreAuthDigest(config.LookupKey, bound.Transaction.Binding, selected)
	if err != nil || digest != bound.Transaction.Cookie {
		t.Fatal("revealed cookie did not match original provider-bound digest", err)
	}
	if out, err := issuer.Issue(t.Context(), prepared); !errors.Is(err, ErrIssuanceAlreadyAttempted) {
		t.Fatal("same preparation reexecuted", err)
	} else {
		noPreAuthDelivery(t, out)
	}
	executor.recover = func(_ context.Context, query identity.RecoveryQuery) (identity.CommandResult, error) {
		if query.CommandID != command.CommandID {
			t.Fatal("recovery did not query the original command")
		}
		return receipt.Receipt, nil
	}
	clock.now = bound.Transaction.Binding.ExpiresAt.Add(time.Second)
	recovered, err := issuer.Recover(t.Context(), command)
	if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Flow != (PreAuthTransaction{}) {
		t.Fatal("recovery did not return the known outcome alone", err)
	}
	noPreAuthDelivery(t, recovered)
	selected.ProviderVersion++
	rotated, err := NewProviderPreAuthIssuer(executor, config, selected)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := rotated.Recover(t.Context(), command); !errors.Is(err, ErrInvalidIssuance) {
		t.Fatal("changed provider version recovered under different startup authority", err)
	} else {
		noPreAuthDelivery(t, out)
	}
}
