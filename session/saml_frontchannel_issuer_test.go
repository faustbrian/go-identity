package session

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestSAMLFrontchannelIssuerDeliversOnlyOriginalCommittedACSFlow(t *testing.T) {
	ordinary, _, executor, clock := preAuthIssuerFixture(t)
	config := ordinary.config
	config.Action = "identity.sso.saml-acs"
	config.CallbackURL = config.Origin + "/saml2/_configured-provider/acs"
	if _, err := NewPreAuthIssuer(executor, config); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatal("SAML action was eligible for the ordinary Lax flow cookie", err)
	}
	config.Cookie = CookiePolicy{}
	issuer, err := NewSAMLFrontchannelIssuer(executor, config)
	if err != nil {
		t.Fatal("select dedicated SAML frontchannel issuer", err)
	}
	_, key, fixture := preAuthFixture(t)
	prepare := func(t *testing.T) PreparedPreAuthIssuance {
		t.Helper()
		prepared, err := issuer.Prepare(PreAuthPrepareInput{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: fixture.Binding.Intent.TenantID, CorrelationID: "saml-original", Remember: fixture.Binding.Intent.Remember})
		if err != nil {
			t.Fatal("prepare original ACS flow", err)
		}
		return prepared
	}
	prepared := prepare(t)
	command, _ := prepared.Command()
	stored, err := command.Record.Bindings()
	if err != nil || stored.Binding.Intent.Action != "identity.sso.saml-acs" || stored.Binding.Intent.CallbackURL != config.CallbackURL || stored.Binding.ExpiresAt.Sub(stored.Binding.IssuedAt) != 5*time.Minute {
		t.Fatal("native owner did not receive exact original ACS intent", err)
	}
	executor.execute = func(_ context.Context, actual PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		if actual != command {
			t.Fatal("execution changed original correlation")
		}
		clock.now = clock.now.Add(1500 * time.Millisecond)
		return preAuthCommitted(actual), nil
	}
	result, err := issuer.Issue(context.Background(), prepared)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
		t.Fatal("new committed ACS flow was not delivered", err)
	}
	cookie := result.Cookie
	if cookie.Name != "__Secure-identity_frontchannel" || cookie.Path != "/saml2/_configured-provider/acs" || cookie.Domain != "" || cookie.Value != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.MaxAge != 298 || cookie.Expires.After(stored.Binding.ExpiresAt) {
		t.Fatal("committed flow did not retain exact cross-site cookie policy")
	}
	wire, err := result.Token.Reveal()
	if err != nil {
		t.Fatal("committed ACS flow withheld original bearer", err)
	}
	token, err := ParseToken(wire)
	if err != nil {
		t.Fatal("original correlation bearer was invalid", err)
	}
	digest, err := token.PreAuthDigest(key, stored.Binding)
	if err != nil || digest != stored.Cookie {
		t.Fatal("browser bearer did not match the original stored flow", err)
	}
	changed := stored.Binding
	changed.Intent.CallbackURL = config.Origin + "/saml2/other-provider/acs"
	if digest, err := token.PreAuthDigest(key, changed); err != nil || digest == stored.Cookie {
		t.Fatal("other ACS did not change the bound cookie commitment", err)
	}
	executor.execute = func(_ context.Context, actual PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		historical := preAuthCommitted(actual)
		historical.Replayed = true
		return historical, nil
	}
	historical, err := issuer.Issue(context.Background(), prepare(t))
	if err != nil || !historical.Replayed {
		t.Fatal("retained commitment was not recognized as history", err)
	}
	noPreAuthDelivery(t, historical)
}

func TestSAMLFrontchannelIssuerRejectsWrongProfileAndWithholdsOnUnknown(t *testing.T) {
	ordinary, _, executor, _ := preAuthIssuerFixture(t)
	config := ordinary.config
	config.Action, config.CallbackURL, config.Cookie = "identity.sso.saml-acs", config.Origin+"/saml2/provider/acs", CookiePolicy{}
	for name, change := range map[string]func(*PreAuthIssuerConfig){
		"wrong action":   func(c *PreAuthIssuerConfig) { c.Action = "identity.sso.oidc-callback" },
		"foreign origin": func(c *PreAuthIssuerConfig) { c.CallbackURL = "https://other.example.test/saml2/provider/acs" },
		"HTTP loopback": func(c *PreAuthIssuerConfig) {
			c.Origin = "http://localhost:8080"
			c.CallbackURL = c.Origin + "/saml2/provider/acs"
		},
		"ordinary flow policy": func(c *PreAuthIssuerConfig) { c.Cookie = ordinary.config.Cookie },
		"unsolicited route":    func(c *PreAuthIssuerConfig) { c.CallbackURL = c.Origin + "/saml2/provider/idp-init" },
		"renewed lifetime":     func(c *PreAuthIssuerConfig) { c.FlowTTL = 6 * time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			change(&candidate)
			if _, err := NewSAMLFrontchannelIssuer(executor, candidate); !errors.Is(err, ErrInvalidIssuer) {
				t.Fatal("admitted cross-protocol or noncanonical frontchannel composition", err)
			}
		})
	}
	issuer, err := NewSAMLFrontchannelIssuer(executor, config)
	if err != nil {
		t.Fatal(err)
	}
	_, _, fixture := preAuthFixture(t)
	prepared, err := issuer.Prepare(PreAuthPrepareInput{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: fixture.Binding.Intent.TenantID, CorrelationID: "saml-unknown", Remember: fixture.Binding.Intent.Remember})
	if err != nil {
		t.Fatal(err)
	}
	executor.execute = func(_ context.Context, actual PreAuthIssueCommand) (PreAuthIssueExecution, error) {
		return PreAuthIssueExecution{}, identity.UnknownCommitError{CommandID: actual.CommandID}
	}
	result, err := issuer.Issue(context.Background(), prepared)
	original, _ := prepared.Command()
	if !errors.Is(err, identity.UnknownCommitError{CommandID: original.CommandID}) || result.CommitOutcome != identity.CommitOutcomeUnknown {
		t.Fatal("unknown commit did not remain unknown", err)
	}
	noPreAuthDelivery(t, result)
}

func TestSAMLFrontchannelIssuerNativeFlowRejectsHTTPDevelopmentOrigin(t *testing.T) {
	_, _, flow := preAuthFixture(t)
	flow.Binding.Intent.Origin = "http://127.0.0.1:8080"
	flow.Binding.Intent.CallbackURL = flow.Binding.Intent.Origin + "/saml2/provider/acs"
	flow.Binding.ExpiresAt = flow.Binding.IssuedAt.Add(5 * time.Minute)
	if _, err := NewPreAuthTransaction(flow); err != nil {
		t.Fatal("ordinary pre-auth no longer accepts explicit HTTP development origins", err)
	}
	flow.Binding.Intent.Action = "identity.sso.saml-acs"
	if _, err := NewPreAuthTransaction(flow); !errors.Is(err, ErrInvalidPreAuthTransaction) {
		t.Fatal("SAML native record accepted HTTP callback custody", err)
	}
}
