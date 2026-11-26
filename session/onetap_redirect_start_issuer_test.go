package session

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestOneTapRedirectStartIssuerRequiresExplicitSelection(t *testing.T) {
	legacy, _, executor, _ := preAuthIssuerFixture(t)
	config := legacy.config
	config.Action = OneTapStartPreAuthOperation().OperationID
	config.CallbackURL = config.Origin + "/v1/oauth/onetap-redirect"
	config.Cookie = CookiePolicy{}
	provider := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "fixture-client", Mode: PreAuthProviderRedirect}
	for _, tc := range []struct {
		name  string
		alter func(*PreAuthIssuerConfig, *PreAuthProviderBinding)
	}{
		{"ordinary cookie", func(c *PreAuthIssuerConfig, _ *PreAuthProviderBinding) { c.Cookie = legacy.config.Cookie }},
		{"popup mode", func(_ *PreAuthIssuerConfig, p *PreAuthProviderBinding) { p.Mode = PreAuthProviderCallback }},
		{"different provider", func(_ *PreAuthIssuerConfig, p *PreAuthProviderBinding) { p.ProviderID = "other" }},
		{"root cookie path", func(c *PreAuthIssuerConfig, _ *PreAuthProviderBinding) { c.CallbackURL = c.Origin + "/" }},
		{"foreign endpoint", func(c *PreAuthIssuerConfig, _ *PreAuthProviderBinding) {
			c.CallbackURL = "https://foreign.example/redirect"
		}},
		{"endpoint alias", func(c *PreAuthIssuerConfig, _ *PreAuthProviderBinding) { c.CallbackURL += "?x=1" }},
		{"longer expiry", func(c *PreAuthIssuerConfig, _ *PreAuthProviderBinding) { c.FlowTTL += time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p := config, provider
			tc.alter(&c, &p)
			issuer, err := NewOneTapRedirectStartPreAuthIssuer(executor, c, p)
			if issuer != nil || !errors.Is(err, ErrInvalidIssuer) {
				t.Fatal("invalid frontchannel selection constructed an issuer", err)
			}
		})
	}
	legacyConfig := config
	legacyConfig.Cookie = legacy.config.Cookie
	if issuer, err := NewOneTapStartPreAuthIssuer(executor, legacyConfig, provider); issuer != nil || !errors.Is(err, ErrInvalidIssuer) {
		t.Fatal("popup issuer implicitly selected a redirect", err)
	}
	issuer, err := NewOneTapRedirectStartPreAuthIssuer(executor, config, provider)
	if err != nil {
		t.Fatal(err)
	}
	_, _, fixture := preAuthFixture(t)
	prepared, err := issuer.Prepare(PreAuthPrepareInput{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: fixture.Binding.Intent.TenantID, CorrelationID: "redirect-generic", Remember: fixture.Binding.Intent.Remember})
	if _, ok := prepared.Command(); ok || !errors.Is(err, ErrInvalidIssuance) {
		t.Fatal("generic preparation substituted for exact keyed start", err)
	}
}

func TestOneTapRedirectStartIssuerCommitsPathBoundCookie(t *testing.T) {
	for _, outcome := range []string{"new commit", "replay", "late commit"} {
		t.Run(outcome, func(t *testing.T) {
			legacy, _, executor, clock := preAuthIssuerFixture(t)
			config := legacy.config
			op := OneTapStartPreAuthOperation()
			const endpoint = "/v1/oauth/onetap-redirect"
			config.Action, config.CallbackURL, config.Cookie = op.OperationID, config.Origin+endpoint, CookiePolicy{}
			provider := PreAuthProviderBinding{ProviderID: "google", ProviderVersion: 7, ClientID: "fixture-client", Mode: PreAuthProviderRedirect}
			issuer, err := NewOneTapRedirectStartPreAuthIssuer(executor, config, provider)
			if err != nil {
				t.Fatal(err)
			}
			_, _, fixture := preAuthFixture(t)
			const flowID = "AwMDAwMDAwMDAwMDAwMDAw"
			binding := identity.CommandBinding{
				CommandID: "AgICAgICAgICAgICAgICAg", TenantID: fixture.Binding.Intent.TenantID, AnonymousFlowID: flowID, RecordID: flowID,
				ActorID: config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID,
				SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion,
				CorrelationID: "onetap-redirect-original",
			}
			prepared, err := issuer.PrepareOneTapStart(binding, fixture.Binding.Intent.Remember)
			if err != nil {
				t.Fatal(err)
			}
			original, ok := prepared.Command()
			selected, err := original.Record.ProviderBindings()
			flow := selected.Transaction.Binding
			if !ok || err != nil || string(flow.ID) != flowID || selected.Provider != provider || flow.Intent.CallbackURL != config.CallbackURL ||
				flow.Intent.Remember != fixture.Binding.Intent.Remember || flow.ExpiresAt.Sub(flow.IssuedAt) != 5*time.Minute {
				t.Fatal("preparation changed the original redirect, mode, or lifetime", err)
			}
			executor.execute = func(_ context.Context, command PreAuthIssueCommand) (PreAuthIssueExecution, error) {
				if command != original {
					t.Fatal("issuance replaced the prepared redirect record")
				}
				ordinary, err := NewPreAuthTransaction(selected.Transaction)
				if err != nil {
					t.Fatal(err)
				}
				committed := preAuthCommitted(PreAuthIssueCommand{CommandID: original.CommandID, CorrelationID: original.CorrelationID, Record: ordinary})
				committed.Receipt.Binding = binding
				committed.Receipt.Feature = &identity.FeatureReceipt{Operation: op, AfterVersion: 1}
				committed.Replayed = outcome == "replay"
				if outcome == "late commit" {
					clock.now = flow.ExpiresAt
				}
				return committed, nil
			}
			issued, err := issuer.Issue(t.Context(), prepared)
			if issued.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("exact receipt did not establish the commit", err)
			}
			if outcome == "replay" {
				if err != nil || !issued.Replayed {
					t.Fatal("replay did not return the original outcome", err)
				}
				noPreAuthDelivery(t, issued)
				return
			}
			if outcome == "late commit" {
				if !errors.Is(err, ErrPreAuthDenied) {
					t.Fatal("delivery did not retain the original expiry", err)
				}
				noPreAuthDelivery(t, issued)
				return
			}
			cookie := issued.Cookie
			if err != nil || issued.Flow != original.Record || cookie.Name != "__Secure-identity_frontchannel" || cookie.Path != endpoint ||
				!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Domain != "" ||
				cookie.Value != "" || cookie.MaxAge != 300 || !cookie.Expires.Equal(flow.ExpiresAt) {
				t.Fatal("new redirect commit did not release safe cross-site POST cookie attributes", err)
			}
			cookiePolicy, err := NewOneTapRedirectFrontchannelCookiePolicy(config.Origin, config.CallbackURL)
			if err != nil {
				t.Fatal(err)
			}
			deletion, err := cookiePolicy.DeletionAttributes()
			if err != nil || deletion.Name != cookie.Name || deletion.Path != cookie.Path || deletion.Domain != cookie.Domain ||
				deletion.SameSite != cookie.SameSite || deletion.Secure != cookie.Secure || deletion.HttpOnly != cookie.HttpOnly || deletion.MaxAge >= 0 {
				t.Fatal("callback cannot clear the original path-bound cookie", err)
			}
			digest, err := issued.Token.ProviderPreAuthDigest(config.LookupKey, flow, provider)
			if err != nil || digest != selected.Transaction.Cookie {
				t.Fatal("released token does not prove possession of this exact original redirect", err)
			}
		})
	}
}
