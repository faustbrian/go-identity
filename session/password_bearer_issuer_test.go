package session_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestPasswordBearerIssuerRequiresExplicitTransportAndCommittedDelivery(t *testing.T) {
	for _, outcome := range []string{"fresh", "replay", "unknown", "expired", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			_, original, command, executor, clock, _ := passwordIssuerFixture(t, false)
			record, _ := original.Session()
			spec, _ := record.Bindings()
			spec.Lookup = session.TokenDigest{}
			key, _ := session.NewDigestKey(1, make([]byte, 32))
			config := session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32}
			issuer, err := session.NewPasswordBearerSessionIssuer(executor, config)
			if err != nil {
				t.Fatal("explicit bearer composition rejected", err)
			}
			feature, _ := command.PasswordSigninFeature()
			prepared, err := issuer.PreparePassword(feature.Binding, spec)
			if err != nil {
				t.Fatal(err)
			}
			prospective, _ := prepared.Session()
			prospectiveSpec, _ := prospective.Bindings()
			_, csrfErr := prospective.CSRFState().Bindings()
			if csrfErr == nil || prospectiveSpec.SessionID != spec.SessionID {
				t.Fatal("bearer preparation retained cookie synchronizer or changed session")
			}
			bound, err := issuer.BindPassword(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			executor.execute = func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				e := committedPasswordIssue(t, request)
				switch outcome {
				case "replay":
					e.Replayed = true
				case "unknown":
					e.Receipt.Outcome = identity.CommitOutcomeUnknown
					e.Receipt.AuditEventID, e.Receipt.Feature = "", &identity.FeatureReceipt{Operation: feature.Operation}
					e.Session = session.Session{}
				case "expired":
					clock.now = spec.Authentication.Proof.ExpiresAt
				case "cancelled":
					cancel()
				}
				return e, nil
			}
			result, err := issuer.Issue(ctx, bound)
			_, csrfErr = result.Session.CSRFState().Bindings()
			if !reflect.DeepEqual(result.Cookie, http.Cookie{}) || csrfErr == nil {
				t.Fatal("bearer result exposed cookie transport or synchronizer")
			}
			if _, err := bound.CSRFToken(); err == nil {
				t.Fatal("bearer result revealed a synchronizer")
			}
			if outcome == "fresh" {
				if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
					t.Fatal("fresh committed bearer withheld", err)
				}
				digest, err := result.Token.Digest(key, string(spec.TenantID))
				actual, _ := result.Session.Bindings()
				if err != nil || digest != actual.Lookup || actual.Authentication != spec.Authentication || actual.Remember != spec.Remember || !actual.IssuedAt.Equal(spec.IssuedAt) {
					t.Fatal("bearer delivery changed original custody/lifetime")
				}
			} else {
				requireNoIssuedToken(t, result)
				if outcome != "replay" && err == nil {
					t.Fatal("unsafe late/ambiguous delivery accepted")
				}
			}
		})
	}
}

func TestPasswordBearerIssuerRejectsCookieAndInvalidComposition(t *testing.T) {
	_, _, _, executor, clock, _ := passwordIssuerFixture(t, false)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	valid := session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32}
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	for _, change := range []func(*session.IssuerConfig){
		func(c *session.IssuerConfig) { c.Cookie = cookie },
		func(c *session.IssuerConfig) { c.Clock = nil },
		func(c *session.IssuerConfig) { c.LookupKey = session.DigestKey{} },
		func(c *session.IssuerConfig) { c.TokenSize = 31 },
		func(c *session.IssuerConfig) { c.MaximumDuration = 0 },
	} {
		c := valid
		change(&c)
		if issuer, err := session.NewPasswordBearerSessionIssuer(executor, c); issuer != nil || !errors.Is(err, session.ErrInvalidIssuer) {
			t.Fatal("invalid/mixed bearer composition admitted")
		}
	}
	if issuer, err := session.NewPasswordBearerSessionIssuer(nil, valid); issuer != nil || !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("missing owned executor admitted")
	}
	if issuer, err := session.NewPasswordSessionIssuer(executor, valid); issuer != nil || !errors.Is(err, session.ErrInvalidIssuer) {
		t.Fatal("existing cookie constructor silently became bearer-only")
	}
}
