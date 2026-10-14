package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestMagicLinkIssuerUsesOriginalCustodyAndCommitGatedDelivery(t *testing.T) {
	for _, c := range []struct {
		outcome           identity.CommitOutcome
		replayed, expired bool
	}{{identity.CommitOutcomeCommitted, false, false}, {identity.CommitOutcomeUnknown, false, false}, {identity.CommitOutcomeNotCommitted, false, false}, {identity.CommitOutcomeCommitted, true, false}, {identity.CommitOutcomeCommitted, false, true}} {
		outcome := c.outcome
		t.Run(fmt.Sprint(outcome, "/", c.replayed, "/", c.expired), func(t *testing.T) {
			spec, meta := magicLinkSession(t)
			spec.Lookup = session.TokenDigest{}
			spec.Version = 1
			vector, _ := spec.Authority.Bindings()
			vector.Session.Version = 1
			spec.Authority, _ = session.NewAuthoritySnapshot(vector)
			b := issueBinding(spec)
			b.CommandID = meta.CommandID
			b.UserID = ""
			b.AnonymousFlowID = "original-browser"
			b.RecordID = ""
			b.OperationID = "identity.magic-link.consume"
			b.SchemaID = "magic-link-consume"
			b.ActorID = "ingress"
			b.ActorKind = authorization.SubjectServiceAccount
			op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			clock := &mutableIssueClock{now: spec.IssuedAt}
			calls := 0
			var retained session.IssueRequest
			executor := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				calls++
				retained = r
				command, record, ok := r.MagicLinkCommand()
				if !ok {
					t.Fatal("native magic-link command missing")
				}
				f, _ := command.Feature()
				if _, ok := command.PreAuthCookie(); !ok {
					t.Fatal("original browser custody missing")
				}
				if _, ok := r.Command(); ok {
					t.Fatal("magic-link entered credential route")
				}
				if r.Validate(nil, clock.Now()) != session.ErrInvalidIssueRequest {
					t.Fatal("magic-link manufactured final credential proof")
				}
				result := session.IssueExecution{Receipt: identity.CommandResult{Binding: f.Binding, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: op}}}
				if outcome == identity.CommitOutcomeCommitted {
					result.Receipt.AuditEventID = "audit"
					result.Session = record
				}
				result.Replayed = c.replayed
				if c.expired {
					clock.now = meta.ValidUntil
				}
				return result, nil
			}, recover: func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
				t.Error("magic-link consuming request entered proof-route recovery")
				return session.IssueExecution{}, nil
			}}
			lookup, _ := session.NewDigestKey(1, make([]byte, 32))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			csrf, _ := session.NewCSRFKey(1, make([]byte, 32))
			issuer, err := session.NewMagicLinkSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, csrf)
			if err != nil {
				t.Fatal(err)
			}
			metadata, _ := session.NewMagicLinkAuthentication(meta)
			prepared, err := issuer.PrepareMagicLink(b, spec, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := prepared.Request(); ok {
				t.Fatal("secret-bearing request advertised as recovery-safe")
			}
			if _, err := prepared.CSRFToken(); err == nil {
				t.Fatal("csrf disclosed before commitment")
			}
			if _, err := issuer.Issue(context.Background(), prepared); err == nil || calls != 0 {
				t.Fatal("unbound issuance executed")
			}
			command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			bound, err := issuer.BindMagicLink(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = issuer.BindMagicLink(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Fatal("alias rebound original custody", err)
			}
			result, err := issuer.Issue(context.Background(), bound)
			if result.CommitOutcome != outcome || calls != 1 {
				t.Fatal("native outcome changed", err)
			}
			if _, e := issuer.Recover(context.Background(), retained); !errors.Is(e, session.ErrInvalidIssuance) {
				t.Fatal("ephemeral consuming request accepted by legacy recovery", e)
			}
			if outcome == identity.CommitOutcomeCommitted && !c.replayed && !c.expired {
				if err != nil || result.Token == (session.Token{}) || result.Cookie.Value != "" {
					t.Fatal("new commit did not gate delivery", err)
				}
				if _, err := bound.CSRFToken(); err != nil {
					t.Fatal(err)
				}
				if _, err := result.Token.Reveal(); err != nil {
					t.Fatal(err)
				}
				if _, err := result.Token.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
					t.Fatal("bearer revealed twice")
				}
			} else {
				if result.Token != (session.Token{}) || !reflect.DeepEqual(result.Cookie, http.Cookie{}) {
					t.Fatal("non-deliverable outcome exposed bearer")
				}
				if _, e := bound.CSRFToken(); e == nil {
					t.Fatal("non-deliverable outcome exposed synchronizer")
				}
				if c.expired && !errors.Is(err, session.ErrInvalidIssuance) {
					t.Fatal("original grant expiry was renewed after executor wait", err)
				}
			}
			if _, err := issuer.Issue(context.Background(), bound); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) && !(c.expired && errors.Is(err, session.ErrInvalidIssuance)) {
				t.Fatal("repeated attempt regenerated custody", err)
			}
		})
	}
}
