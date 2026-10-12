package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestMFAIssuerGatesOriginalCustodyAndExactCommittedSession(t *testing.T) {
	for _, mode := range []string{"commit", "unknown", "replay", "substituted-factor", "expired"} {
		t.Run(mode, func(t *testing.T) {
			spec, primary, provenance := mfaMagicLinkSession(t)
			spec.Lookup, spec.Version = session.TokenDigest{}, 1
			vector, _ := spec.Authority.Bindings()
			vector.Session.Version = 1
			spec.Authority, _ = session.NewAuthoritySnapshot(vector)
			metadata, err := session.NewMFAAuthentication(provenance)
			if err != nil {
				t.Fatal(err)
			}
			b := issueBinding(spec)
			b.CommandID, b.UserID, b.RecordID = provenance.CommandID, "", ""
			b.AnonymousFlowID = "original-browser"
			b.ActorID, b.ActorKind = "ingress", authorization.SubjectServiceAccount
			b.OperationID, b.SchemaID = "identity.mfa.totp-verify", "mfa-totp-verify"
			op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			clock := &mutableIssueClock{now: spec.IssuedAt}
			calls := 0
			var original identity.Command
			executor := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				calls++
				command, record, ok := r.MFACommand()
				if !ok || command != original {
					t.Fatal("MFA lost original opaque command")
				}
				if _, ok := r.Command(); ok {
					t.Fatal("MFA entered credential proof route")
				}
				if _, _, ok := r.MagicLinkCommand(); ok {
					t.Fatal("MFA bypassed factor through primary route")
				}
				result := session.IssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: op}}, Session: record}
				if mode == "unknown" {
					result.Receipt.Outcome, result.Session = identity.CommitOutcomeUnknown, session.Session{}
				}
				if mode == "replay" {
					result.Replayed = true
				}
				if mode == "substituted-factor" {
					changed := provenance
					changed.EnrollmentVersion++
					m, e := session.NewMFAAuthentication(changed)
					if e != nil {
						t.Fatal(e)
					}
					s, _ := record.Bindings()
					result.Session, e = session.NewSessionWithMagicLinkMFAAndCSRF(s, primary, m, record.CSRFState())
					if e != nil {
						t.Fatal(e)
					}
				}
				if mode == "expired" {
					clock.now = provenance.ValidUntil
				}
				return result, nil
			}, recover: func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
				t.Fatal("secret-bearing MFA entered recovery route")
				return session.IssueExecution{}, nil
			}}
			lookup, _ := session.NewDigestKey(1, make([]byte, 32))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			csrf, _ := session.NewCSRFKey(1, make([]byte, 32))
			issuer, err := session.NewMFAMagicLinkSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, csrf)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := issuer.PrepareMFAMagicLink(b, spec, primary, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := prepared.Request(); ok {
				t.Fatal("MFA custody advertised for restart recovery")
			}
			if _, err := issuer.Issue(context.Background(), prepared); err == nil || calls != 0 {
				t.Fatal("unbound factor issuance executed")
			}
			code, _ := auth.NewOneTimeCode("123456")
			original, err = identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			bound, err := issuer.BindMFA(prepared, original)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = issuer.BindMFA(prepared, original); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Fatal("alias rebound original factor custody", err)
			}
			result, err := issuer.Issue(context.Background(), bound)
			if calls != 1 {
				t.Fatal("native execution missing")
			}
			if mode == "commit" {
				if err != nil || result.Token == (session.Token{}) {
					t.Fatal("exact native commit could not deliver", err)
				}
				if _, err := bound.CSRFToken(); err != nil {
					t.Fatal(err)
				}
				if _, err := result.Token.Reveal(); err != nil {
					t.Fatal(err)
				}
				if _, err := result.Token.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
					t.Fatal("MFA bearer revealed twice")
				}
			} else if result.Token != (session.Token{}) || result.Cookie.Name != "" {
				t.Fatal("non-deliverable factor outcome revealed token", fmt.Sprint(mode))
			}
			if mode == "substituted-factor" && (err == nil || result.CommitOutcome != identity.CommitOutcomeUnknown) {
				t.Fatal("changed factor receipt accepted", err)
			}
		})
	}
}
