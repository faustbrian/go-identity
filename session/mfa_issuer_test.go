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
	for _, profile := range []struct {
		mode     string
		password bool
	}{{"commit", false}, {"unknown", false}, {"replay", false}, {"substituted-factor", false}, {"expired", false}, {"commit", true}, {"unknown", true}, {"replay", true}, {"substituted-factor", true}, {"expired", true}} {
		mode := profile.mode
		t.Run(fmt.Sprintf("%s/password=%t", mode, profile.password), func(t *testing.T) {
			spec, primary, provenance := mfaMagicLinkSession(t)
			if profile.password {
				spec.Authentication = sessionSpec(t).Authentication
				spec.Authentication.Proof.Purpose = "identity.password.mfa-primary"
				spec.Authentication.Proof.ID = auth.ProofID(provenance.PrimaryCommandID)
				original, _ := primary.Bindings()
				spec.Authentication.Proof.IssuedAt = original.AuthenticatedAt
				spec.Authentication.Proof.ExpiresAt = original.ValidUntil
			}
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
					if profile.password {
						result.Session, e = session.NewSessionWithPasswordMFAAndCSRF(s, m, record.CSRFState())
					} else {
						result.Session, e = session.NewSessionWithMagicLinkMFAAndCSRF(s, primary, m, record.CSRFState())
					}
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
			config := session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}
			var issuer *session.SessionIssuer
			if profile.password {
				issuer, err = session.NewMFAPasswordSessionIssuerWithCSRF(executor, config, csrf)
			} else {
				issuer, err = session.NewMFAMagicLinkSessionIssuerWithCSRF(executor, config, csrf)
			}
			if err != nil {
				t.Fatal(err)
			}
			var prepared session.PreparedIssuance
			if profile.password {
				if _, e := issuer.PrepareMFAMagicLink(b, spec, primary, metadata); e == nil {
					t.Fatal("password issuer accepted magic-link profile")
				}
				prepared, err = issuer.PrepareMFAPassword(b, spec, metadata)
			} else {
				if _, e := issuer.PrepareMFAPassword(b, spec, metadata); e == nil {
					t.Fatal("magic-link issuer accepted password profile")
				}
				prepared, err = issuer.PrepareMFAMagicLink(b, spec, primary, metadata)
			}
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
