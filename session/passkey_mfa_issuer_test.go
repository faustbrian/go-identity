package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// The executor is the native commit seam only. These tests cannot authenticate
// a passkey or TOTP; the composed PostgreSQL journey must prove that behavior.
func TestPasskeyMFAIssuerRetainsOriginalCustodyAndCommitGate(t *testing.T) {
	for _, mode := range []string{"commit", "unknown", "replay", "substituted-factor", "expired", "failure"} {
		t.Run(mode, func(t *testing.T) {
			spec, primary, provenance := mfaMagicLinkSession(t)
			original, _ := primary.Bindings()
			spec.Authentication = sessionSpec(t).Authentication
			spec.Authentication.CredentialID = "original-passkey"
			spec.Authentication.Proof.ID = auth.ProofID(provenance.PrimaryCommandID)
			spec.Authentication.Proof.Method = "passkey"
			spec.Authentication.Proof.Assurance = auth.AssurancePhishingResistant
			spec.Authentication.Proof.Purpose = session.PasskeyMFAPrimaryPurpose
			spec.Authentication.Proof.IssuedAt, spec.Authentication.Proof.ExpiresAt = original.AuthenticatedAt, original.ValidUntil
			spec.Lookup, spec.Version = session.TokenDigest{}, 1
			vector, _ := spec.Authority.Bindings()
			vector.Session.Version = 1
			vector.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey", Version: 3}}
			spec.Authority, _ = session.NewAuthoritySnapshot(vector)
			metadata, err := session.NewMFAAuthentication(provenance)
			if err != nil {
				t.Fatal(err)
			}
			b := issueBinding(spec)
			b.CommandID, b.UserID, b.RecordID, b.AnonymousFlowID = provenance.CommandID, "", "", "original-browser"
			b.ActorID, b.ActorKind = "ingress", authorization.SubjectServiceAccount
			b.OperationID, b.SchemaID = "identity.mfa.totp-verify", "mfa-totp-verify"
			op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			clock := &mutableIssueClock{now: spec.IssuedAt}
			var command identity.Command
			calls := 0
			executor := &issueExecutor{execute: func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				calls++
				actual, record, ok := request.MFACommand()
				if !ok || actual != command {
					t.Fatal("original completion custody lost")
				}
				if _, _, ok := request.PasskeyCommand(); ok {
					t.Fatal("MFA bypassed factor through ordinary passkey issuer")
				}
				if _, ok := request.AuthenticatedProof(); ok {
					t.Fatal("prospective metadata became an opaque authentication proof")
				}
				got, _ := record.Bindings()
				if got.Authentication != spec.Authentication || record.MFAAuthentication() != metadata {
					t.Fatal("original primary or completed factor changed")
				}
				result := session.IssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: op}}, Session: record}
				switch mode {
				case "unknown":
					result.Receipt.Outcome, result.Session = identity.CommitOutcomeUnknown, session.Session{}
				case "replay":
					result.Replayed = true
				case "substituted-factor":
					changed, _ := metadata.Bindings()
					changed.FactorID = "BwcHBwcHBwcHBwcHBwcHBw"
					factor, _ := session.NewMFAAuthentication(changed)
					result.Session, err = session.NewSessionWithPasskeyMFAAndCSRF(got, factor, record.CSRFState())
					if err != nil {
						t.Fatal(err)
					}
				case "expired":
					clock.now = provenance.ValidUntil
				case "failure":
					return session.IssueExecution{}, errors.New("synthetic native failure")
				}
				return result, nil
			}}
			lookup, _ := session.NewDigestKey(1, make([]byte, 32))
			csrf, _ := session.NewCSRFKey(2, make([]byte, 32))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			config := session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}
			issuer, err := session.NewMFAPasskeySessionIssuerWithCSRF(executor, config, csrf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.PrepareMFAPassword(b, spec, metadata); err == nil {
				t.Fatal("passkey issuer admitted password origin")
			}
			if _, err := issuer.PrepareMFAMagicLink(b, spec, primary, metadata); err == nil {
				t.Fatal("passkey issuer admitted magic-link origin")
			}
			passwordIssuer, err := session.NewMFAPasswordSessionIssuer(executor, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := passwordIssuer.PrepareMFAPasskey(b, spec, metadata); err == nil {
				t.Fatal("password issuer admitted passkey origin")
			}
			prepared, err := issuer.PrepareMFAPasskey(b, spec, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Issue(t.Context(), prepared); err == nil || calls != 0 {
				t.Fatal("unbound completion executed")
			}
			if _, err := prepared.CSRFToken(); err == nil {
				t.Fatal("uncommitted synchronizer revealed")
			}
			code, _ := auth.NewOneTimeCode("123456")
			command, err = identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			bound, err := issuer.BindMFA(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.BindMFA(prepared, command); !errors.Is(err, session.ErrIssuanceAlreadyBound) {
				t.Fatal("copied completion bound twice", err)
			}
			result, err := issuer.Issue(t.Context(), bound)
			if calls != 1 {
				t.Fatal("completion did not execute once")
			}
			if mode == "commit" {
				if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Replayed {
					t.Fatal("exact acknowledged completion rejected", err)
				}
				if token, err := result.Token.Reveal(); err != nil || token == "" {
					t.Fatal("original committed bearer withheld", err)
				}
				if _, err := result.Token.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
					t.Fatal("original bearer revealed twice")
				}
				if _, err := bound.CSRFToken(); err != nil {
					t.Fatal("original synchronizer withheld", err)
				}
			} else {
				if result.Token != (session.Token{}) || result.Cookie.Name != "" {
					t.Fatal("non-deliverable completion disclosed bearer")
				}
				if _, err := bound.CSRFToken(); err == nil {
					t.Fatal("non-deliverable completion disclosed synchronizer")
				}
				if mode == "substituted-factor" && (err == nil || result.CommitOutcome != identity.CommitOutcomeUnknown) {
					t.Fatal("substituted completed factor accepted", err)
				}
			}
		})
	}
}
