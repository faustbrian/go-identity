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

func TestVerificationIssuerUsesSeparateCommittedEmailGrantProfile(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown} {
		for _, replay := range []bool{false, true} {
			spec, provenance := magicLinkSession(t)
			spec.Lookup, spec.Version = session.TokenDigest{}, 1
			vector, _ := spec.Authority.Bindings()
			vector.Session.Version = 1
			spec.Authority, _ = session.NewAuthoritySnapshot(vector)
			binding := issueBinding(spec)
			binding.CommandID = provenance.CommandID
			binding.OperationID, binding.SchemaID = "identity.email.verification-signin", "email-verification-signin"
			parent, _ := identity.NewCommandID()
			binding.RecordID = string(parent)
			binding.ActorID, binding.ActorKind = "confirmation-ingress", authorization.SubjectServiceAccount
			operation := identity.FeatureOperation{Owner: "identity/email", OperationID: binding.OperationID, SchemaID: binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			clock := &mutableIssueClock{now: spec.IssuedAt}
			calls := 0
			executor := &issueExecutor{execute: func(_ context.Context, request session.IssueRequest) (session.IssueExecution, error) {
				calls++
				command, record, ok := request.EmailVerificationCommand()
				if !ok {
					t.Fatal("original verification signin custody missing")
				}
				feature, _ := command.Feature()
				if feature.Binding != binding || feature.Operation != operation {
					t.Fatal("verification command retargeted")
				}
				if _, _, ok := request.MagicLinkCommand(); ok {
					t.Fatal("verification became ordinary magic-link consumption")
				}
				if _, ok := request.AuthenticatedProof(); ok {
					t.Fatal("verification fabricated a credential proof")
				}
				result := session.IssueExecution{Receipt: identity.CommandResult{Binding: binding, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: operation}}, Replayed: replay}
				if outcome == identity.CommitOutcomeCommitted {
					result.Session, result.Receipt.AuditEventID = record, "protected-audit"
					result.Receipt.Feature.AfterVersion = 1
				}
				return result, nil
			}}
			lookup, _ := session.NewDigestKey(1, make([]byte, 32))
			csrf, _ := session.NewCSRFKey(1, make([]byte, 32))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			configuration := session.IssuerConfig{Clock: clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}
			issuer, err := session.NewEmailVerificationSessionIssuerWithCSRF(executor, configuration, csrf)
			if err != nil {
				t.Fatal(err)
			}
			metadata, _ := session.NewMagicLinkAuthentication(provenance)
			prepared, err := issuer.PrepareEmailVerification(binding, spec, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := prepared.Request(); ok {
				t.Fatal("browser-bearing request advertised as safe recovery")
			}
			command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: operation}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.BindMagicLink(prepared, command); err == nil {
				t.Fatal("verification entered ordinary magic-link binder")
			}
			bound, err := issuer.BindEmailVerification(prepared, command)
			if err != nil {
				t.Fatal(err)
			}
			result, err := issuer.Issue(t.Context(), bound)
			if calls != 1 || result.CommitOutcome != outcome {
				t.Fatal("native outcome was not conserved", err)
			}
			deliver := outcome == identity.CommitOutcomeCommitted && !replay
			if (result.Token != (session.Token{})) != deliver || (result.Cookie.Name != "") != deliver {
				t.Fatal("credential delivery did not require one fresh commit", err)
			}
			if _, csrfErr := bound.CSRFToken(); (csrfErr == nil) != deliver {
				t.Fatal("synchronizer delivery did not follow session delivery")
			}
			if _, retryErr := issuer.Issue(t.Context(), bound); !errors.Is(retryErr, session.ErrIssuanceAlreadyAttempted) {
				t.Fatal("duplicate invocation repeated issuance", retryErr)
			}
			ordinary, _ := session.NewMagicLinkSessionIssuer(executor, configuration)
			if _, err := ordinary.PrepareEmailVerification(binding, spec, metadata); err == nil {
				t.Fatal("ordinary link issuer implicitly enabled verification signin")
			}
		}
	}
}
