package mfahttp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// This port tests transport conservation, not signatures or SQL atomicity.
type factorUpdateOwner struct {
	*enableOwner
	last   mfa.FactorUpdateRequest
	result mfa.FactorUpdateResult
	calls  int
	after  func()
}

func (o *factorUpdateOwner) FactorUpdate(ctx context.Context, r mfa.FactorUpdateRequest) (mfa.FactorUpdateResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded management mutation")
	}
	o.calls++
	o.last = r
	if o.after != nil {
		o.after()
	}
	return o.result, nil
}
func (*factorUpdateOwner) RecoverFactorUpdate(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (mfa.FactorUpdateResult, error) {
	return mfa.FactorUpdateResult{}, identity.UnavailableError{}
}

func TestFactorUpdateHTTPConservesCustodyAndWithholdsInvalidMetadata(t *testing.T) {
	for _, mode := range []string{"fresh", "expired", "unknown", "bad-command", "foreign-proof", "foreign-result", "mixed-auth", "missing-key", "duplicate-key", "body-command", "wrong-action", "missing-csrf", "null-name", "overflow-version", "scope-query"} {
		t.Run(mode, func(t *testing.T) {
			base, proofs, _, clock, r := enableFixture(t)
			proofs.proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAAAg"
			proofs.proof.Proof.Method = "totp"
			proofs.proof.Proof.Assurance = auth.AssuranceMultiFactor
			proofs.proof.Proof.Purpose = "identity.mfa.factor-update"
			proofs.proof.Action = "identity.mfa.factor-update"
			proofs.proof.Proof.IssuedAt = clock.now
			proofs.proof.Proof.ExpiresAt = clock.now.Add(time.Minute)
			owner := &factorUpdateOwner{enableOwner: proofs, result: mfa.FactorUpdateResult{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", Outcome: identity.CommitOutcomeCommitted, Factor: mfa.FactorProjection{ID: "AAAAAAAAAAAAAAAAAAAABA", Method: "totp", State: mfa.FactorActive, Label: "<work>", CreatedAt: clock.now.Add(-time.Minute), Version: 4}}}
			c := FactorUpdateConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute}
			r.URL.Path = "/v1/mfa/factor-update"
			r.RequestURI = r.URL.RequestURI()
			body := `{"factorID":"AAAAAAAAAAAAAAAAAAAABA","proofID":"AAAAAAAAAAAAAAAAAAAAAg","action":"rename","name":"<work>","expectedVersion":3}`
			switch mode {
			case "expired":
				owner.after = func() { clock.now = clock.now.Add(21 * time.Second) }
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "bad-command":
				owner.result.Outcome = identity.CommitOutcomeUnknown
				owner.result.CommandID = "synthetic-sensitive-result-value"
			case "foreign-proof":
				proofs.proof.SessionID = "other-session"
			case "foreign-result":
				owner.result.Factor.ID = "AAAAAAAAAAAAAAAAAAAABQ"
			case "mixed-auth":
				r.Header.Set("Authorization", "Bearer forbidden")
			case "missing-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header["Idempotency-Key"] = []string{"one", "two"}
			case "body-command":
				body = strings.TrimSuffix(body, "}") + `,"commandID":"AAAAAAAAAAAAAAAAAAAAAQ"}`
			case "wrong-action":
				body = strings.Replace(body, `"rename"`, `"remove"`, 1)
			case "missing-csrf":
				r.Header.Del("X-CSRF-Token")
			case "null-name":
				body = strings.Replace(body, `"name":"<work>"`, `"name":null`, 1)
			case "overflow-version":
				body = strings.Replace(body, `"expectedVersion":3`, `"expectedVersion":18446744073709551616`, 1)
			case "scope-query":
				r.URL.RawQuery = "userID=foreign"
				r.RequestURI = r.URL.RequestURI()
			}
			r.Body = ioBody(body)
			r.ContentLength = int64(len(body))
			h, err := NewFactorUpdateHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			h.ServeHTTP(w, r)
			if strings.Contains(w.Body.String(), "synthetic-sensitive-result-value") {
				t.Fatal("malformed native command was exported as outcome metadata")
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("management crossed credential/cache boundary")
			}
			if mode == "fresh" {
				if w.Code != 200 || owner.calls != 1 || owner.last.Validate() != nil || owner.last.CommandID != "" || owner.last.CSRFToken == (session.CSRFToken{}) || owner.last.Session.Token() == "" || !strings.Contains(w.Body.String(), `"label":"<work>"`) {
					t.Fatal("native keyed rename custody or closed metadata lost", w.Code)
				}
				feature, err := NewFeature(FeatureConfig{FactorUpdate: &c})
				if err != nil {
					t.Fatal("selected management required unrelated MFA routes", err)
				}
				ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.mfa.factor-update" {
					t.Fatal("management selection exposed unrelated operations", err)
				}
				if _, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Factor management", Version: "1"}}, ops, nil); err != nil {
					t.Fatal("selected management wire invalid", err)
				}
				r.Body = ioBody(body)
				second := httptest.NewRecorder()
				ops[0].Handler.ServeHTTP(second, r)
				if second.Code != 200 || owner.calls != 2 {
					t.Fatal("selected descriptor did not execute native mutation", second.Code)
				}
			} else if w.Code == 200 || strings.Contains(w.Body.String(), `"factor"`) {
				t.Fatal("invalid authority/result disclosed metadata", mode, w.Code)
			}
			if mode == "mixed-auth" || mode == "missing-key" || mode == "duplicate-key" || mode == "body-command" || mode == "wrong-action" || mode == "missing-csrf" || mode == "foreign-proof" || mode == "null-name" || mode == "overflow-version" || mode == "scope-query" {
				if owner.calls != 0 {
					t.Fatal("invalid ingress reached mutation owner")
				}
			}
		})
	}
}

func TestFactorUpdateHTTPRequiresActualOwners(t *testing.T) {
	if h, err := NewFactorUpdateHandler(FactorUpdateConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured HTTP acquired management authority")
	}
}
