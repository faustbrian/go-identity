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
	primitive "github.com/faustbrian/go-password"
)

type regenerationOwner struct {
	enableOwner
	result     mfa.RecoveryRegenerateResult
	calls      int
	last       mfa.RecoveryRegenerateRequest
	afterApply func()
}

func (o *regenerationOwner) RecoveryRegenerate(ctx context.Context, r mfa.RecoveryRegenerateRequest) (mfa.RecoveryRegenerateResult, error) {
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		panic("unbounded or invalid replacement custody")
	}
	o.calls++
	o.last = r
	if o.afterApply != nil {
		o.afterApply()
	}
	return o.result, o.err
}
func (*regenerationOwner) RecoverRecoveryRegenerate(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (mfa.RecoveryRegenerateResult, error) {
	return mfa.RecoveryRegenerateResult{}, identity.UnavailableError{}
}

func TestRegenerationHTTPRequiresNativeComposition(t *testing.T) {
	if h, err := NewRecoveryRegenerateHandler(RecoveryRegenerateConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured regeneration acquired authority")
	}
}

func TestRegenerationHTTPConservesOriginalProofAndRevealOnceCodes(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "unknown", "error", "expired", "foreign-session", "wrong-method", "foreign-fields", "missing-csrf"} {
		t.Run(mode, func(t *testing.T) {
			c, _, reader, clock, r := uriFixture(t)
			command, _ := identity.NewCommandID()
			proofID, _ := identity.NewCommandID()
			b, _ := reader.observation.Session.Bindings()
			p := auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(proofID), Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "totp", Assurance: auth.AssuranceMultiFactor, Purpose: "identity.mfa.recovery-regenerate", Audience: "regeneration", IssuedAt: clock.now, ExpiresAt: clock.now.Add(time.Minute)}, SessionID: b.SessionID, SessionVersion: b.Version, Action: "identity.mfa.recovery-regenerate"}
			secret, err := primitive.NewSecret([]byte("AAAAAAAAAAAAAAAAAAAAAQ"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(secret.Destroy)
			owner := &regenerationOwner{enableOwner: enableOwner{proof: p}, result: mfa.RecoveryRegenerateResult{CommandID: command, Outcome: identity.CommitOutcomeCommitted, RecoveryCodes: mfa.RevealOnceCodes{Codes: []primitive.Secret{secret}}}}
			switch mode {
			case "replay":
				owner.result.RecoveryCodes = mfa.RevealOnceCodes{}
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "error":
				owner.err = identity.UnavailableError{}
			case "expired":
				owner.afterApply = func() { clock.now = clock.now.Add(21 * time.Second) }
			case "foreign-session":
				owner.proof.SessionID = "another-session"
			case "wrong-method":
				owner.proof.Proof.Method = "recovery-code"
			case "missing-csrf":
				r.Header.Del("X-CSRF-Token")
			}
			r.URL.Path = "/v1/mfa/recovery-regenerate"
			r.RequestURI = r.URL.RequestURI()
			body := `{"commandID":"` + string(command) + `","proofID":"` + string(proofID) + `"}`
			if mode == "foreign-fields" {
				body = strings.TrimSuffix(body, "}") + `,"codeCount":1}`
			}
			r.Body = ioBody(body)
			r.ContentLength = int64(len(body))
			config := RecoveryRegenerateConfig{Network: c.Network, Sessions: c.Sessions, Proofs: owner, Service: owner, Rate: c.Rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration, MaximumAge: time.Minute, CodeCount: 1}
			h, err := NewRecoveryRegenerateHandler(config)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			h.ServeHTTP(w, r)
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("replacement issued session or cacheable output")
			}
			if mode == "fresh" {
				if w.Code != 200 || owner.calls != 1 || !strings.Contains(w.Body.String(), `"regenerated":true`) || !strings.Contains(w.Body.String(), `"recoveryCodes":["AAAAAAAAAAAAAAAAAAAAAQ"]`) {
					t.Fatal("fresh replacement delivery unavailable", w.Code)
				}
				if secret.Use(func([]byte) error { return nil }) == nil {
					t.Fatal("transport retained delivered secret ownership")
				}
				feature, err := NewFeature(FeatureConfig{RecoveryRegenerate: &config})
				if err != nil {
					t.Fatal("replacement selection required unrelated HTTP", err)
				}
				ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(ops) != 1 {
					t.Fatal("replacement route missing or duplicated", err)
				}
				if _, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Regeneration", Version: "1"}}, ops, nil); err != nil {
					t.Fatal("replacement wire/router invalid", err)
				}
			} else if w.Code == 200 || strings.Contains(w.Body.String(), `"recoveryCodes"`) || strings.Contains(w.Body.String(), `"regenerated":true`) {
				t.Fatal("denied/replayed/uncertain replacement disclosed codes", mode, w.Code)
			}
			if (mode == "foreign-session" || mode == "wrong-method" || mode == "foreign-fields" || mode == "missing-csrf") && owner.calls != 0 {
				t.Fatal("invalid input acquired replacement authority")
			}
		})
	}
}
