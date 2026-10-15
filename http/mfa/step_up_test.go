package mfahttp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
)

type stepUpOwner struct{ confirmationOwner }

func (o *stepUpOwner) ActiveStepUpRateSource(ctx context.Context, r mfa.TotpVerifyRequest) (time.Duration, time.Time, error) {
	if r.StepUp == nil || r.Enrollment != nil {
		panic("step-up acquired another variant's custody")
	}
	return o.EnrollmentConfirmationRateSource(ctx, r)
}

func TestActiveStepUpHTTPRequiresNativeComposition(t *testing.T) {
	if h, err := NewActiveStepUpHandler(ActiveStepUpConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured step-up acquired authority")
	}
}

func TestActiveStepUpHTTPConservesProofAndAuthenticatedVariant(t *testing.T) {
	for _, mode := range []string{"fresh", "management", "unselected-purpose", "null-purpose", "replay", "unknown", "expired", "foreign-proof", "missing-variant", "enrollment-variant", "duplicate-variant", "foreign-fields"} {
		t.Run(mode, func(t *testing.T) {
			c, _, reader, clock, r := uriFixture(t)
			factor, _ := identity.NewCommandID()
			command, _ := identity.NewCommandID()
			b, _ := reader.observation.Session.Bindings()
			proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(command), Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "totp", Assurance: auth.AssuranceMultiFactor, Purpose: "identity.mfa.recovery-regenerate", Audience: "regeneration", IssuedAt: clock.now, ExpiresAt: clock.now.Add(time.Minute)}, SessionID: b.SessionID, SessionVersion: b.Version, Action: "identity.mfa.recovery-regenerate"}
			owner := &stepUpOwner{confirmationOwner: confirmationOwner{until: clock.now.Add(10 * time.Second), result: mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted}}}
			switch mode {
			case "management":
				proof.Proof.Purpose = "identity.mfa.factor-update"
				proof.Action = "identity.mfa.factor-update"
			case "replay":
				proof = auth.ReauthenticationProof{}
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "expired":
				owner.after = func() { clock.now = owner.until }
			case "foreign-proof":
				proof.SessionID = "another-session"
			}
			if proof.Proof.ID != "" {
				var err error
				owner.result.StepUpProof, err = mfa.NewContinuationProof(proof)
				if err != nil {
					t.Fatal(err)
				}
			}
			rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: &strictRate{}, Namespace: "step-up-test", Key: [32]byte{3}, Now: clock.Now, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { rate.Close() })
			config := ActiveStepUpConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}
			if mode == "management" {
				config.Purposes = []auth.Purpose{"identity.mfa.recovery-regenerate", "identity.mfa.factor-update"}
			}
			r.URL.Path = "/v1/mfa/totp-verify"
			r.RequestURI = r.URL.RequestURI()
			r.Header.Set("X-MFA-Variant", "step-up")
			body := `{"commandID":"` + string(command) + `","factorID":"` + string(factor) + `","code":"123456"}`
			switch mode {
			case "management", "unselected-purpose":
				body = strings.TrimSuffix(body, "}") + `,"purpose":"identity.mfa.factor-update"}`
			case "null-purpose":
				body = strings.TrimSuffix(body, "}") + `,"purpose":null}`
			case "missing-variant":
				r.Header.Del("X-MFA-Variant")
			case "enrollment-variant":
				r.Header.Set("X-MFA-Variant", "enrollment")
			case "duplicate-variant":
				r.Header["X-MFA-Variant"] = []string{"step-up", "step-up"}
			case "foreign-fields":
				body = strings.TrimSuffix(body, "}") + `,"trustDevice":true}`
			}
			r.Body = ioBody(body)
			r.ContentLength = int64(len(body))
			h, err := NewActiveStepUpHandler(config)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			h.ServeHTTP(w, r)
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("step-up issued a session or cacheable output")
			}
			if mode == "fresh" || mode == "management" {
				if w.Code != 200 || owner.calls != 1 || owner.last.StepUp == nil || !strings.Contains(w.Body.String(), `"proofID":"`+string(command)+`"`) {
					t.Fatal("fresh authenticated factor proof unavailable", w.Code)
				}
				if mode == "management" && owner.last.StepUp.Purpose != "identity.mfa.factor-update" {
					t.Fatal("selected purpose changed at native boundary")
				}
				feature, err := NewFeature(FeatureConfig{ActiveStepUp: &config})
				if err != nil {
					t.Fatal("selected step-up required unrelated login", err)
				}
				ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(ops) != 1 {
					t.Fatal("step-up duplicated shared verify route", err)
				}
				if _, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Step-up", Version: "1"}}, ops, nil); err != nil {
					t.Fatal("step-up wire/router invalid", err)
				}
			} else if w.Code == 200 || strings.Contains(w.Body.String(), `"proofID"`) {
				t.Fatal("invalid/replayed result disclosed proof", mode, w.Code)
			}
			if strings.Contains(mode, "variant") || mode == "foreign-fields" || mode == "unselected-purpose" || mode == "null-purpose" {
				if owner.calls != 0 || owner.reads != 0 {
					t.Fatal("another variant acquired active-factor custody")
				}
			}
		})
	}
}
