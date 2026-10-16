package mfahttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

type recoveryNative struct {
	rate         *strictRate
	reads, calls int
	result       func(mfa.RecoveryUseRequest) (mfa.RecoveryUseResult, error)
}

func TestRecoveryAndPasswordTOTPComposeOneBrowserContract(t *testing.T) {
	base, native, _, _ := handlerFixture(t)
	recovery := RecoveryUseConfig{PasswordPrimary: true, Network: base.Network, Service: &recoveryNative{rate: native.rate}, Rate: base.Rate, Origin: base.Origin, CallbackURL: base.CallbackURL, SessionCookie: base.SessionCookie, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Audience: base.Audience, Now: base.Now, MaximumDuration: base.MaximumDuration}
	otp, _, _, _, _ := otpHandlerFixture(t)
	send, _, _, _ := otpSendFixture(t)
	for selected := 1; selected < 16; selected++ {
		selection := FeatureConfig{}
		if selected&1 != 0 {
			selection.PasswordTOTPVerify = &base
		}
		if selected&2 != 0 {
			selection.RecoveryUse = &recovery
		}
		if selected&4 != 0 {
			selection.OTPVerify = &otp
		}
		if selected&8 != 0 {
			selection.OTPSend = &send
		}
		feature, err := NewFeature(selection)
		if err != nil {
			t.Fatal(err)
		}
		operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: base.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "MFA", Version: "1"}}, operations, nil); err != nil {
			t.Fatal("selected MFA browser contract cannot boot", "selection", selected, err)
		}
	}
}

func (s *recoveryNative) RecoveryVerificationRateSource(_ context.Context, r mfa.RecoveryUseRequest) (identity.UserID, string, time.Duration, error) {
	s.reads++
	if s.rate.calls != 1 || r.Validate() != nil {
		panic("recovery source not admitted")
	}
	return "user-a", string(r.ContinuationID), time.Minute, nil
}
func (s *recoveryNative) RecoveryUse(_ context.Context, r mfa.RecoveryUseRequest) (mfa.RecoveryUseResult, error) {
	s.calls++
	if s.rate.calls != 2 || r.Validate() != nil {
		panic("recovery completion not admitted")
	}
	if s.result != nil {
		return s.result(r)
	}
	return mfa.RecoveryUseResult{Outcome: identity.CommitOutcomeCommitted, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeCommitted, Replayed: true}}, nil
}

func TestRecoveryHTTPDistinctClosedInputAndReplay(t *testing.T) {
	for _, mode := range []string{"replay", "conflict", "fresh", "totp-result", "unknown", "expired", "wrong-child", "factor-override", "otp-input", "duplicate", "origin", "authorization", "idempotency", "missing-device"} {
		t.Run(mode, func(t *testing.T) {
			base, totp, body, device := handlerFixture(t)
			owner := &recoveryNative{rate: totp.rate}
			if mode == "conflict" {
				owner.result = func(r mfa.RecoveryUseRequest) (mfa.RecoveryUseResult, error) {
					return mfa.RecoveryUseResult{Outcome: identity.CommitOutcomeNotCommitted, Session: session.IssueResult{CommandID: r.CommandID, CommitOutcome: identity.CommitOutcomeNotCommitted}}, identity.ConflictError{}
				}
			}
			if mode == "fresh" || mode == "totp-result" || mode == "unknown" || mode == "expired" || mode == "wrong-child" {
				owner.result = func(r mfa.RecoveryUseRequest) (mfa.RecoveryUseResult, error) {
					// Issuance is a deliberate native-authentication seam. Construct
					// real method-specific session custody, not a recovery-code proof.
					issued := issuance(t, base, mfa.TotpVerifyRequest{TenantID: r.TenantID, CommandID: r.CommandID, ChallengeID: mfa.ChallengeID(r.ContinuationID), FactorID: "BAQEBAQEBAQEBAQEBAQEBA"})
					if mode != "totp-result" {
						factor, _ := issued.Session.Session.MFAAuthentication().Bindings()
						factor.Method = "recovery-code"
						factor.RecoverySetID = "BQUFBQUFBQUFBQUFBQUFBQ"
						factor.RecoverySetVersion = 1
						if mode == "wrong-child" {
							factor.ContinuationID = "BgYGBgYGBgYGBgYGBgYGBg"
						}
						metadata, err := session.NewMFAAuthentication(factor)
						if err != nil {
							t.Fatal(err)
						}
						spec, _ := issued.Session.Session.Bindings()
						record, err := session.NewSessionWithMagicLinkMFAAndCSRF(spec, issued.Session.Session.MagicLinkAuthentication(), metadata, issued.Session.Session.CSRFState())
						if err != nil {
							t.Fatal(err)
						}
						issued.Session.Session = record
					}
					if mode == "unknown" {
						issued.Outcome = identity.CommitOutcomeUnknown
						issued.Session.CommitOutcome = identity.CommitOutcomeUnknown
					}
					return mfa.RecoveryUseResult{Outcome: issued.Outcome, Session: issued.Session, CSRFToken: issued.CSRFToken, RecoveryRequired: true}, nil
				}
			}
			c := RecoveryUseConfig{Network: base.Network, Service: owner, Rate: base.Rate, Origin: base.Origin, CallbackURL: base.CallbackURL, SessionCookie: base.SessionCookie, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Audience: base.Audience, Now: base.Now, MaximumDuration: base.MaximumDuration}
			if mode == "expired" {
				c.Now = func() time.Time { return base.Now().Add(time.Minute) }
			}
			if mode == "replay" {
				feature, err := NewFeature(FeatureConfig{RecoveryUse: &c})
				if err != nil || len(feature.Operations()) != 1 {
					t.Fatal("selected recovery feature unavailable", err)
				}
			}
			var values map[string]any
			if err := json.Unmarshal([]byte(body), &values); err != nil {
				t.Fatal(err)
			}
			values["continuationID"] = values["challengeID"]
			delete(values, "challengeID")
			delete(values, "factorID")
			delete(values, "trustDevice")
			delete(values, "code")
			values["recoveryCode"] = "synthetic-recovery-code"
			if mode == "factor-override" {
				values["factorID"] = "BAQEBAQEBAQEBAQEBAQEBA"
			}
			if mode == "otp-input" {
				values["code"] = "123456"
				delete(values, "recoveryCode")
			}
			encoded, _ := json.Marshal(values)
			body = string(encoded)
			if mode == "duplicate" {
				body = strings.TrimSuffix(body, "}") + `,"recoveryCode":"other"}`
			}
			h, err := NewRecoveryUseHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/recovery-use", strings.NewReader(body))
			r.RequestURI = r.URL.RequestURI()
			r.RemoteAddr = "127.0.0.1:4242"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", string(c.Origin))
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			if mode != "missing-device" {
				r.AddCookie(device)
			}
			if mode == "origin" {
				r.Header.Set("Origin", "https://foreign.example")
			}
			if mode == "authorization" {
				r.Header.Set("Authorization", "Bearer forbidden")
			}
			if mode == "idempotency" {
				r.Header.Set("Idempotency-Key", "forbidden")
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			h.ServeHTTP(w, r)
			if mode != "fresh" && (w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "") || strings.Contains(w.Body.String(), "synthetic-recovery-code") {
				t.Fatal("recovery leaked credentials")
			}
			if mode == "fresh" {
				if w.Code != 200 || w.Header().Get("Set-Cookie") == "" || w.Header().Get("X-CSRF-Token") == "" || !strings.Contains(w.Body.String(), `"recoveryRequired":true`) {
					t.Fatal("fresh recovery delivery lost", w.Code, w.Body.String())
				}
			} else if mode == "totp-result" || mode == "unknown" || mode == "expired" || mode == "wrong-child" {
				if w.Code != 503 || owner.calls != 1 {
					t.Fatal("invalid native custody delivered", mode, w.Code, owner.calls)
				}
			} else if mode == "replay" || mode == "conflict" {
				if w.Code != 409 || owner.calls != 1 || owner.reads != 1 {
					t.Fatal("recovery replay/admission", w.Code, owner.calls, owner.reads)
				}
			} else if owner.calls != 0 || w.Code == 200 {
				t.Fatal("hostile recovery reached completion", mode, w.Code)
			}
			if totp.calls != 0 || totp.reads != 0 {
				t.Fatal("recovery fell back to TOTP")
			}
		})
	}
}
