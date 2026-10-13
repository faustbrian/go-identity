package mfahttp

import (
	"context"
	"encoding/json"
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
	primitive "github.com/faustbrian/go-password"
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

func TestFactorUpdateHTTPReplacementDeliversPendingCustodyOnce(t *testing.T) {
	for _, mode := range []string{"fresh", "unselected", "name", "exhausted-version", "expired", "unknown", "replay", "same-factor", "mismatched-enrollment", "missing-codes", "duplicate-codes"} {
		t.Run(mode, func(t *testing.T) {
			base, proofs, _, clock, r := enableFixture(t)
			proofs.proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAABg"
			proofs.proof.Proof.Method, proofs.proof.Proof.Assurance = "totp", auth.AssuranceMultiFactor
			proofs.proof.Proof.Purpose, proofs.proof.Action = "identity.mfa.factor-update", "identity.mfa.factor-update"
			proofs.proof.Proof.IssuedAt, proofs.proof.Proof.ExpiresAt = clock.now, clock.now.Add(time.Minute)
			secret, err := primitive.NewSecret([]byte("AAAAAAAAAAAAAAAAAAAAAQ"))
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Destroy()
			owner := &factorUpdateOwner{enableOwner: proofs, result: mfa.FactorUpdateResult{CommandID: "AAAAAAAAAAAAAAAAAAAABA", Outcome: identity.CommitOutcomeCommitted, Factor: mfa.FactorProjection{ID: "AAAAAAAAAAAAAAAAAAAABw", Method: "totp", State: mfa.FactorPending, CreatedAt: clock.now, Version: 1}, Replacement: &mfa.TOTPReplacementEnrollment{Enrollment: mfa.Enrollment{ID: "AAAAAAAAAAAAAAAAAAAABw", FactorMethod: "totp", ExpiresAt: clock.now.Add(time.Minute), Version: 1}, RecoveryMaterial: mfa.RevealOnceCodes{Codes: []primitive.Secret{secret}}}}}
			c := FactorUpdateConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute, Actions: []mfa.FactorUpdateAction{mfa.Replace}, ReplacementCodeCount: 1}
			body := `{"factorID":"AAAAAAAAAAAAAAAAAAAABQ","proofID":"AAAAAAAAAAAAAAAAAAAABg","action":"replace","expectedVersion":3}`
			switch mode {
			case "unselected":
				c.Actions = nil
				c.ReplacementCodeCount = 0
			case "name":
				body = strings.TrimSuffix(body, "}") + `,"name":"not-rename"}`
			case "exhausted-version":
				body = strings.Replace(body, `"expectedVersion":3`, `"expectedVersion":18446744073709551614`, 1)
			case "expired":
				owner.after = func() { clock.now = clock.now.Add(21 * time.Second) }
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "replay":
				owner.result.Factor, owner.result.Replacement = mfa.FactorProjection{}, nil
			case "same-factor":
				owner.result.Factor.ID, owner.result.Replacement.Enrollment.ID = "AAAAAAAAAAAAAAAAAAAABQ", "AAAAAAAAAAAAAAAAAAAABQ"
			case "mismatched-enrollment":
				owner.result.Replacement.Enrollment.ID = "AAAAAAAAAAAAAAAAAAAACA"
			case "missing-codes":
				owner.result.Replacement.RecoveryMaterial.Codes = nil
			case "duplicate-codes":
				duplicate, err := primitive.NewSecret([]byte("AAAAAAAAAAAAAAAAAAAAAQ"))
				if err != nil {
					t.Fatal(err)
				}
				defer duplicate.Destroy()
				owner.result.Replacement.RecoveryMaterial.Codes = append(owner.result.Replacement.RecoveryMaterial.Codes, duplicate)
				c.ReplacementCodeCount = 2
			}
			r.URL.Path, r.RequestURI = "/v1/mfa/factor-update", "/v1/mfa/factor-update"
			r.Body, r.ContentLength = ioBody(body), int64(len(body))
			h, err := NewFactorUpdateHandler(c)
			if err != nil {
				t.Fatal("explicit replacement handler unavailable", err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out struct {
				CommitOutcome string
				Factor        struct {
					ID      mfa.FactorID
					State   mfa.FactorState
					Version uint64
				}
				Replacement *struct {
					EnrollmentID  mfa.EnrollmentID
					FactorMethod  string
					ExpiresAt     time.Time
					Version       uint64
					RecoveryCodes []string
				}
			}
			decodeErr := json.Unmarshal(w.Body.Bytes(), &out)
			if mode == "fresh" {
				if w.Code != 200 || decodeErr != nil || owner.calls != 1 || owner.last.Action != mfa.Replace || owner.last.Name != "" || out.CommitOutcome != "committed" || out.Factor.ID != owner.result.Factor.ID || out.Factor.State != mfa.FactorPending || out.Factor.Version != 1 || out.Replacement == nil || out.Replacement.EnrollmentID != owner.result.Replacement.Enrollment.ID || out.Replacement.FactorMethod != "totp" || out.Replacement.Version != 1 || !out.Replacement.ExpiresAt.Equal(clock.now.Add(time.Minute)) || len(out.Replacement.RecoveryCodes) != 1 || out.Replacement.RecoveryCodes[0] != "AAAAAAAAAAAAAAAAAAAAAQ" {
					t.Fatal("replacement did not deliver exact pending ceremony", w.Code)
				}
				clear(out.Replacement.RecoveryCodes)
			} else if mode == "unselected" || mode == "name" || mode == "exhausted-version" {
				if w.Code != 400 || owner.calls != 0 || out.Replacement != nil {
					t.Fatal("unselected replacement or label override reached mutation", w.Code)
				}
			} else if w.Code != 503 || decodeErr != nil || out.Replacement != nil || out.Factor.ID != "" || out.CommitOutcome == "" {
				t.Fatal("invalid/expired/uncertain replacement disclosed custody or lost observation", w.Code)
			}
			if owner.calls > 0 && mode != "replay" && mode != "missing-codes" && secret.Use(func([]byte) error { return nil }) == nil {
				t.Fatal("replacement transport did not destroy returned recovery custody")
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("replacement response was cacheable or issued a session")
			}
		})
	}
}

func TestFactorUpdateHTTPExplicitRemovalForbidsLabelOverrides(t *testing.T) {
	for _, mode := range []string{"remove", "mixed-remove", "mixed-rename", "mutated-selection", "label", "empty-label", "unselected-rename"} {
		t.Run(mode, func(t *testing.T) {
			base, proofs, _, clock, r := enableFixture(t)
			target := proofs.proof
			target.Proof.Purpose, target.Action = "identity.mfa.factor-update", "identity.mfa.factor-update"
			target.Proof.Method, target.Proof.Assurance = "totp", auth.AssuranceMultiFactor
			target.Proof.ID = "AAAAAAAAAAAAAAAAAAAABg"
			target.Proof.IssuedAt, target.Proof.ExpiresAt = clock.now, clock.now.Add(time.Minute)
			proofs.proof = target
			owner := &factorUpdateOwner{enableOwner: proofs, result: mfa.FactorUpdateResult{CommandID: "AAAAAAAAAAAAAAAAAAAABA", Outcome: identity.CommitOutcomeCommitted, Factor: mfa.FactorProjection{ID: "AAAAAAAAAAAAAAAAAAAABQ", Method: "totp", State: mfa.FactorRevoked, CreatedAt: clock.now.Add(-time.Minute), Version: 4}}}
			c := FactorUpdateConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute, Actions: []mfa.FactorUpdateAction{mfa.Remove}}
			if mode == "mixed-remove" || mode == "mixed-rename" {
				c.Actions = []mfa.FactorUpdateAction{mfa.Rename, mfa.Remove}
			}
			body := `{"factorID":"AAAAAAAAAAAAAAAAAAAABQ","proofID":"AAAAAAAAAAAAAAAAAAAABg","action":"remove","expectedVersion":3}`
			switch mode {
			case "label":
				body = strings.TrimSuffix(body, "}") + `,"name":"other"}`
			case "empty-label":
				body = strings.TrimSuffix(body, "}") + `,"name":""}`
			case "unselected-rename":
				body = strings.Replace(body, `"remove"`, `"rename"`, 1)
			case "mixed-rename":
				body = strings.Replace(body, `"remove"`, `"rename"`, 1)
				body = strings.TrimSuffix(body, "}") + `,"name":"work"}`
				owner.result.Factor.State, owner.result.Factor.Label = mfa.FactorActive, "work"
			}
			r.URL.Path = "/v1/mfa/factor-update"
			r.RequestURI = r.URL.RequestURI()
			r.Body = ioBody(body)
			r.ContentLength = int64(len(body))
			h, err := NewFactorUpdateHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "mutated-selection" {
				c.Actions[0] = mfa.Rename
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "mixed-rename" {
				if w.Code != 200 || owner.calls != 1 || owner.last.Action != mfa.Rename || owner.last.Name != "work" || !strings.Contains(w.Body.String(), `"state":2`) {
					t.Fatal("mixed action policy lost rename custody", w.Code)
				}
			} else if mode == "remove" || mode == "mixed-remove" || mode == "mutated-selection" {
				if w.Code != 200 || owner.calls != 1 || owner.last.Action != mfa.Remove || owner.last.Name != "" || !strings.Contains(w.Body.String(), `"state":3`) {
					t.Fatal("explicit removal lost native custody or revoked projection", w.Code)
				}
			} else if w.Code != 400 || owner.calls != 0 || strings.Contains(w.Body.String(), `"factor"`) {
				t.Fatal("unselected action/label override reached mutation", w.Code)
			}
			if mode == "remove" || mode == "mixed-remove" || mode == "mixed-rename" {
				feature, err := NewFeature(FeatureConfig{FactorUpdate: &c})
				if err != nil {
					t.Fatal("selected management feature invalid", err)
				}
				ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(ops) != 1 {
					t.Fatal("selected actions exposed unrelated operations", err)
				}
				if _, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Selected management", Version: "1"}}, ops, nil); err != nil {
					t.Fatal("selected action wire contract invalid", err)
				}
			}
		})
	}
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
	for _, actions := range [][]mfa.FactorUpdateAction{{mfa.Replace}, {mfa.Remove, mfa.Remove}, {mfa.Rename, mfa.Rename}, {mfa.Remove, mfa.Rename, mfa.Remove}, {mfa.FactorUpdateAction(255)}} {
		base, proofs, _, _, _ := enableFixture(t)
		owner := &factorUpdateOwner{enableOwner: proofs}
		config := FactorUpdateConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute, Actions: actions}
		if h, err := NewFactorUpdateHandler(config); err == nil || h != nil {
			t.Fatal("invalid closed action selection acquired a handler")
		}
	}
}
