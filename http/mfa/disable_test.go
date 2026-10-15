package mfahttp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

type disableOwner struct {
	calls  int
	last   mfa.DisableRequest
	result *mfa.DisableResult
}

func (s *disableOwner) Disable(_ context.Context, r mfa.DisableRequest) (mfa.DisableResult, error) {
	s.calls++
	s.last = r
	if s.result != nil {
		return *s.result, nil
	}
	return mfa.DisableResult{CommandID: "AAAAAAAAAAAAAAAAAAAABA", Outcome: identity.CommitOutcomeCommitted, Factors: []mfa.FactorProjection{}}, nil
}
func (*disableOwner) RecoverDisable(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (mfa.DisableResult, error) {
	return mfa.DisableResult{}, identity.UnavailableError{}
}

func TestDisableHTTPRequiresExplicitTargetAndOriginalPurpose(t *testing.T) {
	for _, mode := range []string{"one", "all", "pending", "invalid-state", "removed-target", "duplicate", "all-nonempty", "nil-remaining", "ambiguous-all", "missing-one", "unknown", "wrong-purpose", "missing-csrf", "override-command"} {
		t.Run(mode, func(t *testing.T) {
			base, proofs, _, clock, r := enableFixture(t)
			p := proofs.proof
			p.Proof.Purpose, p.Action = "identity.mfa.disable", "identity.mfa.disable"
			p.Proof.Method, p.Proof.Assurance = "totp", auth.AssuranceMultiFactor
			p.Proof.ID = "AAAAAAAAAAAAAAAAAAAABg"
			p.Proof.IssuedAt, p.Proof.ExpiresAt = clock.now, clock.now.Add(time.Minute)
			if mode == "wrong-purpose" {
				p.Proof.Purpose, p.Action = "identity.mfa.factor-update", "identity.mfa.factor-update"
			}
			proofs.proof = p
			owner := &disableOwner{}
			resultCase := mode == "pending" || mode == "invalid-state" || mode == "removed-target" || mode == "duplicate" || mode == "all-nonempty" || mode == "nil-remaining"
			if resultCase {
				factor := mfa.FactorProjection{ID: "AAAAAAAAAAAAAAAAAAAACQ", Method: "totp", State: mfa.FactorPending, CreatedAt: clock.now.Add(-time.Minute), Version: 1}
				owner.result = &mfa.DisableResult{CommandID: "AAAAAAAAAAAAAAAAAAAABA", Outcome: identity.CommitOutcomeCommitted, Factors: []mfa.FactorProjection{factor}}
				switch mode {
				case "invalid-state":
					owner.result.Factors[0].State = mfa.FactorRevoked
				case "removed-target":
					owner.result.Factors[0].ID = "AAAAAAAAAAAAAAAAAAAABQ"
				case "duplicate":
					owner.result.Factors = append(owner.result.Factors, factor)
				case "nil-remaining":
					owner.result.Factors = nil
				}
			}
			c := DisableConfig{Network: base.Network, Sessions: base.Sessions, Proofs: proofs, Service: owner, Rate: base.Rate, Cookie: base.Cookie, TrustedOrigins: base.TrustedOrigins, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration, MaximumAge: time.Minute}
			body := `{"target":"one","factorID":"AAAAAAAAAAAAAAAAAAAABQ","proofID":"AAAAAAAAAAAAAAAAAAAABg"}`
			switch mode {
			case "all", "all-nonempty":
				body = `{"target":"all","proofID":"AAAAAAAAAAAAAAAAAAAABg"}`
			case "ambiguous-all":
				body = strings.Replace(body, `"one"`, `"all"`, 1)
			case "missing-one":
				body = `{"target":"one","proofID":"AAAAAAAAAAAAAAAAAAAABg"}`
			case "unknown":
				body = strings.Replace(body, `"one"`, `"unknown"`, 1)
			case "override-command":
				body = strings.TrimSuffix(body, "}") + `,"commandID":"AAAAAAAAAAAAAAAAAAAABA"}`
			case "missing-csrf":
				r.Header.Del("X-CSRF-Token")
			}
			r.URL.Path = "/v1/mfa/disable"
			r.RequestURI = r.URL.RequestURI()
			r.Body = ioBody(body)
			r.ContentLength = int64(len(body))
			h, err := NewDisableHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "pending" {
				if w.Code != 200 || owner.calls != 1 || !strings.Contains(w.Body.String(), `"id":"AAAAAAAAAAAAAAAAAAAACQ"`) || !strings.Contains(w.Body.String(), `"state":1`) || strings.Contains(w.Body.String(), `"LastUsedAt"`) {
					t.Fatal("disable withheld or corrupted safe remaining pending metadata", w.Code)
				}
			} else if resultCase {
				if w.Code != 503 || owner.calls != 1 || !strings.Contains(w.Body.String(), `"commitOutcome":"committed"`) || strings.Contains(w.Body.String(), `"factors"`) {
					t.Fatal("invalid remaining inventory escaped or lost known commitment", w.Code)
				}
			} else if mode == "one" || mode == "all" {
				want := mfa.OneFactor
				if mode == "all" {
					want = mfa.AllFactors
				}
				if w.Code != 200 || owner.calls != 1 || owner.last.Target != want || owner.last.CommandID != "" || owner.last.FactorProof.Purpose != "identity.mfa.disable" || !strings.Contains(w.Body.String(), `"factors":[]`) {
					t.Fatal("disable lost exact native target/purpose custody", w.Code)
				}
			} else if w.Code == 200 || owner.calls != 0 || strings.Contains(w.Body.String(), `"factors"`) {
				t.Fatal("invalid disable reached native mutation", w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("disable exported cacheable state or successor session")
			}
		})
	}
}
