package emailhttp_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

type changeConfirmationOwner struct {
	*owner
	complete func(email.ChangeConfirmRequest) (email.ChangeConfirmResult, error)
}

func (s *changeConfirmationOwner) ChangeConfirmationRateSource(ctx context.Context, p capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	if caller.Request.Action != "identity.email.change-confirm" {
		s.t.Error("change source received verification-only authority")
	}
	return s.owner.RegistrationVerificationRateSource(ctx, p, callback, caller)
}

func (s *changeConfirmationOwner) ChangeConfirm(ctx context.Context, r email.ChangeConfirmRequest) (email.ChangeConfirmResult, error) {
	s.calls++
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil || len(s.b.requests) != 2 || r.Caller.Request.Action != "identity.email.change-confirm" {
		s.t.Error("change bypassed protected phases or lost exact action")
	}
	return s.complete(r)
}

func (*changeConfirmationOwner) VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
	panic("change must not execute verification-only service")
}

func changeReceipt(t *testing.T, r email.ChangeConfirmRequest, outcome identity.CommitOutcome, replayed bool) email.ChangeConfirmResult {
	t.Helper()
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: "original-user", RecordID: "original-address", ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.email.change-confirm"}
	recovery, err := email.NewChangeRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	out := email.ChangeConfirmResult{Outcome: outcome, Recovery: recovery, Replayed: replayed}
	if outcome == identity.CommitOutcomeCommitted && !replayed {
		now := time.Unix(1800000000, 0).UTC()
		state := identity.IdentifierState{User: identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 3}, AuthorityVersion: 3, Identifiers: []identity.Identifier{{ID: identity.IdentifierID(q.RecordID), UserID: q.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", Primary: true, Verified: true, Version: 2}}, Verifications: []identity.Verification{{IdentifierID: identity.IdentifierID(q.RecordID), State: identity.VerificationVerified, VerifiedAt: now, Version: 2}}}
		out.Address, err = identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: q.TenantID, UserID: q.UserID, IdentifierID: identity.IdentifierID(q.RecordID), State: state, ObservedAt: now, Values: identity.IdentifierValuesIncluded})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestChangeConfirmationPreservesDistinctActionAndOutcome(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "unknown", "origin", "wrong-route", "foreign-recovery", "nonprimary-disclosure", "off", "nil-owner"} {
		t.Run(mode, func(t *testing.T) {
			base, native, body := fixture(t)
			service := &changeConfirmationOwner{owner: native}
			service.complete = func(r email.ChangeConfirmRequest) (email.ChangeConfirmResult, error) {
				if mode == "unknown" {
					return changeReceipt(t, r, identity.CommitOutcomeUnknown, false), identity.UnavailableError{}
				}
				out := changeReceipt(t, r, identity.CommitOutcomeCommitted, mode == "replay")
				if mode == "foreign-recovery" {
					q, _ := out.Recovery.Bindings()
					q.ActorID = "foreign-service"
					out.Recovery, _ = email.NewChangeRecovery(q)
				}
				if mode == "nonprimary-disclosure" {
					// A verification-only projection cannot satisfy primary change,
					// even when the native owner reports a committed outcome.
					out.Address = receipt(t, email.VerificationConfirmRequest(r), identity.CommitOutcomeCommitted, false, true).Address
				}
				return out, nil
			}
			c := emailhttp.ChangeConfirmationConfig{Network: base.Network, Service: service, Rate: base.Rate, Origin: base.Origin, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
			if mode == "nil-owner" {
				c.Service = (*changeConfirmationOwner)(nil)
				if h, err := emailhttp.NewChangeConfirmationHandler(c); err == nil || h != nil {
					t.Fatal("typed nil change owner exposed handler")
				}
				return
			}
			services := identityhttp.FeatureServices{}
			if mode != "off" {
				feature, err := emailhttp.NewChangeConfirmationFeature(c)
				if err != nil {
					t.Fatal(err)
				}
				services.Features = []identityhttp.Feature{feature}
			}
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, services)
			if err != nil {
				t.Fatal(err)
			}
			r := request(body)
			r.URL.Path = "/v1/email/change-confirm"
			want, calls := 200, 1
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
				want, calls = 403, 0
			case "wrong-route":
				r.URL.Path = "/v1/email/verification-confirm"
				want, calls = 404, 0
			case "off":
				want, calls = 404, 0
				if strings.Contains(string(doc.JSON()), "identity.email.change-confirm") {
					t.Fatal("disabled change feature advertises route")
				}
			case "unknown", "foreign-recovery", "nonprimary-disclosure":
				want = 503
			}
			r.RequestURI = r.URL.RequestURI()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || native.calls != calls || native.sources != calls || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
				t.Fatal("change dispatch/credential custody differed", w.Code)
			}
			if calls == 0 {
				return
			}
			var out emailhttp.ConfirmationResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Confirmed != (want == 200) || out.CommitOutcome != map[bool]string{true: "unknown", false: "committed"}[mode == "unknown"] || (out.Address != nil) != (mode == "fresh") {
				t.Fatal("change rewrote original outcome or disclosed nonfresh address")
			}
			if mode != "foreign-recovery" && mode != "nonprimary-disclosure" && out.Recovery == nil {
				t.Fatal("change lost exact original recovery correlation")
			}
		})
	}
}
