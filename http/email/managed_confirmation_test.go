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
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

type managedOwner struct{ *owner }

func (s *managedOwner) ManagedVerificationRateSource(ctx context.Context, p capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	return s.owner.RegistrationVerificationRateSource(ctx, p, callback, caller)
}

func (*managedOwner) RegistrationVerificationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	panic("managed transport must not select signup provenance")
}

func TestManagedConfirmationSelectsOriginalOwnerAndNoSession(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "origin", "off", "nil-owner"} {
		t.Run(mode, func(t *testing.T) {
			base, native, body := fixture(t)
			c := emailhttp.ManagedConfirmationConfig{Network: base.Network, Service: &managedOwner{native}, Rate: base.Rate, Origin: base.Origin, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
			native.result = func(r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
				return receipt(t, r, identity.CommitOutcomeCommitted, mode == "replay", mode != "replay"), nil
			}
			if mode == "nil-owner" {
				c.Service = (*managedOwner)(nil)
				if h, err := emailhttp.NewManagedConfirmationHandler(c); err == nil || h != nil {
					t.Fatal("typed nil management owner exposed handler")
				}
				return
			}
			services := identityhttp.FeatureServices{}
			if mode != "off" {
				feature, err := emailhttp.NewManagedConfirmationFeature(c)
				if err != nil {
					t.Fatal(err)
				}
				services.Features = []identityhttp.Feature{feature}
			}
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, services)
			if err != nil || native.calls != 0 || native.sources != 0 {
				t.Fatal("construction ran management owner", err)
			}
			r := request(body)
			want, calls := 200, 1
			if mode == "origin" {
				r.Header.Set("Origin", "https://foreign.example")
				want, calls = 403, 0
			}
			if mode == "off" {
				want, calls = 404, 0
				if strings.Contains(string(doc.JSON()), "verification-confirm") {
					t.Fatal("omitted management feature retained metadata")
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || native.calls != calls || native.sources != calls || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
				t.Fatal("management transport bypassed owner/origin or issued credentials", w.Code)
			}
			if calls == 1 {
				var out emailhttp.ConfirmationResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommitOutcome != "committed" || !out.Confirmed || out.Replayed != (mode == "replay") || (out.Address == nil) != (mode == "replay") {
					t.Fatal("management outcome/disclosure changed")
				}
			}
		})
	}
}
