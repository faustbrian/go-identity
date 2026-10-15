package emailhttp_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

func TestEmailFeatureGroupsDistinctCanonicalConfirmations(t *testing.T) {
	for _, action := range []string{"verification-confirm", "change-confirm"} {
		t.Run(action, func(t *testing.T) {
			base, native, body := fixture(t)
			native.result = func(r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
				return receipt(t, r, identity.CommitOutcomeCommitted, true, false), nil
			}
			change := &changeConfirmationOwner{owner: native, complete: func(r email.ChangeConfirmRequest) (email.ChangeConfirmResult, error) {
				return changeReceipt(t, r, identity.CommitOutcomeCommitted, true), nil
			}}
			cc := emailhttp.ChangeConfirmationConfig{Network: base.Network, Service: change, Rate: base.Rate, Origin: base.Origin, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
			feature, err := emailhttp.NewFeature(emailhttp.FeatureConfig{SignupConfirmation: &base, ChangeConfirmation: &cc})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Email", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal("two selected email operations cannot share one feature", err)
			}
			for _, operation := range []string{"identity.email.verification-confirm", "identity.email.change-confirm"} {
				if !strings.Contains(string(doc.JSON()), operation) {
					t.Fatal("selected native operation has no wire description")
				}
			}
			r := request(body)
			r.URL.Path = "/v1/email/" + action
			r.RequestURI = r.URL.RequestURI()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 || native.calls != 1 || native.sources != 1 {
				t.Fatal("canonical confirmation did not reach its sole selected owner", w.Code)
			}
		})
	}
	base, native, _ := fixture(t)
	managed := emailhttp.ManagedConfirmationConfig{Network: base.Network, Service: &managedOwner{native}, Rate: base.Rate, Origin: base.Origin, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}
	for _, c := range []emailhttp.FeatureConfig{{}, {SignupConfirmation: &base, ManagedConfirmation: &managed}} {
		if _, err := emailhttp.NewFeature(c); err == nil {
			t.Fatal("empty or ambiguous verification owner became a public feature")
		}
	}
}
