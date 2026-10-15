package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// Native IO is intentionally absent here: this proves graph selection and
// guards, not domain persistence or the reference runtime journey.
func TestMagicLinkReferenceSelectionAndLifetime(t *testing.T) {
	for _, f := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if owner, err := f.MagicLinkRequest(); err == nil || owner != nil {
			t.Fatal("unselected request exported")
		}
		if owner, err := f.MagicLinkConsume(); err == nil || owner != nil {
			t.Fatal("unselected consumption exported")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &storeState{lifetime: lifetime, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, timeout: time.Second, magicRequest: &magicpg.RequestService{}, magicConsume: &magicpg.ConsumeService{}}}
	f := FeatureSet{state: state}
	r, err := f.MagicLinkRequest()
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.MagicLinkConsume()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"not-ready", "foreign", "closed"} {
		if mode == "foreign" {
			state.features.ready = true
		}
		if mode == "closed" {
			state.closed = true
			cancel()
		}
		if _, err := r.Request(t.Context(), magiclink.RequestRequest{}); err == nil {
			t.Fatal("inactive/foreign request admitted")
		}
		if _, err := r.RequestRateSource(t.Context(), email.AddressInput("person@example.test")); err == nil {
			t.Fatal("inactive normalization admitted")
		}
		if _, err := r.RecoverRequest(t.Context(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive recovery admitted")
		}
		if _, err := c.Consume(t.Context(), magiclink.ConsumeRequest{}); err == nil {
			t.Fatal("inactive/foreign consume admitted")
		}
		if _, _, _, err := c.ConsumeRateSource(t.Context(), magiclink.ConsumeRequest{}); err == nil {
			t.Fatal("inactive source admitted")
		}
		if _, err := c.RecoverConsume(t.Context(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
			t.Fatal("inactive consume recovery admitted")
		}
		if state.active != 0 {
			t.Fatal("graph admission leaked")
		}
	}
	if _, err := f.MagicLinkRequest(); err == nil {
		t.Fatal("closed graph exported owner")
	}
}

func TestMagicLinkSelectionFailsWithoutNativeGraph(t *testing.T) {
	if request, consume, err := composeMagicLink(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}); err != nil || request != nil || consume != nil {
		t.Fatal("unselected magic-link acquired dependencies")
	}
	selection := StoreConfiguration{MagicLink: &MagicLinkConfiguration{}}
	if request, consume, err := composeMagicLink(selection, ReferenceDependencies{}, risk.Evaluator{}); err == nil || request != nil || consume != nil {
		t.Fatal("missing native graph silently selected")
	}
}

func TestMagicLinkHTTPSelectionCannotDisappearWithoutNativeGraph(t *testing.T) {
	s := &storeState{}
	if err := s.composeFeatureStores(StoreConfiguration{HTTPMagicLink: &HTTPMagicLinkConfiguration{Request: true}}, ReferenceDependencies{}); err == nil {
		t.Fatal("selected HTTP silently disappeared without native dependencies")
	}
}
