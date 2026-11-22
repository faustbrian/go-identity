package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func TestProviderRefreshServiceFailsClosedWithoutExplicitComposition(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, link := range []*LinkService{nil, {}} {
		service, err := NewProviderRefreshService(link, []string{"provider"})
		if service != nil || !errors.As(err, &invalid) {
			t.Fatalf("unconfigured link service admitted: %T", err)
		}
	}
	var service *ProviderRefreshService
	result, err := service.Refresh(context.Background(), ProviderRefreshRequest{})
	if result != (ProviderRefreshResult{}) || !errors.As(err, &invalid) {
		t.Fatalf("unconfigured refresh did not fail closed: %T", err)
	}
}

func TestProviderRefreshIntentIsOnePerOwnerAccountAndGrant(t *testing.T) {
	s := &ProviderRefreshService{profile: [32]byte{2}}
	first := ProviderRefreshRequest{TenantID: "tenant", Account: "account", ExpectedVersion: 7, Network: "192.0.2.1"}
	changedSessionContext := first
	changedSessionContext.Network = "192.0.2.2"
	fieldsOf := func(r ProviderRefreshRequest) []identity.FeatureField {
		t.Helper()
		intent, err := s.intent(r)
		if err != nil {
			t.Fatal(err)
		}
		fields, ok := intent.Fields()
		if !ok || len(fields) != 3 {
			t.Fatalf("invalid stable request intent: %d fields", len(fields))
		}
		return fields
	}
	if !reflect.DeepEqual(fieldsOf(first), fieldsOf(changedSessionContext)) {
		t.Fatal("changing fresh caller context must not permit a second provider attempt")
	}
	changedSessionContext.ExpectedVersion++
	if reflect.DeepEqual(fieldsOf(first), fieldsOf(changedSessionContext)) {
		t.Fatal("a new grant version must select distinct initiating intent")
	}
}

func TestProviderRefreshServiceSelectsOnlyConfiguredOrdinaryProviders(t *testing.T) {
	fixture := newRefreshEnvelopeFixture(t)
	configured := []oauth.Provider{fixture.provider}
	fixture.service.config = func() LinkServiceConfig {
		return LinkServiceConfig{Providers: configured}
	}
	id := fixture.provider.ID()
	if s, err := NewProviderRefreshService(fixture.service, []string{id}); s != nil || err == nil {
		t.Fatal("a service without configured risk policy was accepted")
	}
	selected, err := selectProviderRefreshProviders(configured, []string{id})
	if err != nil || selected[id] == nil {
		t.Fatal("explicit ordinary provider was not selected", err)
	}
	for _, ids := range [][]string{nil, {"missing"}, {id, id}} {
		if selected, err := selectProviderRefreshProviders(configured, ids); selected != nil || err == nil {
			t.Fatal("unsupported or ambiguous provider configuration was accepted")
		}
	}
}
