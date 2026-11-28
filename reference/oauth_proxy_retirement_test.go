package reference_test

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/reference"
)

func TestOAuthProxyRetirementRequiresExplicitSelection(t *testing.T) {
	var invalid identity.InvalidInputError
	if production, err := reference.NewOAuthProxyProductionWithRetirement(nil, reference.OAuthProxyProductionConfiguration{}, nil, nil); production != nil || !errors.As(err, &invalid) {
		t.Fatal("unconfigured production retirement selection was accepted", err)
	}
	if _, err := reference.ComposeStoresWithOAuthProxyPreviewRetirement(reference.StoreConfiguration{}, reference.ReferenceDependencies{}, nil, nil); !errors.As(err, &invalid) {
		t.Fatal("unconfigured preview retirement selection was accepted", err)
	}
	request := oauthpg.ProxyOriginRetirementRequest{}
	for _, retire := range []func(context.Context, oauthpg.ProxyOriginRetirementRequest) (identity.CommandResult, error){
		(&reference.OAuthProxyProduction{}).RetireDisabledProviderOrigin,
		(reference.FeatureSet{}).RetireDisabledOAuthProxyPreviewOrigin,
	} {
		var denied identity.ForbiddenError
		if got, err := retire(t.Context(), request); got.Outcome == identity.CommitOutcomeCommitted || !errors.As(err, &denied) {
			t.Fatal("unselected Reference owner reported retirement", err)
		}
	}
}
