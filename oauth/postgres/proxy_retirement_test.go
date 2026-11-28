package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProxyRetirementRequiresConfiguredAuthority(t *testing.T) {
	var invalid identity.InvalidInputError
	if authority, err := NewProxyRetirementAuthority(nil, "social-provider-operator"); authority != nil || !errors.As(err, &invalid) {
		t.Fatal("missing audit reader was accepted", err)
	}
	for _, retire := range []func(context.Context, *ProxyRetirementAuthority, ProxyOriginRetirementRequest) (identity.CommandResult, error){
		(&ProxyForwardService{}).RetireDisabledProviderOrigin,
		(&ProxyPreviewService{}).RetireDisabledProviderOrigin,
	} {
		if result, err := retire(context.Background(), &ProxyRetirementAuthority{}, ProxyOriginRetirementRequest{}); result.Outcome == identity.CommitOutcomeCommitted || err == nil {
			t.Fatal("unconfigured retirement returned success", err)
		}
	}
}
