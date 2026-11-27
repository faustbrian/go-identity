package reference_test

import (
	"errors"
	"testing"

	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/reference"
)

func TestOAuthProxyPreviewDoesNotStartWithoutSelectedOwner(t *testing.T) {
	var features reference.FeatureSet
	result, err := features.StartOAuthProxyPreview(t.Context(), nil, reference.OAuthProxyPreviewStartRequest{})
	if !errors.Is(err, oauthproxy.CompletionInvalid) || result.URL() != "" {
		t.Fatal("an unconfigured preview disclosed an authorization request", err)
	}
}
